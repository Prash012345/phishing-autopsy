from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import joblib
import email
from email import policy
import re

app = Flask(__name__)
CORS(app)

# 1. Load YOUR custom NLP model
model = joblib.load('phishing_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

def check_domain_records(domain):
    records = {"mx_found": False, "dmarc_found": False}
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        if len(mx_answers) > 0: records["mx_found"] = True
        txt_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for txt in txt_answers:
            if "v=DMARC1" in str(txt): records["dmarc_found"] = True
    except Exception:
        pass 
    return records

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    email_text = ""
    sender_domain = ""

    # Check if a file was uploaded
    if 'file' in request.files:
        file = request.files['file']
        msg = email.message_from_bytes(file.read(), policy=policy.default)
        
        # 1. Extract Domain
        from_header = msg.get('From', '')
        domain_match = re.search(r'@([\w.-]+)', from_header)
        if domain_match:
            sender_domain = domain_match.group(1).strip('>')
            
        # 2. Robust Body Extraction
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                # Priority 1: Plain Text
                if content_type == 'text/plain':
                    temp_text = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore').strip()
                    if len(temp_text) > 5 and temp_text != '=':
                        email_text = temp_text
                        break
                        
                # Priority 2: HTML
                elif content_type == 'text/html' and not email_text:
                    html_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    email_text = re.sub('<[^<]+?>', ' ', html_content).strip()
        else:
            email_text = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore').strip()
            
    # Fallback to manual text entry
    elif request.is_json:
        data = request.json
        email_text = data.get('email_text', '')
        sender_domain = data.get('sender_domain', '')

    # --- FINAL SAFETY CHECK ---
    print(f"DEBUG -> Final Extracted Domain: {sender_domain} | Final Text Length: {len(email_text)}")
    
    if not email_text:
        return jsonify({"error": "No email text or file provided"}), 400

    # Run the DNS Checks
    dns_results = check_domain_records(sender_domain) if sender_domain else None
    
    # 1. Run the Base Machine Learning Model
    text_vector = vectorizer.transform([email_text])
    prediction_proba = model.predict_proba(text_vector)[0]
    threat_score = int(prediction_proba[1] * 100)

    # 2. CONTEXT-AWARE HEURISTIC BOOSTER
    spear_phishing_keywords = ['confidential', 'urgent', 'invoice', 'payment', 'transfer', 'overdue']
    email_lower = email_text.lower()
    keyword_hits = sum(1 for word in spear_phishing_keywords if word in email_lower)
    

    
    # Check if it's a verified domain AND passes DMARC
    is_trusted_sender = (dns_results and dns_results.get('dmarc_found') == True)

    # Only apply the penalty if the sender is NOT trusted
    if keyword_hits >= 2 and not is_trusted_sender:
        threat_score = max(threat_score, 92)
        explanation = f"While ML patterns appeared normal, the sender is external/unverified and used {keyword_hits} high-risk CEO Fraud keywords."
    
    elif keyword_hits >= 2 and is_trusted_sender:
        explanation = f"Our custom NLP model determined a {threat_score}% probability of malicious intent. (High-risk keywords ignored because sender domain is verified)."
    
    else:
        explanation = f"Our custom NLP model analyzed the linguistic patterns and determined a {threat_score}% probability of malicious intent."

    is_phishing = threat_score > 50

    return jsonify({
        "dns_analysis": dns_results,
        "extracted_domain": sender_domain, 
        "ai_analysis": {
            "threat_score": threat_score,
            "is_phishing": is_phishing,
            "suspicious_links": [], 
            "explanation": explanation
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)