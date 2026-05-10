from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import joblib
import email
from email import policy
from pathlib import Path
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent

model = joblib.load(BASE_DIR / 'phishing_model.pkl')
vectorizer = joblib.load(BASE_DIR / 'vectorizer.pkl')

def check_domain_records(domain):
    records = {"mx_found": False, "spf_found": False, "dmarc_found": False}
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return records

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        records["mx_found"] = len(mx_answers) > 0
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        records["spf_found"] = any("v=spf1" in str(txt).lower() for txt in txt_answers)
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        records["dmarc_found"] = any("v=dmarc1" in str(txt).lower() for txt in txt_answers)
    except Exception:
        pass

    return records

def extract_links(email_text):
    href_pattern = r'href=["\']?([^"\'\s>]+)'
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    candidates = re.findall(href_pattern, email_text, flags=re.IGNORECASE)
    candidates.extend(re.findall(url_pattern, email_text, flags=re.IGNORECASE))

    links = []
    seen = set()
    for candidate in candidates:
        link = candidate.strip().rstrip('.,);]')
        if link.startswith('www.'):
            link = f'https://{link}'
        if link and link not in seen:
            seen.add(link)
            links.append(link)
    return links

def find_suspicious_links(links, sender_domain):
    suspicious_links = []
    sender_domain = (sender_domain or "").lower()
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
    }

    for link in links:
        parsed = urlparse(link)
        host = (parsed.hostname or "").lower()
        reasons = []

        if parsed.scheme == "http":
            reasons.append("plain HTTP")
        if host in shorteners:
            reasons.append("URL shortener")
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
            reasons.append("IP address host")
        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("punycode domain")
        if sender_domain and host and not (host == sender_domain or host.endswith(f".{sender_domain}")):
            reasons.append("domain differs from sender")

        if reasons:
            suspicious_links.append({"url": link, "reasons": reasons})

    return suspicious_links

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    email_text = ""
    link_source_text = ""
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
                    link_source_text += f"\n{temp_text}"
                    if len(temp_text) > 5 and temp_text != '=':
                        email_text = temp_text
                        break
                        
                # Priority 2: HTML
                elif content_type == 'text/html' and not email_text:
                    html_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    link_source_text += f"\n{html_content}"
                    email_text = re.sub('<[^<]+?>', ' ', html_content).strip()
        else:
            email_text = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore').strip()
            link_source_text = email_text
            
    # Fallback to manual text entry
    elif request.is_json:
        data = request.json
        email_text = data.get('email_text', '')
        sender_domain = data.get('sender_domain', '')
        link_source_text = email_text
    elif request.form:
        email_text = request.form.get('email_text', '')
        sender_domain = request.form.get('sender_domain', '')
        link_source_text = email_text

    if not email_text:
        return jsonify({"error": "No email text or file provided"}), 400

    dns_results = check_domain_records(sender_domain) if sender_domain else None
    links = extract_links(link_source_text or email_text)
    suspicious_links = find_suspicious_links(links, sender_domain)
    
    text_vector = vectorizer.transform([email_text])
    prediction_proba = model.predict_proba(text_vector)[0]
    phishing_class_index = list(model.classes_).index(1)
    threat_score = int(prediction_proba[phishing_class_index] * 100)

    spear_phishing_keywords = ['confidential', 'urgent', 'invoice', 'payment', 'transfer', 'overdue']
    email_lower = email_text.lower()
    keyword_hits = sum(1 for word in spear_phishing_keywords if word in email_lower)

    is_trusted_sender = (dns_results and dns_results.get('dmarc_found') == True)

    if keyword_hits >= 2 and not is_trusted_sender:
        threat_score = max(threat_score, 92)
        explanation = f"While ML patterns appeared normal, the sender is external/unverified and used {keyword_hits} high-risk CEO Fraud keywords."
    
    elif keyword_hits >= 2 and is_trusted_sender:
        explanation = f"Our custom NLP model determined a {threat_score}% probability of malicious intent. (High-risk keywords ignored because sender domain is verified)."
    
    else:
        explanation = f"Our custom NLP model analyzed the linguistic patterns and determined a {threat_score}% probability of malicious intent."

    if suspicious_links:
        threat_score = max(threat_score, 80)
        explanation += f" Found {len(suspicious_links)} suspicious link(s) based on URL heuristics."

    is_phishing = threat_score > 50

    return jsonify({
        "dns_analysis": dns_results,
        "extracted_domain": sender_domain, 
        "ai_analysis": {
            "threat_score": threat_score,
            "is_phishing": is_phishing,
            "links": links,
            "suspicious_links": suspicious_links,
            "explanation": explanation
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
