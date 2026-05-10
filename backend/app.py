from email import policy
from email.utils import parseaddr
from html import unescape
from pathlib import Path
from urllib.parse import urlparse
import email
import ipaddress
import re

from flask import Flask, jsonify, request
from flask_cors import CORS
import dns.resolver
import joblib


app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent

model = joblib.load(BASE_DIR / "phishing_model.pkl")
vectorizer = joblib.load(BASE_DIR / "vectorizer.pkl")

RISK_KEYWORDS = {
    "urgency": ["urgent", "immediately", "expires", "today", "24 hours", "final notice"],
    "financial": ["invoice", "payment", "transfer", "wire", "overdue", "refund", "payroll"],
    "credential": ["password", "verify", "login", "account", "security alert", "mfa", "authenticate"],
    "authority": ["ceo", "cfo", "director", "confidential", "approved", "executive"],
    "attachment": ["attached", "attachment", "download", "document", "statement"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
}


def domain_from_address(value):
    _, address = parseaddr(value or "")
    match = re.search(r"@([\w.-]+)", address)
    return match.group(1).lower().strip(">.") if match else ""


def normalize_domain(domain):
    return (domain or "").strip().lower().rstrip(".")


def domain_matches(base_domain, candidate_domain):
    base_domain = normalize_domain(base_domain)
    candidate_domain = normalize_domain(candidate_domain)
    return bool(
        base_domain
        and candidate_domain
        and (candidate_domain == base_domain or candidate_domain.endswith(f".{base_domain}"))
    )


def check_domain_records(domain):
    records = {"mx_found": False, "spf_found": False, "dmarc_found": False}
    domain = normalize_domain(domain)
    if not domain:
        return records

    try:
        records["mx_found"] = len(dns.resolver.resolve(domain, "MX")) > 0
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(domain, "TXT")
        records["spf_found"] = any("v=spf1" in str(txt).lower() for txt in txt_answers)
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        records["dmarc_found"] = any("v=dmarc1" in str(txt).lower() for txt in txt_answers)
    except Exception:
        pass

    return records


def extract_links(text):
    href_pattern = r'href=["\']?([^"\'\s>]+)'
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    candidates = re.findall(href_pattern, text or "", flags=re.IGNORECASE)
    candidates.extend(re.findall(url_pattern, text or "", flags=re.IGNORECASE))

    links = []
    seen = set()
    for candidate in candidates:
        link = unescape(candidate.strip()).rstrip(".,);]")
        if link.startswith("www."):
            link = f"https://{link}"
        if link and link not in seen:
            seen.add(link)
            links.append(link)
    return links


def get_link_reasons(link, sender_domain):
    parsed = urlparse(link)
    host = normalize_domain(parsed.hostname)
    reasons = []

    if parsed.scheme == "http":
        reasons.append("plain HTTP")
    if host in URL_SHORTENERS:
        reasons.append("URL shortener")
    try:
        if host:
            ipaddress.ip_address(host)
            reasons.append("IP address host")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("punycode domain")
    if sender_domain and host and not domain_matches(sender_domain, host):
        reasons.append("domain differs from sender")
    if "@" in parsed.netloc:
        reasons.append("userinfo in URL")
    if len(link) > 140:
        reasons.append("unusually long URL")

    return host, reasons


def analyze_links(links, sender_domain):
    details = []
    suspicious = []
    domains = set()

    for link in links:
        host, reasons = get_link_reasons(link, sender_domain)
        if host:
            domains.add(host)
        item = {
            "url": link,
            "host": host,
            "reasons": reasons,
            "is_suspicious": bool(reasons),
        }
        details.append(item)
        if reasons:
            suspicious.append({"url": link, "reasons": reasons})

    return {
        "links": links,
        "details": details,
        "unique_domains": sorted(domains),
        "total_links": len(links),
        "suspicious_count": len(suspicious),
        "suspicious_links": suspicious,
    }


def parse_email_message(uploaded_file):
    msg = email.message_from_bytes(uploaded_file.read(), policy=policy.default)
    headers = {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_count": len(msg.get_all("Received", [])),
        "authentication_results": msg.get_all("Authentication-Results", []),
    }

    text_parts = []
    html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            filename = part.get_filename()

            if filename or disposition == "attachment":
                attachments.append({
                    "filename": filename or "unnamed",
                    "content_type": content_type,
                })
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            decoded = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
            if content_type == "text/plain":
                text_parts.append(decoded.strip())
            elif content_type == "text/html":
                html_parts.append(decoded.strip())
    else:
        payload = msg.get_payload(decode=True)
        decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore") if payload else str(msg.get_payload())
        if msg.get_content_type() == "text/html":
            html_parts.append(decoded.strip())
        else:
            text_parts.append(decoded.strip())

    html_text = " ".join(re.sub("<[^<]+?>", " ", html) for html in html_parts)
    email_text = " ".join(part for part in text_parts if part).strip() or html_text.strip()
    link_source_text = "\n".join(text_parts + html_parts)

    return msg, headers, email_text, link_source_text, attachments


def manual_message():
    if request.is_json:
        data = request.json
    else:
        data = request.form

    email_text = data.get("email_text", "")
    sender_domain = data.get("sender_domain", "")
    headers = {
        "from": data.get("from", ""),
        "reply_to": data.get("reply_to", ""),
        "return_path": data.get("return_path", ""),
        "subject": data.get("subject", ""),
        "date": "",
        "message_id": "",
        "received_count": 0,
        "authentication_results": [],
    }
    return headers, email_text, email_text, sender_domain, []


def analyze_headers(headers, sender_domain):
    from_domain = domain_from_address(headers.get("from"))
    reply_to_domain = domain_from_address(headers.get("reply_to"))
    return_path_domain = domain_from_address(headers.get("return_path"))
    domain = normalize_domain(sender_domain or from_domain)

    auth_blob = " ".join(headers.get("authentication_results", [])).lower()
    auth_results = {
        "spf_pass": "spf=pass" in auth_blob,
        "dkim_pass": "dkim=pass" in auth_blob,
        "dmarc_pass": "dmarc=pass" in auth_blob,
        "has_authentication_results": bool(auth_blob),
    }

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "sender_domain": domain,
        "reply_to_mismatch": bool(reply_to_domain and not domain_matches(domain, reply_to_domain)),
        "return_path_mismatch": bool(return_path_domain and not domain_matches(domain, return_path_domain)),
        "received_count": headers.get("received_count", 0),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "message_id_present": bool(headers.get("message_id")),
        "authentication_results": auth_results,
    }


def analyze_language(email_text):
    text = (email_text or "").lower()
    keyword_hits = {
        category: [word for word in words if word in text]
        for category, words in RISK_KEYWORDS.items()
    }
    keyword_hits = {category: hits for category, hits in keyword_hits.items() if hits}
    punctuation_flags = {
        "many_exclamation_marks": (email_text or "").count("!") >= 3,
        "contains_all_caps_phrase": bool(re.search(r"\b[A-Z]{4,}(?:\s+[A-Z]{4,})+\b", email_text or "")),
    }

    return {
        "character_count": len(email_text or ""),
        "word_count": len(re.findall(r"\b\w+\b", email_text or "")),
        "keyword_hits": keyword_hits,
        "keyword_hit_count": sum(len(hits) for hits in keyword_hits.values()),
        "punctuation_flags": punctuation_flags,
    }


def add_factor(factors, severity, category, signal, detail, points):
    factors.append({
        "severity": severity,
        "category": category,
        "signal": signal,
        "detail": detail,
        "points": points,
    })


def build_risk_factors(dns_results, header_analysis, link_analysis, language_analysis, attachments):
    factors = []

    if dns_results:
        if not dns_results.get("mx_found"):
            add_factor(factors, "medium", "DNS", "No MX record", "Sender domain could not be confirmed as mail-capable.", 6)
        if not dns_results.get("spf_found"):
            add_factor(factors, "low", "DNS", "No SPF record", "Domain does not publish an SPF sender policy.", 3)
        if not dns_results.get("dmarc_found"):
            add_factor(factors, "low", "DNS", "No DMARC record", "Domain lacks a visible DMARC policy.", 4)

    if header_analysis.get("reply_to_mismatch"):
        add_factor(factors, "high", "Headers", "Reply-To mismatch", "Reply-To domain differs from the claimed sender domain.", 18)
    if header_analysis.get("return_path_mismatch"):
        add_factor(factors, "medium", "Headers", "Return-Path mismatch", "Return-Path domain differs from the claimed sender domain.", 10)
    if not header_analysis.get("message_id_present"):
        add_factor(factors, "low", "Headers", "Missing Message-ID", "Message-ID header is absent or unavailable.", 4)

    if link_analysis["suspicious_count"]:
        add_factor(
            factors,
            "high",
            "Links",
            "Suspicious URL pattern",
            f"{link_analysis['suspicious_count']} link(s) matched suspicious URL heuristics.",
            min(25, 8 * link_analysis["suspicious_count"]),
        )
    if len(link_analysis["unique_domains"]) >= 3:
        add_factor(factors, "medium", "Links", "Multiple link domains", "Email links point to several different domains.", 8)

    for category, hits in language_analysis["keyword_hits"].items():
        severity = "medium" if category in {"urgency", "credential", "financial"} else "low"
        add_factor(
            factors,
            severity,
            "Language",
            f"{category.title()} lure language",
            f"Matched: {', '.join(hits[:6])}",
            min(14, 4 * len(hits)),
        )

    keyword_categories = set(language_analysis["keyword_hits"])
    if (
        "financial" in keyword_categories
        and "authority" in keyword_categories
        and ("urgency" in keyword_categories or "credential" in keyword_categories)
    ):
        add_factor(
            factors,
            "high",
            "Language",
            "Business email compromise pattern",
            "Message combines authority, financial action, and urgency/confidentiality cues.",
            12,
        )

    if language_analysis["punctuation_flags"]["many_exclamation_marks"]:
        add_factor(factors, "low", "Language", "Excessive punctuation", "Message contains repeated exclamation marks.", 3)
    if language_analysis["punctuation_flags"]["contains_all_caps_phrase"]:
        add_factor(factors, "low", "Language", "All-caps phrase", "Message contains a sustained all-caps phrase.", 3)
    if attachments:
        add_factor(factors, "medium", "Attachments", "Attachment present", f"{len(attachments)} attachment(s) found in the message.", 8)

    severity_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(factors, key=lambda item: (severity_order[item["severity"]], -item["points"]))


def get_model_score(email_text):
    text_vector = vectorizer.transform([email_text])
    prediction_proba = model.predict_proba(text_vector)[0]
    classes = list(model.classes_)
    phishing_class_index = classes.index(1) if 1 in classes else classes.index("1")
    return int(prediction_proba[phishing_class_index] * 100)


@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    if "file" in request.files:
        _, headers, email_text, link_source_text, attachments = parse_email_message(request.files["file"])
        sender_domain = domain_from_address(headers.get("from"))
    else:
        headers, email_text, link_source_text, sender_domain, attachments = manual_message()

    if not email_text:
        return jsonify({"error": "No email text or file provided"}), 400

    header_analysis = analyze_headers(headers, sender_domain)
    sender_domain = header_analysis["sender_domain"]
    dns_results = check_domain_records(sender_domain) if sender_domain else None
    links = extract_links(link_source_text or email_text)
    link_analysis = analyze_links(links, sender_domain)
    language_analysis = analyze_language(email_text)
    risk_factors = build_risk_factors(
        dns_results,
        header_analysis,
        link_analysis,
        language_analysis,
        attachments,
    )

    model_score = get_model_score(email_text)
    heuristic_points = min(45, sum(factor["points"] for factor in risk_factors))
    threat_score = max(model_score, min(100, int((model_score * 0.7) + heuristic_points)))
    if any(factor["severity"] == "high" and factor["category"] != "DNS" for factor in risk_factors):
        threat_score = max(threat_score, 75)

    is_phishing = threat_score > 50
    verdict = "high_risk" if threat_score >= 75 else "suspicious" if threat_score >= 51 else "low_risk"
    explanation = (
        f"Model phishing probability is {model_score}%. "
        f"Evidence review found {len(risk_factors)} risk factor(s), "
        f"including {link_analysis['suspicious_count']} suspicious link(s)."
    )

    return jsonify({
        "dns_analysis": dns_results,
        "extracted_domain": sender_domain,
        "header_analysis": header_analysis,
        "link_analysis": link_analysis,
        "language_analysis": language_analysis,
        "attachments": attachments,
        "risk_factors": risk_factors,
        "score_breakdown": {
            "model_probability": model_score,
            "heuristic_points": heuristic_points,
            "final_score": threat_score,
            "verdict": verdict,
        },
        "ai_analysis": {
            "threat_score": threat_score,
            "is_phishing": is_phishing,
            "links": link_analysis["links"],
            "suspicious_links": link_analysis["suspicious_links"],
            "explanation": explanation,
        },
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
