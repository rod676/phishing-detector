import re
import socket
import requests
import validators
from urllib.parse import urlparse

# Patterns suspects connus
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "paypal", "amazon", "microsoft", "apple",
    "confirm", "password", "credential", "urgent", "suspended"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".link", ".work", ".party", ".loan"
]

def analyze_url(url: str) -> dict:
    """Analyse technique complète d'une URL."""
    
    result = {
        "url": url,
        "is_valid": False,
        "domain": "",
        "ip_address": "",
        "uses_https": False,
        "suspicious_keywords": [],
        "suspicious_tld": False,
        "is_shortened": False,
        "redirects": [],
        "domain_length": 0,
        "has_ip_in_url": False,
        "subdomain_count": 0,
        "risk_indicators": []
    }
    
    # Validation basique
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    if not validators.url(url):
        result["error"] = "URL invalide"
        return result
    
    result["is_valid"] = True
    parsed = urlparse(url)
    domain = parsed.netloc
    result["domain"] = domain
    result["uses_https"] = parsed.scheme == "https"
    result["domain_length"] = len(domain)
    
    # HTTPS absent = risque
    if not result["uses_https"]:
        result["risk_indicators"].append("No HTTPS — connection not encrypted")
    
    # IP dans l'URL au lieu d'un domaine
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.search(domain):
        result["has_ip_in_url"] = True
        result["risk_indicators"].append("IP address used instead of domain name")
    
    # Keywords suspects dans l'URL
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    result["suspicious_keywords"] = found_keywords
    if found_keywords:
        result["risk_indicators"].append(
            f"Suspicious keywords detected: {', '.join(found_keywords)}"
        )
    
    # TLD suspect
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            result["suspicious_tld"] = True
            result["risk_indicators"].append(f"High-risk TLD detected: {tld}")
            break
    
    # Domaine trop long (souvent phishing)
    if result["domain_length"] > 30:
        result["risk_indicators"].append(
            f"Unusually long domain ({result['domain_length']} chars)"
        )
    
    # URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link"]
    if any(s in domain for s in shorteners):
        result["is_shortened"] = True
        result["risk_indicators"].append("URL shortener detected — real destination hidden")
    
    # Sous-domaines excessifs
    subdomains = domain.split(".")
    result["subdomain_count"] = len(subdomains) - 2
    if result["subdomain_count"] > 2:
        result["risk_indicators"].append(
            f"Excessive subdomains ({result['subdomain_count']}) — common phishing pattern"
        )
    
    # Résolution IP
    try:
        result["ip_address"] = socket.gethostbyname(domain)
    except:
        result["risk_indicators"].append("Domain cannot be resolved — possibly fake")
    
    # Vérification des redirections
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if response.history:
            result["redirects"] = [r.url for r in response.history]
            result["risk_indicators"].append(
                f"URL redirects {len(response.history)} time(s)"
            )
    except:
        result["risk_indicators"].append("URL unreachable or timed out")
    
    return result


def analyze_email_text(email_text: str) -> dict:
    """Analyse le texte d'un email pour détecter des patterns de phishing."""
    
    result = {
        "urgency_indicators": [],
        "threat_indicators": [],
        "action_requests": [],
        "urls_found": [],
        "risk_indicators": []
    }
    
    text_lower = email_text.lower()
    
    # Urgence
    urgency_words = [
        "urgent", "immediately", "asap", "right now", "expires",
        "24 hours", "48 hours", "limited time", "act now", "dringend",
        "sofort", "unverzüglich"
    ]
    result["urgency_indicators"] = [w for w in urgency_words if w in text_lower]
    if result["urgency_indicators"]:
        result["risk_indicators"].append("Urgency language detected")
    
    # Menaces
    threat_words = [
        "suspended", "terminated", "blocked", "unauthorized",
        "breach", "compromised", "hacked", "locked", "disabled"
    ]
    result["threat_indicators"] = [w for w in threat_words if w in text_lower]
    if result["threat_indicators"]:
        result["risk_indicators"].append("Threat language detected")
    
    # Demandes d'action suspectes
    action_words = [
        "click here", "verify now", "confirm your", "update your",
        "enter your password", "provide your", "sign in"
    ]
    result["action_requests"] = [w for w in action_words if w in text_lower]
    if result["action_requests"]:
        result["risk_indicators"].append("Suspicious action requests found")
    
    # URLs dans le texte
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    result["urls_found"] = url_pattern.findall(email_text)
    
    return result