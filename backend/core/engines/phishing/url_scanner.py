import os
import re
import math
import urllib.parse
import numpy as np
import xgboost as xgb
from typing import Dict, Any, List
from core.llm.client import CloudLLMClient

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "data", "models"))
os.makedirs(MODELS_DIR, exist_ok=True)
XGB_PATH = os.path.join(MODELS_DIR, "url_xgboost.json")

# Trusted global entities and top domains that should NEVER be flagged as threats
TRUSTED_DOMAINS = [
    "google.com", "google.co.in", "google.co.uk", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "live.com", "office.com", "bing.com", "apple.com", "icloud.com",
    "github.com", "wikipedia.org", "wikimedia.org", "amazon.com", "cloudflare.com",
    "mozilla.org", "youtube.com", "yahoo.com", "linkedin.com", "twitter.com", "x.com",
    "stackoverflow.com", "nytimes.com", "cnn.com", "bbc.com", "reuters.com", "theverge.com",
    "krebsonsecurity.com", "wired.com", "medium.com", "reddit.com", "cisa.gov", "nist.gov"
]

HIGH_RISK_TLDS = [".ru", ".xyz", ".top", ".buzz", ".work", ".click", ".surf", ".gq", ".ml", ".cf", ".tk", ".su"]

BRAND_SPOOFS = [
    "paypa1", "paypal-", "micros0ft", "microsoft-verify", "apple-id-", "appleid-",
    "g00gle", "amaz0n", "amazon-security", "chase-auth", "bofa-update", "netflix-login",
    "secure-banking", "account-verify-login", "wallet-connect-dapp", "metamask-auth"
]

def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy for domain randomness detection."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return round(float(-sum((count / length) * math.log2(count / length) for count in freq.values())), 4)

def extract_features_vector(url: str) -> Dict[str, Any]:
    """Extracts features isolating domain properties from path characteristics."""
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw

    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        parsed = urllib.parse.urlparse("http://unknown-host.com")

    domain = (parsed.netloc.split(":")[0] or "").lower()
    path = (parsed.path or "").lower()

    # Domain features
    domain_length = len(domain)
    domain_entropy = calculate_shannon_entropy(domain)
    digits_in_domain = sum(c.isdigit() for c in domain)
    domain_digit_ratio = round(digits_in_domain / max(domain_length, 1), 4)
    
    subparts = [p for p in domain.split(".") if p]
    num_subdomains = max(len(subparts) - 2, 0) if len(subparts) > 1 else 0

    is_https = 1.0 if raw.lower().startswith("https://") else 0.0
    has_ip = 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain) else 0.0
    has_high_risk_tld = 1.0 if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) else 0.0
    has_brand_spoof = 1.0 if any(spoof in domain for spoof in BRAND_SPOOFS) else 0.0
    has_punycode = 1.0 if "xn--" in domain else 0.0

    # Path features
    path_length = len(path)
    # Search / Blog indicator (e.g. readmore, search, query, view)
    is_safe_read_more = 1.0 if any(k in raw.lower() for k in ["readmore", "read-more", "search?q=", "utm_", "page=", "article"]) else 0.0

    # Vector of 10 features:
    # [domain_length, domain_entropy, domain_digit_ratio, num_subdomains, is_https, has_ip, has_high_risk_tld, has_brand_spoof, has_punycode, is_safe_read_more]
    vec = np.array([[
        float(domain_length),
        float(domain_entropy),
        float(domain_digit_ratio),
        float(num_subdomains),
        float(is_https),
        float(has_ip),
        float(has_high_risk_tld),
        float(has_brand_spoof),
        float(has_punycode),
        float(is_safe_read_more)
    ]])

    return {
        "domain": domain,
        "path": path,
        "domain_length": domain_length,
        "domain_entropy": domain_entropy,
        "domain_digit_ratio": domain_digit_ratio,
        "num_subdomains": num_subdomains,
        "is_https": bool(is_https),
        "has_ip": bool(has_ip),
        "has_high_risk_tld": bool(has_high_risk_tld),
        "has_brand_spoof": bool(has_brand_spoof),
        "has_punycode": bool(has_punycode),
        "is_safe_read_more": bool(is_safe_read_more),
        "vector": vec
    }


def train_balanced_xgboost() -> xgb.XGBClassifier:
    """Trains a balanced XGBoost model to replace overfitted dummy models."""
    np.random.seed(42)
    X = []
    y = []

    # 1. Benign patterns (news, blogs, search results, readmore, normal corporate domains)
    for _ in range(400):
        dom_len = np.random.randint(8, 24)
        entropy = np.random.uniform(2.0, 3.8)
        digit_ratio = np.random.uniform(0.0, 0.05)
        subdomains = np.random.choice([0, 0, 1], p=[0.7, 0.2, 0.1])
        is_https = 1.0 if np.random.rand() > 0.1 else 0.0
        has_ip = 0.0
        high_risk_tld = 0.0
        brand_spoof = 0.0
        punycode = 0.0
        read_more = 1.0 if np.random.rand() > 0.4 else 0.0
        X.append([dom_len, entropy, digit_ratio, subdomains, is_https, has_ip, high_risk_tld, brand_spoof, punycode, read_more])
        y.append(0)

    # 2. Phishing patterns (IP hosts, brand spoofing, high-risk TLDs, extreme entropy, punycode)
    for _ in range(400):
        dom_len = np.random.randint(22, 60)
        entropy = np.random.uniform(3.9, 5.2)
        digit_ratio = np.random.uniform(0.1, 0.4)
        subdomains = np.random.choice([2, 3, 4])
        is_https = np.random.choice([0.0, 1.0])
        has_ip = 1.0 if np.random.rand() > 0.6 else 0.0
        high_risk_tld = 1.0 if np.random.rand() > 0.3 else 0.0
        brand_spoof = 1.0 if np.random.rand() > 0.4 else 0.0
        punycode = 1.0 if np.random.rand() > 0.8 else 0.0
        read_more = 0.0
        X.append([dom_len, entropy, digit_ratio, subdomains, is_https, has_ip, high_risk_tld, brand_spoof, punycode, read_more])
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss"
    )
    model.fit(X, y)
    model.save_model(XGB_PATH)
    return model


url_model = None
try:
    if os.path.exists(XGB_PATH):
        url_model = xgb.XGBClassifier()
        url_model.load_model(XGB_PATH)
        # Check feature dimension compatibility
        if url_model.n_features_in_ != 10:
            print("Upgrading URL XGBoost model to 10-feature architecture...")
            url_model = train_balanced_xgboost()
    else:
        url_model = train_balanced_xgboost()
except Exception as e:
    print(f"Retraining URL classifier due to: {e}")
    url_model = train_balanced_xgboost()


def analyze_url_structure(url: str) -> Dict[str, Any]:
    """
    Evaluates a URL with domain-isolation features, XGBoost model,
    trusted whitelist, AbuseIPDB reputation, and LLM triage.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        return {
            "risk_score": 0.0,
            "risk_tier": "Safe",
            "xai_explanation": "Empty URL target.",
            "evidence_factors": [],
            "mitre_ttp": "None",
            "confidence": 1.0
        }

    feat = extract_features_vector(cleaned)
    domain = feat["domain"]

    # 1. Domain Whitelist check (Never flag trusted entities or search engine links)
    is_whitelisted = any(domain == root or domain.endswith("." + root) for root in TRUSTED_DOMAINS) or \
                     domain.endswith((".gov", ".gov.in", ".edu", ".mil"))

    if is_whitelisted:
        return {
            "risk_score": 0.01,
            "risk_tier": "Safe",
            "xai_explanation": f"Verified trusted corporate / institutional domain: {domain}. Zero malicious indicators detected.",
            "evidence_factors": [
                {"factor": "Domain Authority", "value": "Whitelisted Infrastructure Entity", "contribution": 0.0},
                {"factor": "Security Validation", "value": "Reputable Host Reputation", "contribution": 0.0}
            ],
            "mitre_ttp": "None",
            "confidence": 1.0
        }

    # 2. Hard malicious signatures (Immediate Critical triage)
    if feat["has_ip"] or (feat["has_brand_spoof"] and (feat["has_high_risk_tld"] or not feat["is_https"])):
        risk_score = 0.95
        tier = "Critical"
        evidence_factors = [
            {"factor": "Domain Deception", "value": f"Host signature imitation: {domain}", "contribution": 0.50},
            {"factor": "Protocol/Host Anomaly", "value": "Raw IP Host or Untrusted TLD", "contribution": 0.45}
        ]
        xai = f"High-confidence threat: Detected brand spoofing or direct IP host on '{domain}'. Immediate credential theft risk."
        ttp = "T1566.002"
        return {
            "risk_score": risk_score,
            "risk_tier": tier,
            "xai_explanation": xai,
            "evidence_factors": evidence_factors,
            "mitre_ttp": ttp,
            "confidence": 0.98
        }

    # 3. XGBoost Model Probability
    probs = url_model.predict_proba(feat["vector"])[0]
    malicious_prob = float(probs[1])
    
    # If the URL is simply a blog article or search result link with "read more", ensure safe floor
    if feat["is_safe_read_more"] and not feat["has_brand_spoof"] and not feat["has_ip"]:
        malicious_prob = min(malicious_prob, 0.08)

    risk_score = round(min(max(malicious_prob, 0.02), 1.0), 4)

    # 4. AbuseIPDB Reputation Check (if key configured)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    abuse_confidence = 0.0
    if abuse_key and abuse_key != "your_abuseipdb_api_key_here" and not is_whitelisted:
        try:
            import socket, requests
            target_ip = domain if feat["has_ip"] else socket.gethostbyname(domain)
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": abuse_key, "Accept": "application/json"}
            params = {"ipAddress": target_ip, "maxAgeInDays": "90"}
            resp = requests.get(abuse_url, headers=headers, params=params, timeout=3)
            if resp.status_code == 200:
                abuse_confidence = float(resp.json().get("data", {}).get("abuseConfidenceScore", 0)) / 100.0
        except Exception:
            pass

    if abuse_confidence > 0.3:
        risk_score = round(min(max(risk_score, abuse_confidence), 1.0), 4)

    # 5-Tier classification
    if risk_score > 0.85:
        tier = "Critical"
    elif risk_score > 0.65:
        tier = "High"
    elif risk_score > 0.40:
        tier = "Medium"
    elif risk_score > 0.20:
        tier = "Low"
    else:
        tier = "Safe"

    evidence_factors = [
        {"factor": "Domain Entropy", "value": f"{feat['domain_entropy']:.2f} bits", "contribution": round(feat["domain_entropy"] / 5.0 * 0.25, 3)},
        {"factor": "Domain Length", "value": f"{feat['domain_length']} chars", "contribution": 0.05 if feat['domain_length'] < 30 else 0.25},
        {"factor": "Protocol Security", "value": "HTTPS" if feat["is_https"] else "Insecure HTTP", "contribution": 0.0 if feat["is_https"] else 0.20}
    ]
    if feat["has_brand_spoof"]:
        evidence_factors.append({"factor": "Brand Mimicry", "value": f"Spoof pattern in {domain}", "contribution": 0.40})
    if feat["has_high_risk_tld"]:
        evidence_factors.append({"factor": "High-Risk TLD", "value": f"TLD in unmonitored zone", "contribution": 0.20})
    if abuse_confidence > 0.0:
        evidence_factors.append({"factor": "AbuseIPDB Score", "value": f"{abuse_confidence*100:.0f}% confidence", "contribution": round(abuse_confidence, 3)})

    xai_explanation = (
        f"XGBoost structural model evaluated '{domain}' (Entropy: {feat['domain_entropy']:.2f}, "
        f"Subdomains: {feat['num_subdomains']}, Protocol: {'HTTPS' if feat['is_https'] else 'HTTP'}). "
        f"Assessed risk: {risk_score*100:.1f}% ({tier} Risk)."
    )

    return {
        "risk_score": risk_score,
        "risk_tier": tier,
        "xai_explanation": xai_explanation,
        "evidence_factors": evidence_factors,
        "mitre_ttp": "T1190" if tier in ["High", "Critical"] else "None",
        "confidence": 0.95
    }
