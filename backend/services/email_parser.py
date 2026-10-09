import email
from email import policy
from typing import Dict, Any

def parse_and_score_email_headers(raw_email_string: str) -> Dict[str, Any]:
    """
    Parses raw email headers and calculates an authentication risk score based on SPF/DKIM/DMARC.
    """
    msg = email.message_from_string(raw_email_string, policy=policy.default)
    
    auth_results = str(msg.get('Authentication-Results', '')).lower()
    return_path = str(msg.get('Return-Path', '')).strip('<>')
    from_header = str(msg.get('From', ''))
    
    # Extract domain from From header
    from_domain = ""
    if '@' in from_header:
        from_domain = from_header.split('@')[-1].strip('<>')
        
    return_domain = ""
    if '@' in return_path:
        return_domain = return_path.split('@')[-1]
        
    risk_score = 0.0
    factors = []
    
    # 1. SPF Check
    if 'spf=fail' in auth_results or 'spf=softfail' in auth_results:
        risk_score += 0.3
        factors.append({"factor": "SPF Failed", "value": "Sender IP not authorized by domain.", "contribution": 0.3})
    elif 'spf=pass' in auth_results:
        factors.append({"factor": "SPF Pass", "value": "Sender IP authorized.", "contribution": -0.1})
        
    # 2. DKIM Check
    if 'dkim=fail' in auth_results:
        risk_score += 0.3
        factors.append({"factor": "DKIM Failed", "value": "Cryptographic signature invalid or missing.", "contribution": 0.3})
    elif 'dkim=pass' in auth_results:
        factors.append({"factor": "DKIM Pass", "value": "Signature valid.", "contribution": -0.1})
        
    # 3. DMARC Check
    if 'dmarc=fail' in auth_results:
        risk_score += 0.2
        factors.append({"factor": "DMARC Failed", "value": "Domain alignment failed.", "contribution": 0.2})
        
    # 4. Alignment Check (From vs Return-Path)
    if from_domain and return_domain and from_domain != return_domain:
        risk_score += 0.4
        factors.append({"factor": "Domain Mismatch", "value": f"From ({from_domain}) != Return-Path ({return_domain})", "contribution": 0.4})
        
    return {
        "auth_risk_score": min(max(risk_score, 0.0), 1.0),
        "auth_factors": factors
    }
