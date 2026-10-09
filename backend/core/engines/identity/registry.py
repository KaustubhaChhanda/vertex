from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from models.schemas.common import ScanResult, EvidenceFactor
import Levenshtein

class IdentityCheckRequest(BaseModel):
    claimed_identity: str
    message_content: str
    sender_domain: str
    sender_email: str

# In a real setup, this would be a Postgres connection.
# For demo execution without a live seeded DB, we represent the registry in memory.
IDENTITY_REGISTRY = {
    "CEO": {
        "known_domains": ["vertex-security.com", "vertex.io"],
        "known_emails": ["ceo@vertex-security.com"],
        "style_baseline": "Formal, brief, often uses 'Action Required' and professional sign-offs."
    },
    "HR": {
        "known_domains": ["vertex-security.com"],
        "known_emails": ["hr@vertex-security.com", "careers@vertex-security.com"],
        "style_baseline": "Polite, informative, references company policies."
    }
}

def analyze_impersonation(request: IdentityCheckRequest) -> Dict[str, Any]:
    """
    Evaluates digital impersonation by checking domain spoofing and identity mismatches.
    """
    factors = []
    risk_score = 0.0
    
    # Check if identity is registered
    profile = IDENTITY_REGISTRY.get(request.claimed_identity)
    if not profile:
        return {
            "risk_score": 0.2,
            "risk_tier": "Low",
            "xai_explanation": "Claimed identity is not in the VIP registry. Standard phishing checks apply.",
            "evidence_factors": [],
            "mitre_ttp": "T1656",
            "confidence": 0.9
        }
    
    # 1. Exact Domain Match
    if request.sender_domain in profile["known_domains"]:
        factors.append({"factor": "Domain Match", "value": f"{request.sender_domain} is trusted.", "contribution": -0.2})
    else:
        # 2. Look-alike Domain Check (Levenshtein Distance)
        min_distance = min(Levenshtein.distance(request.sender_domain, d) for d in profile["known_domains"])
        if min_distance > 0 and min_distance <= 3:
            factors.append({"factor": "Lookalike Domain Spoofing", "value": f"{request.sender_domain} is dangerously close to a known domain.", "contribution": +0.6})
            risk_score += 0.8
        else:
            factors.append({"factor": "Unrecognized Domain", "value": f"{request.sender_domain} is not associated with this identity.", "contribution": +0.4})
            risk_score += 0.5
            
    # Determine Tier
    if risk_score >= 0.8:
        risk_tier = "Critical"
    elif risk_score >= 0.5:
        risk_tier = "High"
    elif risk_score >= 0.3:
        risk_tier = "Medium"
    else:
        risk_tier = "Safe"
        
    explanation = f"Impersonation analysis generated a risk score of {risk_score:.2f}."
    if risk_score > 0.5:
        explanation += " Strong indicators of domain spoofing or unauthorized sender identity detected."
        
    return {
        "risk_score": float(min(risk_score, 1.0)),
        "risk_tier": risk_tier,
        "xai_explanation": explanation,
        "evidence_factors": factors,
        "mitre_ttp": "T1656",
        "confidence": 0.95
    }
