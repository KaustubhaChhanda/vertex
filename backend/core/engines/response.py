from typing import List

# Matrix mapping Threat Type + Risk Tier to Actions
RESPONSE_MATRIX = {
    "Phishing": {
        "Low": ["Warn User", "Log Event"],
        "Medium": ["Warn User", "Flag for Review", "Log Event"],
        "High": ["Quarantine Email", "Block Sender Domain", "Notify SOC"],
        "Critical": ["Quarantine Email", "Block Sender Domain", "Revoke Active Sessions", "Notify SOC"]
    },
    "ATO": {
        "Low": ["Log Event"],
        "Medium": ["Require Step-Up Auth", "Log Event"],
        "High": ["Force Password Reset", "Block IP", "Notify SOC"],
        "Critical": ["Revoke Active Sessions", "Block IP", "Force Password Reset", "Notify SOC"]
    },
    "Deepfake": {
        "Low": ["Log Event"],
        "Medium": ["Flag for Manual Verification", "Log Event"],
        "High": ["Quarantine Media", "Notify SOC"],
        "Critical": ["Quarantine Media", "Report Impersonation", "Notify SOC"]
    },
    "Identity": {
        "Low": ["Warn Recipient", "Log Event"],
        "Medium": ["Warn Recipient", "Flag Message"],
        "High": ["Quarantine Message", "Report Impersonation", "Notify SOC"],
        "Critical": ["Quarantine Message", "Report Impersonation", "Revoke Sender Access", "Escalate"]
    },
    "Network": {
        "Low": ["Log Event"],
        "Medium": ["Monitor Flow", "Log Event"],
        "High": ["Rate Limit IP", "Notify SOC"],
        "Critical": ["Block Suspicious IP", "Isolate Subnet", "Escalate"]
    }
}

class Action:
    def __init__(self, name: str, automated: bool):
        self.name = name
        self.automated = automated
        
    def to_dict(self):
        return {"name": self.name, "automated": self.automated}

def recommend_response(threat_category: str, risk_tier: str) -> List[dict]:
    """
    Returns granular recommended actions based on the threat category and risk tier.
    """
    category = threat_category
    # Fallback to Phishing if category doesn't match exactly
    if category not in RESPONSE_MATRIX:
        category = "Phishing"
        
    actions = RESPONSE_MATRIX[category].get(risk_tier, ["Log Event"])
    
    # High and Critical actions are marked as automated responses
    return [Action(name=a, automated=risk_tier in ['High', 'Critical']).to_dict() for a in actions]
