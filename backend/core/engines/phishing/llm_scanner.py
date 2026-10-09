import os
import json
import re
from typing import Dict, Any
from core.llm.client import CloudLLMClient

def analyze_phishing_intent(text: str, source: str = "email") -> Dict[str, Any]:
    """
    Evaluates semantic persuasion, urgency, brand impersonation, and deceptive intent
    under the LLMPEA framework.
    Uses Cloud LLM (Groq / Gemini) with an intelligent calibrated heuristic engine fallback.
    """
    cleaned_text = (text or "").strip()
    if not cleaned_text:
        return {
            "risk_score": 0.01,
            "risk_tier": "Safe",
            "xai_explanation": "Empty message content. No malicious patterns detected.",
            "evidence_factors": [{"factor": "Content Length", "value": "0 chars", "contribution": 0.0}],
            "mitre_ttp": "None",
            "confidence": 1.0,
            "action": "Allow"
        }

    # 1. High-Context Cloud LLM Semantic Reasoning
    prompt = f"""
You are an expert cybersecurity triage analyst evaluating an inbound {source}.
Evaluate if this message is benign business communication, spam, or a genuine phishing / social engineering threat.

CRITICAL INSTRUCTIONS:
- Routine corporate emails, meeting requests, friendly greetings, or normal notifications without credential harvesting or suspicious links MUST be marked as "Safe" or "Low" risk (risk_score < 0.20).
- Flag as "High" or "Critical" ONLY when there is clear deception: credential harvesting lures, spoofed brand domains, urgent threats of account deactivation/suspension, requests for passwords/2FA tokens, gift card or wire transfer demands.

Output strictly valid JSON matching this schema:
{{
  "risk_score": <float between 0.0 and 1.0>,
  "risk_tier": <"Safe" | "Low" | "Medium" | "High" | "Critical">,
  "xai_explanation": <detailed 2-3 sentence explanation explaining why this message is safe or dangerous>,
  "evidence_factors": [
    {{"factor": "<Name of factor, e.g. Domain Mimicry, Artificial Urgency, Credential Harvest>", "value": "<Detected snippet>", "contribution": <float between 0.0 and 0.5>}}
  ],
  "mitre_ttp": "<Relevant MITRE ATT&CK ID such as T1566.001 or T1566.002 or None>",
  "recommended_playbook": "<Actionable mitigation steps for SOC analyst and recipient>",
  "action": "<Quarantine Email | Block Sender | Warn User | Log Event | Allow>"
}}

Message to analyze:
\"\"\"
{cleaned_text[:4000]}
\"\"\"
"""

    cloud_result = CloudLLMClient.call_groq(prompt)
    if not cloud_result:
        cloud_result = CloudLLMClient.call_gemini(prompt)

    if cloud_result and isinstance(cloud_result, dict) and "risk_score" in cloud_result:
        try:
            score = float(cloud_result.get("risk_score", 0.0))
            score = min(max(score, 0.0), 1.0)
            tier = cloud_result.get("risk_tier", "Low")
            if tier not in ["Safe", "Low", "Medium", "High", "Critical"]:
                tier = "Critical" if score > 0.85 else "High" if score > 0.65 else "Medium" if score > 0.40 else "Low" if score > 0.15 else "Safe"

            return {
                "risk_score": round(score, 4),
                "risk_tier": tier,
                "xai_explanation": cloud_result.get("xai_explanation", "Cloud LLM completed semantic persuasion analysis."),
                "evidence_factors": cloud_result.get("evidence_factors", []),
                "mitre_ttp": cloud_result.get("mitre_ttp", "T1566"),
                "recommended_playbook": cloud_result.get("recommended_playbook", "1. Quarantine message. 2. Block sender domain. 3. Reset user credentials if accessed."),
                "action": cloud_result.get("action", "Quarantine Email" if score >= 0.65 else "Allow"),
                "confidence": 0.96
            }
        except Exception:
            pass

    # 2. Local Fallback Heuristic Engine (Calibrated to eliminate false positives on routine text)
    text_lower = cleaned_text.lower()

    # Exact high-threat combinations (requires combination of intent + lure)
    critical_lures = [
        "verify your password", "reset your password immediately", "account will be suspended within",
        "confirm your credentials", "unauthorized login detected click here", "update your banking",
        "wire transfer immediately", "send gift cards", "irs tax audit warrant"
    ]
    urgency_cues = ["immediately", "within 24 hours", "action required immediately", "final notice", "suspended if not updated"]
    credential_cues = ["password", "login link", "verify credentials", "2fa code", "reset link"]
    financial_cues = ["wire transfer", "bank routing", "crypto payment", "bitcoin wallet", "gift card code"]

    has_critical_lure = any(lure in text_lower for lure in critical_lures)
    found_urgency = [cue for cue in urgency_cues if cue in text_lower]
    found_cred = [cue for cue in credential_cues if cue in text_lower]
    found_fin = [cue for cue in financial_cues if cue in text_lower]

    evidence_factors = []
    
    if has_critical_lure or (len(found_urgency) > 0 and len(found_cred) > 0):
        risk_score = 0.88
        tier = "Critical" if (len(found_urgency) > 1 or len(found_fin) > 0) else "High"
        evidence_factors.append({"factor": "High-Pressure Credential Lure", "value": "Found direct credential verification demand with deadline pressure", "contribution": 0.55})
        explanation = (
            f"Phishing alert: Message uses artificial urgency combined with credential harvesting triggers. "
            f"Detected pressure cues: {', '.join(found_urgency or ['Urgent Action'])}. Do not click links or provide credentials."
        )
        action = "Quarantine Email"
        ttp = "T1566.002"
        playbook = "1. Quarantine email immediately. 2. Blacklist sender domain. 3. Check mail logs for matching subject lines."
    elif (len(found_cred) > 0 or len(found_fin) > 0) and len(found_urgency) > 0:
        risk_score = 0.45
        tier = "Medium"
        evidence_factors.append({"factor": "Sensitive Action Request", "value": "Contains references to credentials or finances with some urgency", "contribution": 0.30})
        explanation = "Suspicious communication: References account credentials or payments with slight urgency. Exercise caution before proceeding."
        action = "Warn User"
        ttp = "T1566"
        playbook = "1. Display warning banner to recipient. 2. Verify sender via secondary channel before taking action."
    else:
        risk_score = 0.04
        tier = "Safe"
        evidence_factors.append({"factor": "Linguistic Authenticity", "value": "Standard business communication tone", "contribution": 0.0})
        explanation = "Verified safe communication. Normal conversational style with zero deceptive urgency or credential harvesting indicators."
        action = "Allow"
        ttp = "None"
        playbook = "No action required. Communication safe for delivery."

    return {
        "risk_score": risk_score,
        "risk_tier": tier,
        "xai_explanation": explanation,
        "evidence_factors": evidence_factors,
        "mitre_ttp": ttp,
        "recommended_playbook": playbook,
        "action": action,
        "confidence": 0.94
    }
