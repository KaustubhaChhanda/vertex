from fastapi import APIRouter, HTTPException
from models.schemas.common import MessageScanRequest, EmailScanRequest, ScanResult, EvidenceFactor
from core.engines.phishing.llm_scanner import analyze_phishing_intent
from core.engines.response import recommend_response
from core.threat_store import ThreatStore

router = APIRouter()

@router.post("/email", response_model=ScanResult)
async def scan_email(request: EmailScanRequest):
    """
    Endpoint for Email scanning matching Blueprint:
    POST /api/v1/scan/email
    Uses Cloud LLM / semantic engine and persists incident to ThreatStore.
    """
    try:
        analysis = analyze_phishing_intent(request.email_text, source="email")
        actions = recommend_response("Phishing", analysis.get("risk_tier", "Safe"))
        action_name = analysis.get("action") or (actions[0]["name"] if actions else "Quarantine Email")

        # Record real event in SOC ThreatStore
        sender_hint = "Unknown Sender"
        if request.headers and isinstance(request.headers, dict):
            sender_hint = request.headers.get("from", request.headers.get("sender", "Email Inbound"))

        ThreatStore.record_event(
            threat_type="Phishing Email",
            target=f"{sender_hint}: {request.email_text[:60]}...",
            risk_tier=analysis.get("risk_tier", "Safe"),
            risk_score=analysis.get("risk_score", 0.0),
            xai_explanation=analysis.get("xai_explanation", "Scanned email text."),
            mitre_ttp=analysis.get("mitre_ttp", "T1566"),
            recommended_response=action_name,
            evidence_factors=analysis.get("evidence_factors", [])
        )

        return ScanResult(
            risk_score=analysis.get("risk_score", 0.0),
            risk_tier=analysis.get("risk_tier", "Safe"),
            xai_explanation=analysis.get("xai_explanation", "Scanned email text."),
            mitre_ttp=analysis.get("mitre_ttp", "T1566"),
            action=action_name,
            evidence_factors=[
                EvidenceFactor(**factor) for factor in analysis.get("evidence_factors", [])
            ],
            confidence=analysis.get("confidence", 0.95)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/message", response_model=ScanResult)
async def scan_message(request: MessageScanRequest):
    """
    Endpoint for unified message scanning (SMS, WhatsApp, Slack).
    """
    try:
        source_label = request.source or "message"
        analysis = analyze_phishing_intent(request.message_text, source=source_label)
        actions = recommend_response("Phishing", analysis.get("risk_tier", "Safe"))
        action_name = analysis.get("action") or (actions[0]["name"] if actions else "Warn User")

        ThreatStore.record_event(
            threat_type="Phishing Message (SMS/Chat)",
            target=f"[{source_label.upper()}] {request.message_text[:60]}...",
            risk_tier=analysis.get("risk_tier", "Safe"),
            risk_score=analysis.get("risk_score", 0.0),
            xai_explanation=analysis.get("xai_explanation", "Scanned message text."),
            mitre_ttp=analysis.get("mitre_ttp", "T1566"),
            recommended_response=action_name,
            evidence_factors=analysis.get("evidence_factors", [])
        )

        return ScanResult(
            risk_score=analysis.get("risk_score", 0.0),
            risk_tier=analysis.get("risk_tier", "Safe"),
            xai_explanation=analysis.get("xai_explanation", "Scanned message text."),
            mitre_ttp=analysis.get("mitre_ttp", "T1566"),
            action=action_name,
            evidence_factors=[
                EvidenceFactor(**factor) for factor in analysis.get("evidence_factors", [])
            ],
            confidence=analysis.get("confidence", 0.95)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
