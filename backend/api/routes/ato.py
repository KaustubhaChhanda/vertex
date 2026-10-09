from fastapi import APIRouter, HTTPException
from models.schemas.ato import LoginAnomalyRequest, LoginScanResponse
from core.engines.ato.isolation_forest import evaluate_login_telemetry
from core.threat_store import ThreatStore

router = APIRouter()

@router.post("/", response_model=LoginScanResponse)
@router.post("", response_model=LoginScanResponse)
@router.post("/login", response_model=LoginScanResponse)
async def scan_login(request: LoginAnomalyRequest):
    """
    Endpoint for Account Takeover (ATO) and login anomaly detection.
    Matches Blueprint: POST /api/v1/scan/login
    Records real event to SOC ThreatStore.
    """
    try:
        result = evaluate_login_telemetry(
            user_id=request.user_id,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            timestamp_str=request.timestamp,
            failed_attempts=request.failed_attempts
        )

        travel_text = " (Impossible Physical Travel)" if result.get("impossible_travel") else ""
        explanation = f"Isolation Forest evaluated login: anomaly score {result['anomaly_score']:.2f}.{travel_text} Action: {result['action']}."

        ThreatStore.record_event(
            threat_type="Account Takeover (ATO)",
            target=f"User {request.user_id} (IP: {request.ip_address})",
            risk_tier=result["risk_tier"],
            risk_score=result["anomaly_score"],
            xai_explanation=explanation,
            mitre_ttp="T1078",
            recommended_response=result["action"],
            evidence_factors=[
                {"factor": "Impossible Travel", "value": "Yes" if result.get("impossible_travel") else "No", "contribution": 0.5 if result.get("impossible_travel") else 0.0},
                {"factor": "Failed Attempts", "value": str(request.failed_attempts), "contribution": min(request.failed_attempts * 0.1, 0.4)}
            ]
        )

        return LoginScanResponse(
            anomaly_score=result["anomaly_score"],
            risk_tier=result["risk_tier"],
            shap_attributions=result["shap_attributions"],
            impossible_travel=result["impossible_travel"],
            action=result["action"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
