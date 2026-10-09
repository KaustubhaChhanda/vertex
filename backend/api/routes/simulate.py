import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from core.engines.ato.isolation_forest import evaluate_login_telemetry
from core.threat_store import ThreatStore

class SimulateLoginRequest(BaseModel):
    scenario: str  # "normal", "brute_force", "impossible_travel", "credential_compromise"

class SimulateLoginResponse(BaseModel):
    telemetry_event: Dict[str, Any]
    detection_result: Dict[str, Any]

router = APIRouter()

@router.post("/", response_model=SimulateLoginResponse)
@router.post("", response_model=SimulateLoginResponse)
async def simulate_login(request: SimulateLoginRequest):
    """
    Generates synthetic authentication telemetry and runs it through the
    real Isolation Forest ATO detection engine.
    Matches Blueprint: POST /api/v1/simulate/login
    Response: { "telemetry_event": object, "detection_result": object }
    """
    scenario = request.scenario.lower().strip()
    now_ts = str(time.time())

    # Build realistic telemetry based on scenario
    if scenario == "brute_force":
        telemetry = {
            "user_id": "U-9182",
            "ip_address": "45.22.11.2",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": now_ts,
            "failed_attempts": 14
        }
    elif scenario == "impossible_travel":
        telemetry = {
            "user_id": "U-8472",
            "ip_address": "185.15.12.5",  # London IP (moving from NYC)
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)",
            "timestamp": now_ts,
            "failed_attempts": 1
        }
    elif scenario == "credential_compromise":
        telemetry = {
            "user_id": "U-3321",
            "ip_address": "103.21.244.0",
            "user_agent": "Python-urllib/3.10 (Scripted Bot)",
            "timestamp": now_ts,
            "failed_attempts": 6
        }
    else:  # normal
        telemetry = {
            "user_id": "U-1001",
            "ip_address": "192.168.1.100",  # Normal NYC IP
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": now_ts,
            "failed_attempts": 0
        }

    # Run real model evaluation
    eval_result = evaluate_login_telemetry(
        user_id=telemetry["user_id"],
        ip_address=telemetry["ip_address"],
        user_agent=telemetry["user_agent"],
        timestamp_str=telemetry["timestamp"],
        failed_attempts=telemetry["failed_attempts"]
    )

    detection_result = {
        "anomaly_score": eval_result["anomaly_score"],
        "risk_tier": eval_result["risk_tier"],
        "shap_attributions": eval_result["shap_attributions"],
        "impossible_travel": eval_result["impossible_travel"],
        "action": eval_result["action"],
        "xai_explanation": eval_result["xai_explanation"]
    }

    # Record the simulator event so it shows up in the command center
    ThreatStore.record_event(
        threat_type=f"ATO Simulation: {scenario}",
        target=f"User {telemetry['user_id']} ({telemetry['ip_address']})",
        risk_tier=detection_result["risk_tier"],
        risk_score=detection_result["anomaly_score"],
        xai_explanation=detection_result["xai_explanation"],
        mitre_ttp="T1078",
        recommended_response=detection_result["action"],
        evidence_factors=[
            {"factor": k, "value": str(v), "contribution": v} 
            for k, v in eval_result["shap_attributions"].items()
        ]
    )

    return SimulateLoginResponse(
        telemetry_event=telemetry,
        detection_result=detection_result
    )
