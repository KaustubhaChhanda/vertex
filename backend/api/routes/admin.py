from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from core.threat_store import ThreatStore

router = APIRouter()

class BlockTargetRequest(BaseModel):
    target: str
    entry_type: Optional[str] = "domain"
    reason: Optional[str] = "SOC Analyst Action"
    incident_id: Optional[str] = None

class ActionRequest(BaseModel):
    incident_id: str
    action: Optional[str] = None
    target: Optional[str] = None

@router.get("/")
@router.get("")
async def get_threats():
    """
    Returns real logged incidents analyzed by Vertex engines.
    Matches Blueprint: GET /api/v1/admin/threats
    """
    try:
        incidents = ThreatStore.get_all_incidents()
        return {
            "status": "success",
            "count": len(incidents),
            "threats": incidents
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_dashboard_metrics():
    """
    Centralized SOC Dashboard Metrics computed dynamically from real events.
    Matches Vertex.txt specifications:
    1. Total Events Analyzed
    2. Threats Detected
    3. Threat Category Breakdown
    4. Risk Level Distribution
    5. Phishing Attempts
    6. Suspected Deepfakes
    7. Account Takeover Attempts
    8. Recommended Responses
    """
    try:
        metrics = ThreatStore.compute_dashboard_metrics()
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blocklist")
async def get_blocklist():
    """
    Returns the active URL and IP blocklist enforced by Vertex SOC and extension.
    """
    try:
        return {
            "status": "success",
            "blocklist": ThreatStore.get_blocklist()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/actions/block-url")
async def block_url_action(req: BlockTargetRequest):
    """
    Adds destination URL or host domain to the active Vertex Blocklist.
    """
    try:
        entry = ThreatStore.add_to_blocklist(req.target, req.entry_type or "domain", req.reason or "SOC Analyst Block")
        if req.incident_id:
            ThreatStore.update_incident_status(req.incident_id, "Blocked", action_taken="Block URLs")
        return {
            "status": "success",
            "message": f"Target '{req.target}' added to active Blocklist.",
            "entry": entry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/actions/quarantine")
async def quarantine_action(req: ActionRequest):
    """
    Quarantines suspicious email or actor account.
    """
    try:
        updated = ThreatStore.update_incident_status(req.incident_id, "Quarantined", action_taken="Quarantine Email")
        return {
            "status": "success",
            "message": f"Incident {req.incident_id} quarantined successfully.",
            "incident": updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/actions/block-ip")
async def block_ip_action(req: BlockTargetRequest):
    """
    Blocks source IP from communicating with enterprise infrastructure.
    """
    try:
        entry = ThreatStore.add_to_blocklist(req.target, "ip", req.reason or "Hostile IP Blocked by SOC")
        if req.incident_id:
            ThreatStore.update_incident_status(req.incident_id, "Blocked", action_taken="Block IP/Device")
        return {
            "status": "success",
            "message": f"IP '{req.target}' successfully blocked.",
            "entry": entry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/actions/dismiss")
async def dismiss_action(req: ActionRequest):
    """
    Marks incident as Resolved / False Positive.
    """
    try:
        updated = ThreatStore.update_incident_status(req.incident_id, "Resolved", action_taken="Dismissed / Verified")
        return {
            "status": "success",
            "message": f"Incident {req.incident_id} marked as resolved.",
            "incident": updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
