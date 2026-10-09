from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.schemas.common import ScanResult, EvidenceFactor
from core.engines.network.flow_classifier import analyze_network_flow

class NetworkFlowRequest(BaseModel):
    src_ip: str
    dst_ip: str
    packet_count: int
    byte_count: int
    duration_ms: float

router = APIRouter()

@router.post("/", response_model=ScanResult)
async def scan_network(request: NetworkFlowRequest):
    """
    Endpoint for Intelligent Cyber Threat Detection (Network Flow Anomaly).
    """
    try:
        analysis = analyze_network_flow(
            packet_count=request.packet_count,
            byte_count=request.byte_count,
            duration_ms=request.duration_ms
        )
        return ScanResult(
            risk_score=analysis["risk_score"],
            risk_tier=analysis["risk_tier"],
            xai_explanation=analysis["xai_explanation"],
            evidence_factors=[
                EvidenceFactor(**f) for f in analysis["evidence_factors"]
            ],
            mitre_ttp=analysis["mitre_ttp"],
            confidence=analysis["confidence"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
