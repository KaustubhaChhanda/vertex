from fastapi import APIRouter, HTTPException
from models.schemas.common import ScanResult, EvidenceFactor
from pydantic import BaseModel
from core.engines.identity.registry import analyze_impersonation, IdentityCheckRequest

router = APIRouter()

@router.post("/", response_model=ScanResult)
async def scan_identity(request: IdentityCheckRequest):
    try:
        analysis = analyze_impersonation(request)
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
