import cv2
import numpy as np
from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
from models.schemas.common import ScanResult, EvidenceFactor
from core.engines.phishing.url_scanner import analyze_url_structure
from core.engines.response import recommend_response
from core.threat_store import ThreatStore

class UrlScanRequest(BaseModel):
    url: str
    source: Optional[str] = "portal"

router = APIRouter()

@router.post("/", response_model=ScanResult)
@router.post("", response_model=ScanResult)
async def scan_url(request: UrlScanRequest):
    """
    Endpoint for URL scanning using local trained XGBoost model.
    Matches Blueprint & Vertex.txt: POST /api/v1/scan/url
    Persists real incident data to SOC ThreatStore.
    """
    try:
        # Check active blocklist first
        if ThreatStore.is_blocked(request.url):
            return ScanResult(
                risk_score=1.0,
                risk_tier="Critical",
                xai_explanation=f"URL or host domain is present on the active Vertex SOC Blocklist. Direct access denied.",
                mitre_ttp="T1566.002",
                action="Block URLs",
                evidence_factors=[
                    EvidenceFactor(factor="Active Blocklist", value="Manual/SOC Blocklist Match", contribution=1.0)
                ],
                confidence=1.0
            )

        analysis = analyze_url_structure(request.url)
        if "error" in analysis:
            raise Exception(analysis["error"])
            
        actions = recommend_response("Phishing", analysis["risk_tier"])
        action_name = actions[0]["name"] if actions else "Block URLs"

        # Record real event in SOC ThreatStore
        ThreatStore.record_event(
            threat_type="Phishing & URL",
            target=request.url,
            risk_tier=analysis["risk_tier"],
            risk_score=analysis["risk_score"],
            xai_explanation=analysis["xai_explanation"],
            mitre_ttp=analysis.get("mitre_ttp", "T1190"),
            recommended_response=action_name,
            evidence_factors=analysis.get("evidence_factors", [])
        )
            
        return ScanResult(
            risk_score=analysis["risk_score"],
            risk_tier=analysis["risk_tier"],
            xai_explanation=analysis["xai_explanation"],
            mitre_ttp=analysis["mitre_ttp"],
            action=action_name,
            evidence_factors=[EvidenceFactor(**f) for f in analysis.get("evidence_factors", [])],
            confidence=analysis.get("confidence", 0.95)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/qr", response_model=ScanResult)
async def scan_qr(file: UploadFile = File(...)):
    """
    Endpoint for QR-Based Phishing Detection (Vertex.txt Scenario 1.c).
    Extracts embedded URL via Computer Vision (OpenCV QR Detector) and routes
    to real trained XGBoost classifier and SOC ThreatStore.
    """
    try:
        content = await file.read()
        nparr = np.frombuffer(content, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            raise ValueError("Uploaded file could not be decoded as an image.")
            
        detector = cv2.QRCodeDetector()
        decoded_url, points, _ = detector.detectAndDecode(img)
        
        if not decoded_url:
            ThreatStore.record_event(
                threat_type="QR Phishing",
                target=file.filename or "uploaded_qr.png",
                risk_tier="Safe",
                risk_score=0.0,
                xai_explanation="No QR code pattern detected in the uploaded image.",
                mitre_ttp="None",
                recommended_response="Allow"
            )
            return ScanResult(
                risk_score=0.0,
                risk_tier="Safe",
                xai_explanation="No QR code pattern detected in the uploaded image.",
                mitre_ttp="None",
                action="Allow",
                evidence_factors=[
                    EvidenceFactor(factor="QR Detection", value="No QR detected", contribution=0.0)
                ],
                confidence=1.0
            )

        # Route extracted URL through real XGBoost model
        analysis = analyze_url_structure(decoded_url)
        actions = recommend_response("Phishing", analysis["risk_tier"])
        action_name = actions[0]["name"] if actions else "Block URLs"
        
        evidence = [
            EvidenceFactor(factor="Decoded QR Target", value=decoded_url, contribution=0.3)
        ] + [EvidenceFactor(**f) for f in analysis.get("evidence_factors", [])]

        ThreatStore.record_event(
            threat_type="QR Phishing",
            target=decoded_url,
            risk_tier=analysis["risk_tier"],
            risk_score=analysis["risk_score"],
            xai_explanation=f"Computer Vision extracted target: {decoded_url}. {analysis['xai_explanation']}",
            mitre_ttp="T1566.002",
            recommended_response=action_name,
            evidence_factors=evidence
        )

        return ScanResult(
            risk_score=analysis["risk_score"],
            risk_tier=analysis["risk_tier"],
            xai_explanation=f"Computer Vision extracted target: {decoded_url}. {analysis['xai_explanation']}",
            mitre_ttp="T1566.002",
            action=action_name,
            evidence_factors=evidence,
            confidence=analysis.get("confidence", 0.95)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
