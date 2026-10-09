import os
import tempfile
from fastapi import APIRouter, HTTPException, UploadFile, File
from models.schemas.common import MediaScanResponse
from core.engines.deepfake.scanner import analyze_media_file
from core.threat_store import ThreatStore

router = APIRouter()

@router.post("/", response_model=MediaScanResponse)
@router.post("", response_model=MediaScanResponse)
async def scan_media(file: UploadFile = File(...)):
    """
    Endpoint for Multimodal Deepfake & Synthetic Media Detection.
    Matches Blueprint: POST /api/v1/scan/media
    Persists scanned media result directly into SOC ThreatStore.
    """
    try:
        suffix = os.path.splitext(file.filename or "media.mp4")[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        try:
            result = analyze_media_file(tmp_path, file.filename or "media.mp4")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        risk_tier = result.get("risk_tier", "Low")
        visual_score = result.get("visual_score", 0.0)
        audio_score = result.get("audio_score", 0.0)
        overall_score = max(visual_score, audio_score)

        action_taken = "Flag Multimedia for Verification" if risk_tier in ["High", "Critical"] else "Allow / Archive"

        # Record real event in SOC ThreatStore
        ThreatStore.record_event(
            threat_type="Deepfake Media",
            target=file.filename or "uploaded_media_asset",
            risk_tier=risk_tier,
            risk_score=overall_score,
            xai_explanation=result.get("xai_explanation", "Media scan completed."),
            mitre_ttp="T1656",
            recommended_response=action_taken,
            evidence_factors=[
                {"factor": "Visual Synthetic Score", "value": f"{visual_score*100:.1f}%", "contribution": visual_score},
                {"factor": "Audio Acoustic Score", "value": f"{audio_score*100:.1f}%", "contribution": audio_score}
            ]
        )

        return MediaScanResponse(
            media_type=result.get("media_type", file.content_type or "unknown"),
            visual_score=visual_score,
            audio_score=audio_score,
            risk_tier=risk_tier,
            xai_explanation=result.get("xai_explanation", "Media scan completed.")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
