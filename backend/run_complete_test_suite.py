import os
import io
import json
import requests
import numpy as np
from PIL import Image
import soundfile as sf

BASE_URL = "http://127.0.0.1:8000"

print("================================================================================")
print("VERTEX THREAT INTELLIGENCE SYSTEM - AUTOMATED VERIFICATION TEST SUITE")
print("Referencing: vertex_system_architecture_blueprint.txt & Vertex.txt")
print("================================================================================")

results = []

def run_test(name, func):
    try:
        status, data = func()
        print(f"\n[PASS] {name} (HTTP {status})")
        print(f"       Response: {json.dumps(data, indent=2)[:300]}...")
        results.append((name, True, status))
    except Exception as e:
        print(f"\n[FAIL] {name}: {e}")
        results.append((name, False, str(e)))

# 1. Health Check
def test_health():
    res = requests.get(f"{BASE_URL}/health")
    assert res.status_code == 200
    return res.status_code, res.json()
run_test("1. System Health & Active Model Engines", test_health)

# 2. URL Structural Threat Scan (XGBoost)
def test_url_scan():
    payload = {
        "url": "http://192.168.1.1/login-admin-verify-free-token-bonus",
        "source": "extension"
    }
    res = requests.post(f"{BASE_URL}/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data and "risk_tier" in data and "xai_explanation" in data
    return res.status_code, data
run_test("2. XGBoost Structural URL Threat Scan", test_url_scan)

# 3. QR-Based Phishing Scan (Computer Vision + XGBoost)
def test_qr_scan():
    # Generate a dummy test image for QR endpoint
    img = Image.new("RGB", (128, 128), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    files = {"file": ("test_qr.png", buf, "image/png")}
    res = requests.post(f"{BASE_URL}/api/v1/scan/qr", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "risk_tier" in data and "action" in data
    return res.status_code, data
run_test("3. Computer Vision QR Phishing Scan", test_qr_scan)

# 4. Email Phishing Scan (LLMPEA / NLP Intent)
def test_email_scan():
    payload = {
        "email_text": "URGENT: Your account has been suspended! Please click here immediately to reset your password and verify your bank payment details.",
        "headers": {"from": "security@fake-support.com"}
    }
    res = requests.post(f"{BASE_URL}/api/v1/scan/email", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_tier"] in ["High", "Critical"]
    return res.status_code, data
run_test("4. Email Phishing & Persuasion Analysis", test_email_scan)

# 5. Message / SMS Threat Scan
def test_message_scan():
    payload = {
        "message_text": "IRS Alert: Legal action pending against your SSN. Wire $500 immediately to avoid arrest.",
        "source": "sms"
    }
    res = requests.post(f"{BASE_URL}/api/v1/scan/message", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "evidence_factors" in data
    return res.status_code, data
run_test("5. SMS / Social Messaging Phishing Scan", test_message_scan)

# 6. Deepfake Visual Scan (SigLIP Model)
def test_visual_deepfake():
    img = Image.new("RGB", (224, 224), color=(210, 160, 120))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    files = {"file": ("face_sample.png", buf, "image/png")}
    res = requests.post(f"{BASE_URL}/api/v1/scan/media", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "visual_score" in data and "risk_tier" in data
    return res.status_code, data
run_test("6. Visual Deepfake Inference (SigLIP v2.0)", test_visual_deepfake)

# 7. Deepfake Audio Scan (Wav2Vec2 Model)
def test_audio_deepfake():
    buf = io.BytesIO()
    audio_data = (0.3 * np.sin(2 * np.pi * 440 * np.linspace(0, 1, 16000))).astype(np.float32)
    sf.write(buf, audio_data, 16000, format="WAV")
    buf.seek(0)
    files = {"file": ("voice_sample.wav", buf, "audio/wav")}
    res = requests.post(f"{BASE_URL}/api/v1/scan/media", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "audio_score" in data and "risk_tier" in data
    return res.status_code, data
run_test("7. Audio Voice Clone Deepfake Inference (Wav2Vec2)", test_audio_deepfake)

# 8. Account Takeover Scan (Isolation Forest & TreeSHAP)
def test_login_scan():
    payload = {
        "user_id": "U-8472",
        "ip_address": "185.15.12.5",
        "user_agent": "Mozilla/5.0 (iPhone; CPU OS 16)",
        "timestamp": "1728374920",
        "failed_attempts": 6
    }
    res = requests.post(f"{BASE_URL}/api/v1/scan/login", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "shap_attributions" in data and "impossible_travel" in data
    return res.status_code, data
run_test("8. Behavioral ATO Anomaly & TreeSHAP Attribution", test_login_scan)

# 9. Synthetic Auth Activity Simulator
def test_simulate_login():
    for scenario in ["normal", "impossible_travel", "brute_force", "credential_compromise"]:
        res = requests.post(f"{BASE_URL}/api/v1/simulate/login", json={"scenario": scenario})
        assert res.status_code == 200
        data = res.json()
        assert "telemetry_event" in data and "detection_result" in data
    return res.status_code, data
run_test("9. Auth Activity Telemetry Simulator (All 4 Scenarios)", test_simulate_login)

# 10. Admin SOC Incident Feed
def test_admin_threats():
    res = requests.get(f"{BASE_URL}/api/v1/admin/threats")
    assert res.status_code == 200
    data = res.json()
    assert "threats" in data
    return res.status_code, data
run_test("10. Central Admin SOC Incident Feed", test_admin_threats)

# 11. Central SOC Dashboard (Vertex.txt Metrics)
def test_admin_dashboard():
    res = requests.get(f"{BASE_URL}/api/v1/admin/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "total_events_analyzed" in data and "threat_categories" in data
    assert "recommended_responses" in data
    return res.status_code, data
run_test("11. SOC Command Dashboard (8 Vertex Metrics)", test_admin_dashboard)

print("\n================================================================================")
print(f"VERIFICATION SUMMARY: {sum(1 for _, ok, _ in results if ok)} / {len(results)} TESTS PASSED SUCCESSFULLY!")
print("================================================================================")
