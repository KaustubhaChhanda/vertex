import os
import math
import joblib
import numpy as np
from datetime import datetime
from typing import Dict, Any, Tuple

# Locate saved Isolation Forest and SHAP explainer
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..", "data", "models"))
ISO_PATH = os.path.join(MODELS_DIR, "isolation_forest.joblib")
SHAP_PATH = os.path.join(MODELS_DIR, "shap_explainer.joblib")

iso_forest = None
shap_explainer = None

try:
    if os.path.exists(ISO_PATH) and os.path.exists(SHAP_PATH):
        print(f"Loading real Isolation Forest & SHAP Explainer from {MODELS_DIR}...")
        iso_forest = joblib.load(ISO_PATH)
        shap_explainer = joblib.load(SHAP_PATH)
        print("ATO Models loaded successfully.")
    else:
        print("Warning: Pre-trained ATO models not found. Creating inline...")
        from sklearn.ensemble import IsolationForest
        import shap
        iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        X_base = np.array([
            [10.0, 10.0, 0.0, 1.0, 0],
            [15.0, 15.0, 0.1, 1.0, 0],
            [20.0, 25.0, 0.2, 1.0, 1],
            [4000.0, 2000.0, 0.8, 0.0, 8]
        ])
        iso_forest.fit(X_base)
        shap_explainer = shap.TreeExplainer(iso_forest)
except Exception as e:
    print(f"Error loading ATO models: {e}")


# In-memory baseline user history for stateful velocity and displacement calculation
USER_AUTH_HISTORY: Dict[str, Dict[str, Any]] = {
    "default": {
        "last_ip": "192.168.1.100",
        "last_lat": 40.7128,  # New York City
        "last_lon": -74.0060,
        "last_timestamp": datetime.utcnow().timestamp() - 3600,
        "known_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
}


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two coordinates in kilometers."""
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return round(R * c, 2)


def resolve_ip_coordinates(ip_address: str) -> Tuple[float, float, str]:
    """
    Resolves IP to coordinates and location label.
    Uses realistic IP mapping for enterprise simulation.
    """
    known_geos = {
        "192.168.1.100": (40.7128, -74.0060, "New York, USA"),
        "127.0.0.1": (40.7128, -74.0060, "Localhost (NYC Baseline)"),
        "185.15.12.5": (51.5074, -0.1278, "London, UK"),
        "45.22.11.2": (35.6762, 139.6503, "Tokyo, Japan"),
        "103.21.244.0": (28.6139, 77.2090, "New Delhi, India"),
        "89.160.20.156": (59.3293, 18.0686, "Stockholm, Sweden")
    }
    
    if ip_address in known_geos:
        return known_geos[ip_address]
        
    # Deterministic coordinate hash for arbitrary IPs
    h = abs(hash(ip_address))
    lat = ((h % 14000) / 100.0) - 70.0
    lon = (((h // 14000) % 36000) / 100.0) - 180.0
    return (round(lat, 4), round(lon, 4), f"Resolved IP {ip_address}")


def evaluate_login_telemetry(
    user_id: str,
    ip_address: str,
    user_agent: str,
    timestamp_str: str,
    failed_attempts: int
) -> Dict[str, Any]:
    """
    Computes mathematical ATO risk score and TreeSHAP attributions using
    the real trained Isolation Forest model.
    Blueprint Section 5.2 & 5.3.
    """
    curr_lat, curr_lon, curr_loc = resolve_ip_coordinates(ip_address)
    
    # Parse timestamp
    try:
        curr_time = float(timestamp_str)
    except Exception:
        try:
            curr_time = datetime.fromisoformat(timestamp_str).timestamp()
        except Exception:
            curr_time = datetime.utcnow().timestamp()

    # Retrieve or initialize user baseline
    user_hist = USER_AUTH_HISTORY.get(user_id, USER_AUTH_HISTORY["default"])
    prev_lat = user_hist["last_lat"]
    prev_lon = user_hist["last_lon"]
    prev_time = user_hist["last_timestamp"]
    known_ua = user_hist["known_user_agent"]

    # 1. Great-circle geographical displacement
    dist_km = haversine_distance_km(prev_lat, prev_lon, curr_lat, curr_lon)

    # 2. Velocity calculation
    elapsed_hours = max((curr_time - prev_time) / 3600.0, 0.05)
    velocity_kmh = round(dist_km / elapsed_hours, 2)

    # 3. Time of day deviation
    dt = datetime.utcfromtimestamp(curr_time)
    time_dev = round(math.sin(dt.hour * math.pi / 12.0), 3)

    # 4. User-Agent match
    ua_match = 1.0 if user_agent == known_ua else 0.0

    # 5. Consecutive failed attempts
    consecutive_failures = int(failed_attempts)

    # Construct exact 5-feature vector
    X_vector = np.array([[
        float(dist_km),
        float(velocity_kmh),
        float(time_dev),
        float(ua_match),
        float(consecutive_failures)
    ]])

    # Calculate real Isolation Forest Anomaly Score
    # raw score from decision_function: negative is anomalous, positive is normal
    raw_decision = float(iso_forest.decision_function(X_vector)[0])
    # Normalize to 0.0 - 1.0 risk score
    # Score < 0 is anomaly; map: 0.2 -> 0.0, -0.3 -> 1.0
    anomaly_score = round(min(max(0.5 - (raw_decision * 1.8), 0.0), 1.0), 4)

    # Compute exact SHAP values
    shap_vals = shap_explainer.shap_values(X_vector)[0]
    
    feature_names = [
        "Geographic Distance (km)",
        "Geographic Velocity (km/h)",
        "Time Deviation",
        "Device Match",
        "Failed Attempts"
    ]

    shap_attributions = {
        feature_names[i]: round(float(shap_vals[i]), 4)
        for i in range(len(feature_names))
    }

    # Impossible Travel heuristic (> 800 km/h commercial airliner threshold)
    impossible_travel = bool(velocity_kmh > 800.0 and dist_km > 500.0)
    if impossible_travel:
        anomaly_score = max(anomaly_score, 0.88)

    # 6. External Threat Intelligence (AbuseIPDB & HaveIBeenPwned)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    abuse_confidence = 0.0
    if abuse_key and abuse_key != "your_abuseipdb_api_key_here":
        try:
            import requests
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            abuse_headers = {"Key": abuse_key, "Accept": "application/json"}
            abuse_params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
            resp = requests.get(abuse_url, headers=abuse_headers, params=abuse_params, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_confidence = float(data.get("abuseConfidenceScore", 0)) / 100.0
        except Exception as e:
            print(f"AbuseIPDB query failed: {e}")

    # Elevate anomaly score if IP is flagged by AbuseIPDB
    if abuse_confidence > 0.2:
        anomaly_score = min(max(anomaly_score, abuse_confidence), 1.0)
        shap_attributions["AbuseIPDB Threat Score"] = round(abuse_confidence, 4)

    # Determine 5-tier risk
    if anomaly_score > 0.85:
        tier = "Critical"
        action = "Revoke Active Session & Block IP"
    elif anomaly_score > 0.65:
        tier = "High"
        action = "Step-Up Multi-Factor Authentication"
    elif anomaly_score > 0.40:
        tier = "Medium"
        action = "Alert User & Admin SOC"
    elif anomaly_score > 0.20:
        tier = "Low"
        action = "Log Event"
    else:
        tier = "Safe"
        action = "Allow Authentication"

    xai_explanation = (
        f"Isolation Forest computed anomaly score of {anomaly_score:.2f} ({tier} Risk). "
        f"User moved {dist_km:.1f} km at {velocity_kmh:.1f} km/h from {curr_loc} "
        f"with {consecutive_failures} failed attempts. "
    )
    if abuse_confidence > 0.0:
        xai_explanation += f"AbuseIPDB flagged host IP with {abuse_confidence*100:.0f}% confidence. "
    xai_explanation += (
        f"Primary SHAP attribution: Velocity ({shap_attributions['Geographic Velocity (km/h)']}), "
        f"Failed Attempts ({shap_attributions['Failed Attempts']})."
    )

    # Update in-memory history
    USER_AUTH_HISTORY[user_id] = {
        "last_ip": ip_address,
        "last_lat": curr_lat,
        "last_lon": curr_lon,
        "last_timestamp": curr_time,
        "known_user_agent": user_agent if ua_match == 1.0 else known_ua
    }

    return {
        "anomaly_score": anomaly_score,
        "risk_tier": tier,
        "shap_attributions": shap_attributions,
        "impossible_travel": impossible_travel,
        "action": action,
        "xai_explanation": xai_explanation,
        "telemetry_details": {
            "distance_km": dist_km,
            "velocity_kmh": velocity_kmh,
            "location": curr_loc
        }
    }
