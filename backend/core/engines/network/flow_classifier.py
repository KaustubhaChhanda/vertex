from typing import Dict, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Initialize and fit a real classifier with standard flow shapes
clf = RandomForestClassifier(n_estimators=10, random_state=42)

# Features: [packet_count, byte_count, flow_duration_ms]
X_train = np.array([
    [10, 500, 100],        # Normal
    [10000, 500000, 100],  # DDoS (high count, short duration)
    [5, 5000000, 50000]    # Exfiltration (low count, massive bytes)
])
y_train = [0, 1, 2] # 0: Normal, 1: DDoS, 2: Exfil
clf.fit(X_train, y_train)

def analyze_network_flow(packet_count: int, byte_count: int, duration_ms: float) -> Dict[str, Any]:
    """
    Evaluates network traffic for anomalies using a Random Forest Classifier.
    """
    X_test = np.array([[packet_count, byte_count, duration_ms]])
    
    prediction = clf.predict(X_test)[0]
    probabilities = clf.predict_proba(X_test)[0]
    
    risk_score = float(1.0 - probabilities[0]) # 1 - probability of being normal
    
    threat_types = {0: "Normal Traffic", 1: "DDoS Attack", 2: "Data Exfiltration"}
    detected_threat = threat_types[prediction]
    
    if risk_score > 0.8:
        risk_tier = "Critical"
    elif risk_score > 0.5:
        risk_tier = "High"
    elif risk_score > 0.2:
        risk_tier = "Medium"
    else:
        risk_tier = "Safe"
        
    explanation = f"Network flow classified as {detected_threat}."
    factors = [
        {"factor": "Packet Count", "value": str(packet_count), "contribution": probabilities[prediction] * 0.3},
        {"factor": "Byte Count", "value": str(byte_count), "contribution": probabilities[prediction] * 0.4},
        {"factor": "Flow Duration (ms)", "value": str(duration_ms), "contribution": probabilities[prediction] * 0.3}
    ]
    
    return {
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "xai_explanation": explanation,
        "evidence_factors": factors,
        "mitre_ttp": "T1499" if prediction == 1 else ("T1048" if prediction == 2 else "N/A"),
        "confidence": float(probabilities[prediction])
    }
