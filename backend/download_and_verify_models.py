import os
import sys
import socket

# Force IPv4 in socket to avoid Windows IPv6 getaddrinfo failures
old_getaddrinfo = socket.getaddrinfo
def ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return old_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = ipv4_getaddrinfo

import math
import json
import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
import shap

# Set local cache and model directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
MODELS_DIR = os.path.join(ROOT_DIR, "data", "models")
HF_CACHE_DIR = os.path.join(MODELS_DIR, "huggingface")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(HF_CACHE_DIR, exist_ok=True)

os.environ["HF_HOME"] = HF_CACHE_DIR
os.environ["TRANSFORMERS_CACHE"] = HF_CACHE_DIR

print("==================================================================")
print("VERTEX REAL ML MODELS DOWNLOADER & INITIALIZATION")
print("==================================================================")
print(f"Target Models Directory: {MODELS_DIR}")
print(f"Hugging Face Cache: {HF_CACHE_DIR}")

# -------------------------------------------------------------
# 1. Download Hugging Face Visual Deepfake Model
# Model: prithivMLmods/AI-vs-Deepfake-vs-Real-v2.0
# -------------------------------------------------------------
print("\n[1/4] Downloading Visual Deepfake Model: prithivMLmods/AI-vs-Deepfake-vs-Real-v2.0 ...")
try:
    from huggingface_hub import snapshot_download
    from transformers import AutoImageProcessor, AutoModelForImageClassification, pipeline
    from PIL import Image

    visual_local_path = os.path.join(MODELS_DIR, "visual_deepfake")
    print(f"Downloading repository snapshot to {visual_local_path} ...")
    snapshot_download(
        repo_id="prithivMLmods/AI-vs-Deepfake-vs-Real-v2.0",
        local_dir=visual_local_path,
        local_dir_use_symlinks=False,
        resume_download=True
    )
    print("Downloaded visual deepfake snapshot successfully!")

    print("Testing visual model pipeline instantiation...")
    visual_pipe = pipeline("image-classification", model=visual_local_path)
    
    # Test inference with synthetic test image (224x224 RGB)
    test_img = Image.new("RGB", (224, 224), color=(128, 128, 128))
    v_preds = visual_pipe(test_img)
    print(f"Visual Model Test Inference Result: {v_preds}")
    print("[SUCCESS] Visual Deepfake Model is verified and ready on disk.")
except Exception as e:
    print(f"[ERROR downloading visual model]: {e}")
    sys.exit(1)

# -------------------------------------------------------------
# 2. Download Hugging Face Audio Deepfake Model
# Model: garystafford/wav2vec2-deepfake-voice-detector
# -------------------------------------------------------------
print("\n[2/4] Downloading Audio Deepfake Model: garystafford/wav2vec2-deepfake-voice-detector ...")
try:
    audio_local_path = os.path.join(MODELS_DIR, "audio_deepfake")
    print(f"Downloading repository snapshot to {audio_local_path} ...")
    snapshot_download(
        repo_id="garystafford/wav2vec2-deepfake-voice-detector",
        local_dir=audio_local_path,
        local_dir_use_symlinks=False,
        resume_download=True
    )
    print("Downloaded audio deepfake snapshot successfully!")

    print("Testing audio model pipeline instantiation...")
    audio_pipe = pipeline("audio-classification", model=audio_local_path)
    
    # Test inference with 1-second synthetic 16kHz audio array
    synthetic_audio = np.sin(2 * np.pi * 440 * np.linspace(0, 1, 16000)).astype(np.float32)
    a_preds = audio_pipe(synthetic_audio)
    print(f"Audio Model Test Inference Result: {a_preds}")
    print("[SUCCESS] Audio Deepfake Model is verified and ready on disk.")
except Exception as e:
    print(f"[ERROR downloading audio model]: {e}")
    sys.exit(1)

# -------------------------------------------------------------
# 3. Train & Export Real XGBoost URL Classifier
# Features: [url_length, domain_length, entropy, digit_ratio, num_subdomains, is_https, has_ip, has_suspicious_word]
# -------------------------------------------------------------
print("\n[3/4] Training and Exporting XGBoost URL Classifier ...")
try:
    np.random.seed(42)
    # Synthetic realistic feature generation for training
    # Class 0: Legitimate (lower entropy, no suspicious keywords, standard length, https=1)
    # Class 1: Phishing (high entropy, suspicious keywords, ip presence, long deceptive domains)
    
    # 500 benign samples
    benign_len = np.random.normal(25, 8, 500).clip(10, 60)
    benign_dom_len = np.random.normal(12, 4, 500).clip(5, 25)
    benign_entropy = np.random.normal(2.8, 0.4, 500).clip(1.5, 3.8)
    benign_digits = np.random.uniform(0.0, 0.05, 500)
    benign_subdomains = np.random.choice([1, 2], size=500, p=[0.8, 0.2])
    benign_https = np.random.choice([0, 1], size=500, p=[0.05, 0.95])
    benign_ip = np.zeros(500)
    benign_suspicious = np.random.choice([0, 1], size=500, p=[0.97, 0.03])
    X_benign = np.column_stack([benign_len, benign_dom_len, benign_entropy, benign_digits, benign_subdomains, benign_https, benign_ip, benign_suspicious])
    y_benign = np.zeros(500)

    # 500 phishing samples
    phish_len = np.random.normal(65, 20, 500).clip(30, 150)
    phish_dom_len = np.random.normal(30, 10, 500).clip(15, 60)
    phish_entropy = np.random.normal(4.2, 0.5, 500).clip(3.5, 5.5)
    phish_digits = np.random.uniform(0.1, 0.35, 500)
    phish_subdomains = np.random.choice([2, 3, 4, 5], size=500, p=[0.3, 0.4, 0.2, 0.1])
    phish_https = np.random.choice([0, 1], size=500, p=[0.4, 0.6])
    phish_ip = np.random.choice([0, 1], size=500, p=[0.75, 0.25])
    phish_suspicious = np.random.choice([0, 1], size=500, p=[0.15, 0.85])
    X_phish = np.column_stack([phish_len, phish_dom_len, phish_entropy, phish_digits, phish_subdomains, phish_https, phish_ip, phish_suspicious])
    y_phish = np.ones(500)

    X_train = np.vstack([X_benign, X_phish])
    y_train = np.concatenate([y_benign, y_phish])

    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss"
    )
    xgb_model.fit(X_train, y_train)

    xgb_path = os.path.join(MODELS_DIR, "url_xgboost.json")
    xgb_model.save_model(xgb_path)
    print(f"XGBoost model saved to: {xgb_path} ({os.path.getsize(xgb_path)} bytes)")

    # Test sample inference
    test_phish_features = np.array([[85, 38, 4.5, 0.22, 4, 0, 0, 1]])
    prob = float(xgb_model.predict_proba(test_phish_features)[0][1])
    print(f"XGBoost Test Inference (Phishing Sample Probability): {prob:.4f}")
    print("[SUCCESS] Real XGBoost URL Classifier trained and saved.")
except Exception as e:
    print(f"[ERROR training XGBoost]: {e}")
    sys.exit(1)

# -------------------------------------------------------------
# 4. Fit & Export Isolation Forest ATO Model & SHAP Explainer
# Features: [distance_km, velocity_kmh, time_dev, user_agent_match, failed_attempts]
# -------------------------------------------------------------
print("\n[4/4] Fitting and Exporting Isolation Forest ATO Model ...")
try:
    # 1000 normal login events baseline
    norm_dist = np.random.exponential(15, 1000).clip(0, 100)
    norm_vel = np.random.exponential(10, 1000).clip(0, 60)
    norm_time = np.random.normal(0, 0.2, 1000).clip(-1, 1)
    norm_ua = np.ones(1000)
    norm_failed = np.random.choice([0, 1], size=1000, p=[0.92, 0.08])
    X_norm = np.column_stack([norm_dist, norm_vel, norm_time, norm_ua, norm_failed])

    # 50 anomalous events
    anom_dist = np.random.uniform(500, 6000, 50)
    anom_vel = np.random.uniform(400, 3000, 50)
    anom_time = np.random.uniform(-1, 1, 50)
    anom_ua = np.zeros(50)
    anom_failed = np.random.choice([3, 5, 8, 12], size=50)
    X_anom = np.column_stack([anom_dist, anom_vel, anom_time, anom_ua, anom_failed])

    X_all = np.vstack([X_norm, X_anom])

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    iso_forest.fit(X_all)

    iso_path = os.path.join(MODELS_DIR, "isolation_forest.joblib")
    joblib.dump(iso_forest, iso_path)
    print(f"Isolation Forest model saved to: {iso_path} ({os.path.getsize(iso_path)} bytes)")

    # SHAP Explainer
    explainer = shap.TreeExplainer(iso_forest)
    explainer_path = os.path.join(MODELS_DIR, "shap_explainer.joblib")
    joblib.dump(explainer, explainer_path)
    print(f"SHAP Explainer saved to: {explainer_path} ({os.path.getsize(explainer_path)} bytes)")

    # Test ATO inference
    test_ato_vector = np.array([[5500.0, 1800.0, 0.8, 0.0, 5]])
    raw_score = float(-iso_forest.score_samples(test_ato_vector)[0])
    shap_vals = explainer.shap_values(test_ato_vector)[0]
    print(f"Isolation Forest Test Anomaly Score: {raw_score:.4f}")
    print(f"SHAP Values for [dist, vel, time, ua, failed]: {shap_vals}")
    print("[SUCCESS] Real Isolation Forest & SHAP Explainer fitted and saved.")
except Exception as e:
    print(f"[ERROR fitting Isolation Forest]: {e}")
    sys.exit(1)

print("\n==================================================================")
print("ALL ML MODELS DOWNLOADED, COMPILED, TRAINED AND PHYSICALLY ON DISK!")
print("==================================================================")
for root, dirs, files in os.walk(MODELS_DIR):
    total_size = sum(os.path.getsize(os.path.join(root, name)) for name in files)
    if files:
        print(f"-> {root}: {len(files)} files, {total_size / (1024*1024):.2f} MB")
