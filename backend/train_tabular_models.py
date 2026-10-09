import os
import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
import shap

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "models"))
os.makedirs(MODELS_DIR, exist_ok=True)

# -------------------------------------------------------------
# 1. Real XGBoost URL Classifier Training
# Features: [url_length, domain_length, entropy, digit_ratio, num_subdomains, is_https, has_ip, has_suspicious_word]
# -------------------------------------------------------------
print("Training XGBoost URL Classifier...")
np.random.seed(42)

# Benign samples (1000)
benign_len = np.random.normal(25, 8, 1000).clip(10, 60)
benign_dom_len = np.random.normal(12, 4, 1000).clip(5, 25)
benign_entropy = np.random.normal(2.8, 0.4, 1000).clip(1.5, 3.8)
benign_digits = np.random.uniform(0.0, 0.05, 1000)
benign_subdomains = np.random.choice([1, 2], size=1000, p=[0.85, 0.15])
benign_https = np.random.choice([0, 1], size=1000, p=[0.05, 0.95])
benign_ip = np.zeros(1000)
benign_suspicious = np.random.choice([0, 1], size=1000, p=[0.98, 0.02])
X_benign = np.column_stack([benign_len, benign_dom_len, benign_entropy, benign_digits, benign_subdomains, benign_https, benign_ip, benign_suspicious])
y_benign = np.zeros(1000)

# Phishing samples (1000)
phish_len = np.random.normal(65, 20, 1000).clip(30, 150)
phish_dom_len = np.random.normal(30, 10, 1000).clip(15, 60)
phish_entropy = np.random.normal(4.2, 0.5, 1000).clip(3.5, 5.5)
phish_digits = np.random.uniform(0.1, 0.35, 1000)
phish_subdomains = np.random.choice([2, 3, 4, 5], size=1000, p=[0.3, 0.4, 0.2, 0.1])
phish_https = np.random.choice([0, 1], size=1000, p=[0.4, 0.6])
phish_ip = np.random.choice([0, 1], size=1000, p=[0.75, 0.25])
phish_suspicious = np.random.choice([0, 1], size=1000, p=[0.15, 0.85])
X_phish = np.column_stack([phish_len, phish_dom_len, phish_entropy, phish_digits, phish_subdomains, phish_https, phish_ip, phish_suspicious])
y_phish = np.ones(1000)

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

# -------------------------------------------------------------
# 2. Real Isolation Forest ATO Anomaly Model & SHAP
# Features: [distance_km, velocity_kmh, time_dev, user_agent_match, failed_attempts]
# -------------------------------------------------------------
print("Training Isolation Forest ATO Model...")
# 2000 normal login events baseline
norm_dist = np.random.exponential(15, 2000).clip(0, 100)
norm_vel = np.random.exponential(10, 2000).clip(0, 60)
norm_time = np.random.normal(0, 0.2, 2000).clip(-1, 1)
norm_ua = np.ones(2000)
norm_failed = np.random.choice([0, 1], size=2000, p=[0.92, 0.08])
X_norm = np.column_stack([norm_dist, norm_vel, norm_time, norm_ua, norm_failed])

# 100 anomalous events
anom_dist = np.random.uniform(500, 6000, 100)
anom_vel = np.random.uniform(400, 3000, 100)
anom_time = np.random.uniform(-1, 1, 100)
anom_ua = np.zeros(100)
anom_failed = np.random.choice([3, 5, 8, 12], size=100)
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

print("ALL TABULAR & ATO MODELS TRAINED & EXPORTED!")
