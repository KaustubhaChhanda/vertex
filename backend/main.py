from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import phishing, ato, identity, deepfake, network, url, simulate, admin, auth

app = FastAPI(
    title="Vertex Threat Intelligence API",
    description="Backend API for the Vertex Cyber Defense System (Conforming to Blueprint & Vertex.txt)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "engines": {
            "xgboost_url": "active",
            "opencv_qr_vision": "active",
            "siglip_deepfake_visual": "active",
            "wav2vec2_deepfake_audio": "active",
            "isolation_forest_ato": "active",
            "shap_explainer": "active"
        }
    }

# 1. Blueprint & Vertex.txt Specific Routes
# POST /api/v1/scan/url
app.include_router(url.router, prefix="/api/v1/scan/url", tags=["Phishing & Malicious URLs"])
# POST /api/v1/scan/qr (Scenario 1.c QR-based phishing)
app.include_router(url.router, prefix="/api/v1/scan", tags=["Phishing & Malicious URLs"])
# POST /api/v1/scan/email, POST /api/v1/scan/message (Scenario 1.a & 1.b)
app.include_router(phishing.router, prefix="/api/v1/scan", tags=["Phishing & Messages"])
# POST /api/v1/scan/media (Scenario 2 Deepfake Detection - Visual, Audio, Video)
app.include_router(deepfake.router, prefix="/api/v1/scan/media", tags=["Deepfake Media"])
# POST /api/v1/scan/login (Scenario 3 ATO Anomaly Detection)
app.include_router(ato.router, prefix="/api/v1/scan/login", tags=["Account Takeover"])
# POST /api/v1/simulate/login (Scenario 3 Simulation Tool)
app.include_router(simulate.router, prefix="/api/v1/simulate/login", tags=["Simulation Tools"])
# GET /api/v1/admin/threats & GET /api/v1/admin/dashboard (Central SOC Operations)
app.include_router(admin.router, prefix="/api/v1/admin/threats", tags=["Admin SOC Dashboard"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin SOC Dashboard"])
# POST /api/v1/auth/login
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])

# 2. Additional Specialized Category Routes
app.include_router(ato.router, prefix="/api/v1/scan/ato", tags=["Account Takeover"])
app.include_router(deepfake.router, prefix="/api/v1/scan/deepfake", tags=["Deepfake Media"])
app.include_router(identity.router, prefix="/api/v1/scan/identity", tags=["Digital Impersonation"])
app.include_router(network.router, prefix="/api/v1/scan/network", tags=["Network Anomalies"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
