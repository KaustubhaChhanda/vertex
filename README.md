# Vertex: AI-Powered Cyber Threat Intelligence Platform

## Overview
Vertex is an autonomous, multimodal cyber threat intelligence and active response platform built for modern enterprise Security Operations Centers (SOCs). It unifies perimeter defense, forensics, and automated incident response into a single cognitive immune system.

## Core Features
1. Unified Platform: Intercepts web threats, deepfakes, and login anomalies.
2. Browser Extension: Provides real-time scanning for links and emails without adding latency.
3. Multimodal Triage Portal: On-demand forensic analysis for audio, video, text, and QR codes.
4. SOC Dashboard: Centralized interactive incident response and threat visualization.
5. Explainable AI (XAI): Generates human-readable evidence using mathematical SHAP attributions instead of opaque risk scores.
6. Automated Correlation: Uses graph databases to map scattered threats to MITRE ATT&CK profiles.

## Technical Architecture
- Backend: FastAPI handles asynchronous routing and orchestrates the hybrid intelligence pipeline.
- Frontend: Next.js and Tailwind CSS power the SOC dashboard and triage portal.
- Machine Learning (Local): XGBoost for zero-latency URL classification and Isolation Forest for account takeover (ATO) anomaly detection.
- Deep Learning (Multimedia): Local PyTorch dual-stream neural networks for inspecting visual artifacts and acoustic anomalies in deepfakes.
- Semantic Analysis (Cloud): Asynchronous integration with Groq and Gemini LLMs for advanced phishing intent detection.
- Databases: PostgreSQL acts as the relational single source of truth for logs and user profiles. Neo4j acts as the graph database to project and correlate complex threat campaigns.
- Deployment: The architecture is containerized using Docker for scalable and isolated microservices deployment.

## Installation and Setup
Ensure that you have Docker, Python 3.11+, and Node.js installed on your system.

1. Clone this repository to your local machine.
2. Install the backend dependencies using pip inside your backend directory or virtual environment.
3. Install the frontend dependencies using npm inside the frontend directory.
4. Configure the required environment variables for database connections and API keys (Groq, Gemini, Neo4j, PostgreSQL).
5. Start the backend services using the FastAPI server.
6. Start the frontend application using the Next.js development server.

## Notice Regarding Models and Assets
Large machine learning models, neural network weights, and datasets have been intentionally excluded from this repository via the .gitignore file due to file size constraints and version control best practices.
