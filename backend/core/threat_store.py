import os
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)
STORE_FILE = os.path.join(DATA_DIR, "threat_store.json")

class ThreatStore:
    """
    Centralized, thread-safe, persistent Threat Ledger & Blocklist for Vertex SOC.
    Every single analyzed event (URL, email, QR, media, login ATO) is persisted here.
    """
    _lock = threading.Lock()

    @classmethod
    def _load_data(cls) -> Dict[str, Any]:
        if not os.path.exists(STORE_FILE):
            # No mock data allowed
            initial_data = {
                "blocklist": [],
                "incidents": []
            }
            with open(STORE_FILE, "w", encoding="utf-8") as f:
                json.dump(initial_data, f, indent=2)
            return initial_data

        try:
            with open(STORE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"blocklist": [], "incidents": []}

    @classmethod
    def _save_data(cls, data: Dict[str, Any]):
        with open(STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def record_event(
        cls,
        threat_type: str,
        target: str,
        risk_tier: str,
        risk_score: float,
        xai_explanation: str,
        mitre_ttp: str = "T1566",
        recommended_response: str = "Log Event",
        evidence_factors: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        with cls._lock:
            data = cls._load_data()
            new_id = f"INC-{1000 + len(data['incidents']) + 1}"
            
            action_taken = recommended_response
            status = "Flagged"
            if risk_tier in ["High", "Critical"]:
                status = "Active Threat"
            elif risk_tier == "Safe":
                status = "Resolved / Safe"

            incident = {
                "id": new_id,
                "type": threat_type,
                "target": target,
                "risk_tier": risk_tier,
                "risk_score": round(float(risk_score), 4),
                "mitre_ttp": mitre_ttp,
                "action_taken": action_taken,
                "status": status,
                "xai_explanation": xai_explanation,
                "recommended_response": recommended_response,
                "evidence_factors": evidence_factors or [],
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            data["incidents"].insert(0, incident) # Insert most recent first
            cls._save_data(data)
            return incident

    @classmethod
    def get_all_incidents(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            data = cls._load_data()
            return data.get("incidents", [])

    @classmethod
    def get_blocklist(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            data = cls._load_data()
            return data.get("blocklist", [])

    @classmethod
    def add_to_blocklist(cls, target: str, entry_type: str = "domain", reason: str = "Manual SOC Analyst Block") -> Dict[str, Any]:
        with cls._lock:
            data = cls._load_data()
            # Avoid duplicates
            for b in data.get("blocklist", []):
                if b["target"].lower() == target.lower():
                    return b

            entry = {
                "target": target.lower(),
                "type": entry_type,
                "reason": reason,
                "added_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            data["blocklist"].insert(0, entry)
            cls._save_data(data)
            return entry

    @classmethod
    def is_blocked(cls, url_or_domain: str) -> bool:
        with cls._lock:
            data = cls._load_data()
            lower = url_or_domain.lower()
            for b in data.get("blocklist", []):
                target = b["target"].lower()
                if target in lower:
                    return True
            return False

    @classmethod
    def update_incident_status(cls, incident_id: str, new_status: str, action_taken: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with cls._lock:
            data = cls._load_data()
            for inc in data.get("incidents", []):
                if inc["id"] == incident_id:
                    inc["status"] = new_status
                    if action_taken:
                        inc["action_taken"] = action_taken
                    cls._save_data(data)
                    return inc
            return None

    @classmethod
    def compute_dashboard_metrics(cls) -> Dict[str, Any]:
        with cls._lock:
            data = cls._load_data()
            incidents = data.get("incidents", [])

            total_analyzed = len(incidents)
            threats_detected = sum(1 for i in incidents if i["risk_tier"] in ["Medium", "High", "Critical"])

            category_counts = {
                "Phishing & Malicious URLs": 0,
                "Deepfakes & Synthetic Media": 0,
                "Account Takeover (ATO)": 0,
                "Digital Impersonation": 0
            }
            risk_dist = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}

            phishing_count = 0
            deepfake_count = 0
            ato_count = 0

            for i in incidents:
                tier = i.get("risk_tier", "Low")
                if tier in risk_dist:
                    risk_dist[tier] += 1

                t_type = i.get("type", "").lower()
                if "phish" in t_type or "url" in t_type:
                    category_counts["Phishing & Malicious URLs"] += 1
                    if tier in ["Medium", "High", "Critical"]:
                        phishing_count += 1
                elif "deepfake" in t_type or "media" in t_type:
                    category_counts["Deepfakes & Synthetic Media"] += 1
                    if tier in ["Medium", "High", "Critical"]:
                        deepfake_count += 1
                elif "ato" in t_type or "takeover" in t_type or "login" in t_type:
                    category_counts["Account Takeover (ATO)"] += 1
                    if tier in ["Medium", "High", "Critical"]:
                        ato_count += 1
                else:
                    category_counts["Digital Impersonation"] += 1

            return {
                "total_events_analyzed": total_analyzed,
                "threats_detected": threats_detected,
                "threat_categories": category_counts,
                "risk_level_distribution": risk_dist,
                "phishing_attempts": phishing_count,
                "suspected_deepfakes": deepfake_count,
                "account_takeover_attempts": ato_count,
                "blocklist_count": len(data.get("blocklist", [])),
                "recommended_responses": [
                    {"action": "Block URLs", "triggered": sum(1 for i in incidents if "block" in i.get("action_taken", "").lower()), "status": "Enforced"},
                    {"action": "Quarantine Emails", "triggered": sum(1 for i in incidents if "quarantine" in i.get("action_taken", "").lower()), "status": "Enforced"},
                    {"action": "Block IP/Device", "triggered": sum(1 for i in incidents if "ip" in i.get("action_taken", "").lower()), "status": "Enforced"},
                    {"action": "Flag Multimedia for Verification", "triggered": sum(1 for i in incidents if "flag" in i.get("action_taken", "").lower()), "status": "Pending Review"},
                    {"action": "Notify Admin / SOC Escalation", "triggered": threats_detected, "status": "Dispatched"}
                ]
            }
