import re
import time
import uuid
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="SecureIT Safe Spaces SDK (Enterprise ML Engine)",
    description="Localized NLP Threat Classification & DLP Engine for Nigerian EdTech",
    version="2.0.0"
)

ADMIN_ALERT_QUEUE: List[Dict] = []

class AuditRequest(BaseModel):
    text: str
    student_id: str = "STU-NG-8841"
    platform_id: str = "lagos-edtech-portal"
    sensitivity: str = "strict"

class LocalizedMLModerator:
    def __init__(self):
        # Labels: 0 = Safe, 1 = Cyber-Extortion, 2 = Online Grooming, 3 = Cyberbullying
        self.training_data = [
            # Safe Educational & Nigerian Student Chat (Label 0)
            ("Please send me the mathematics assignment notes for tomorrow", 0),
            ("Abeg help me check when WAEC physics exam is starting", 0),
            ("Good morning sir, I have submitted my biology project on the portal", 0),
            ("Can we form a study group for JAMB preparation this weekend?", 0),
            ("No wahala, I will share the PDF textbook with the class group", 0),
            ("Thank you for helping me understand the algebra equation", 0),
            ("Our school portal is working very fast today", 0),
            ("Make we read together for library after assembly", 0),
            
            # Cyber-Extortion & Blackmail (Label 1)
            ("Pay 20k naira into my account before tonight else I go cast your secret", 1),
            ("Drop your private photo now or I will post your face on every group chat", 1),
            ("If you no transfer money sharp sharp I go expose everything you did", 1),
            ("Send your picha right now or everybody in class go see am", 1),
            ("I have your screenshots, send airtime or I ruin your reputation", 1),
            ("Better send the money today before I leak your chat to the principal", 1),

            # Online Grooming & Secrecy Isolation (Label 2)
            ("Do not tell your parents or teacher that we are chatting privately here", 2),
            ("No tell your mummy anything, let us meet outside the school gate alone", 2),
            ("You are very mature for your age, keep this secret between just us", 2),
            ("Send me your house address so I can pick you up after school without anyone knowing", 2),
            ("Delete this chat after reading, nobody must know we talk", 2),
            ("I will buy you a new phone if you keep our meeting secret from your dad", 2),

            # Cyberbullying & Severe Harassment (Label 3)
            ("You are a complete mumu and ode, nobody in this school likes you", 3),
            ("You are too dull to be in this class, stop coming to school", 3),
            ("Everybody hates you, you are completely useless", 3),
            ("We go beat you seriously after school close today", 3),
            ("Nobody wants you in our study group, get out", 3),
            ("We go deal with you if you show your face tomorrow", 3)
        ]

        texts = [self.normalize_text(item[0]) for item in self.training_data]
        labels = [item[1] for item in self.training_data]

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", max_features=5000)
        X = self.vectorizer.fit_transform(texts)

        self.classifier = LogisticRegression(C=2.0, max_iter=1000)
        self.classifier.fit(X, labels)

        self.phone_pattern = r"(\+?234[\s\-]*|0)(70|80|81|90|91)[\s\-]*\d{4}[\s\-]*\d{4}"

    def normalize_text(self, text: str) -> str:
        cleaned = text.lower()
        evasion_map = {'3': 'e', '4': 'a', '@': 'a', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's'}
        for char, replacement in evasion_map.items():
            cleaned = cleaned.replace(char, replacement)
        cleaned = re.sub(r'(?<=\w)[\.\-\_\*]+(?=\w)', '', cleaned)
        return cleaned

    def evaluate(self, raw_text: str, sensitivity: str = "strict") -> dict:
        start_time = time.perf_counter()
        normalized = self.normalize_text(raw_text)

        vectorized = self.vectorizer.transform([normalized])
        probs = self.classifier.predict_proba(vectorized)[0]

        scores = {
            "safe": round(float(probs[0]), 4),
            "cyber_extortion": round(float(probs[1]), 4),
            "online_grooming": round(float(probs[2]), 4),
            "cyberbullying": round(float(probs[3]), 4)
        }

        sanitized_text = raw_text
        pii_detected = False
        if re.search(self.phone_pattern, sanitized_text):
            pii_detected = True
            sanitized_text = re.sub(self.phone_pattern, "[REDACTED_NG_PHONE]", sanitized_text)

        scores["pii_leakage"] = 1.0 if pii_detected else 0.0

        thresholds = {"strict": 0.35, "moderate": 0.50, "lenient": 0.70}
        cutoff = thresholds.get(sensitivity.lower(), 0.35)

        flagged_categories = []
        if scores["cyber_extortion"] >= cutoff:
            flagged_categories.append("CYBER_EXTORTION")
        if scores["online_grooming"] >= cutoff:
            flagged_categories.append("ONLINE_GROOMING")
        if scores["cyberbullying"] >= cutoff:
            flagged_categories.append("CYBERBULLYING")
        if pii_detected:
            flagged_categories.append("PII_DATA_LEAK")

        max_threat_score = max(
            scores["cyber_extortion"],
            scores["online_grooming"],
            scores["cyberbullying"],
            scores["pii_leakage"]
        )

        is_flagged = len(flagged_categories) > 0
        action = "BLOCK_AND_ESCALATE" if is_flagged else "ALLOW"
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "flagged": is_flagged,
            "action": action,
            "max_risk_score": round(max_threat_score, 4),
            "categories": flagged_categories,
            "category_scores": scores,
            "sanitized_text": sanitized_text,
            "telemetry": {
                "latency_ms": latency_ms,
                "model_architecture": "TFIDF-CharNGram-LogReg-v2",
                "sensitivity_mode": sensitivity
            }
        }

ml_engine = LocalizedMLModerator()

@app.post("/api/v2/moderate")
async def moderate_endpoint(payload: AuditRequest):
    result = ml_engine.evaluate(payload.text, payload.sensitivity)
    if result["flagged"]:
        ADMIN_ALERT_QUEUE.insert(0, {
            "alert_id": f"ALT-{str(uuid.uuid4())[:6].upper()}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "student_id": payload.student_id,
            "platform_id": payload.platform_id,
            "original_text": payload.text,
            "sanitized_text": result["sanitized_text"],
            "categories": result["categories"],
            "risk_score": result["max_risk_score"],
            "status": "PENDING_REVIEW"
        })
    return result

@app.get("/api/v2/alerts")
async def get_admin_alerts():
    return {"total_alerts": len(ADMIN_ALERT_QUEUE), "alerts": ADMIN_ALERT_QUEUE}

@app.post("/api/v2/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    for alert in ADMIN_ALERT_QUEUE:
        if alert["alert_id"] == alert_id:
            alert["status"] = "RESOLVED_BY_ADMIN"
            return {"message": "Alert marked resolved", "alert": alert}
    raise HTTPException(status_code=404, detail="Alert ID not found")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    html_file = Path("index.html")
    return html_file.read_text(encoding="utf-8")
