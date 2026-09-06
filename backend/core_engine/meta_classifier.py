import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trained_models", "meta_model.pkl")

class EnsembleMetaClassifier:
    """
    Stage 6: The Final Ensemble ML Model.
    Takes the extracted features from NLP, Link Analysis, and Sandbox,
    and runs them through a trained Random Forest to get the Final Verdict.
    """
    def __init__(self):
        self.model = None
        self._load_or_mock_model()

    def _load_or_mock_model(self):
        """
        Loads the trained RandomForest model. If it doesn't exist (e.g. fresh clone),
        it trains a lightweight mock model instantly so the MVP works out-of-the-box.
        """
        if os.path.exists(MODEL_PATH):
            print("🧠 [META-CLASSIFIER] Loading pre-trained Ensemble Model...")
            self.model = joblib.load(MODEL_PATH)
        else:
            print("⚠️ [META-CLASSIFIER] Model file not found. Training a fresh Sandbox-Ensemble model on the fly...")
            self._train_mock_model()

    def _train_mock_model(self):
        """
        Trains the Scikit-Learn RandomForestClassifier using a dataset of features:
        [nlp_score, typosquat_risk, sandbox_threat_score, mimics_login]
        """
        # Feature Columns:
        # 1. NLP Text Risk (0-100)
        # 2. Typosquat Risk (0 or 1)
        # 3. Sandbox Threat Score (0-100)
        # 4. Has Password Field (0 or 1)
        
        # X = Training Data, y = Labels (0: Legitimate, 1: Phishing)
        X_train = np.array([
            [0, 0, 0, 0],       # Perfectly clean email
            [10, 0, 0, 0],      # Slightly weird text, but clean links
            [90, 0, 0, 0],      # High BEC intent text, no bad links
            [95, 1, 100, 1],    # Textbook Phishing (Bad Text + Typosquat + Sandbox flag + Fake Login)
            [20, 1, 80, 0],     # Clean text, but link is typosquatted and flagged by sandbox
            [5, 0, 95, 1],      # Clean text, but link is a stealthy zero-day malware download
            [0, 1, 60, 0],      # Typosquatted link that is dead/unresolvable in DNS (Suspicious/Phishing)
            [0, 1, 0, 0],       # Typosquatted domain (Suspicious)
            [0, 0, 60, 0],      # Dead/unreachable domain (Suspicious)
        ])
        
        y_train = np.array([0, 0, 1, 1, 1, 1, 1, 1, 1])
        
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Save it for future runs
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        print("✅ [META-CLASSIFIER] Ensemble Model trained and saved successfully.")

    def predict_verdict(
        self, 
        nlp_score: float, 
        typosquat_risk: int, 
        sandbox_threat: float, 
        has_password_field: int,
        external_form_action: int = 0,
        suspicious_exfiltration: int = 0,
        newly_registered_domain: int = 0,
        brand_impersonation: int = 0
    ) -> dict:
        """
        Runs the final prediction with multi-modal ensemble model & defense-in-depth guardrails.
        """
        # Prepare the feature vector exactly as the model expects it
        feature_vector = np.array([[nlp_score, typosquat_risk, sandbox_threat, has_password_field]])
        
        # Probabilities: [prob_legitimate, prob_phishing]
        probabilities = self.model.predict_proba(feature_vector)[0]
        # Threat score is the percentage probability of phishing (0 to 100)
        threat_score = probabilities[1] * 100 if len(probabilities) > 1 else (100.0 if self.model.predict(feature_vector)[0] == 1 else 0.0)
        
        # Hard security guardrails (Defense in Depth):
        if suspicious_exfiltration == 1 and has_password_field == 1:
            # Active credential theft targeting Telegram, Discord, or raw IP
            threat_score = 100.0
        elif brand_impersonation == 1 and (has_password_field == 1 or external_form_action == 1):
            # Impersonating high-value brand with password harvest or external form
            threat_score = max(threat_score, 95.0)
        elif brand_impersonation == 1:
            # Impersonating high-value brand on unauthorized domain
            threat_score = max(threat_score, 85.0)
        elif suspicious_exfiltration == 1:
            threat_score = max(threat_score, 85.0)
        elif external_form_action == 1 and has_password_field == 1:
            # Form submits sensitive credentials to external domain
            threat_score = max(threat_score, 90.0)
        elif newly_registered_domain == 1 and has_password_field == 1:
            # Zero-day domain asking for password
            threat_score = max(threat_score, 85.0)
        elif typosquat_risk == 1 and sandbox_threat >= 50:
            threat_score = max(threat_score, 75.0)
        elif newly_registered_domain == 1:
            threat_score = max(threat_score, 65.0)
        elif typosquat_risk == 1:
            threat_score = max(threat_score, 65.0)
        elif sandbox_threat >= 60 or has_password_field == 1:
            threat_score = max(threat_score, 70.0)
        elif sandbox_threat >= 50:
            threat_score = max(threat_score, 55.0)
            
        if threat_score >= 80:
            verdict = "CRITICAL FRAUD / PHISHING"
        elif threat_score >= 50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"
            
        return {
            "verdict": verdict,
            "threat_score": round(threat_score, 2),
            "confidence": round(threat_score, 2),
            "meta_features_used": {
                "nlp_score": nlp_score,
                "typosquat_risk": typosquat_risk,
                "sandbox_threat": sandbox_threat,
                "has_password_field": has_password_field,
                "external_form_action": external_form_action,
                "suspicious_exfiltration": suspicious_exfiltration,
                "newly_registered_domain": newly_registered_domain,
                "brand_impersonation": brand_impersonation
            }
        }
