import os

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
except (ImportError, ModuleNotFoundError):
    joblib = None
    np = None
    RandomForestClassifier = None

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trained_models", "meta_model.pkl")

class EnsembleMetaClassifier:
    """
    Stage 6: The Final Ensemble ML Model.
    Takes the extracted features from NLP, Link Analysis, and Sandbox,
    and runs them through a trained Random Forest or smart weighted heuristic to get the Final Verdict.
    """
    def __init__(self):
        self.model = None
        self._load_or_mock_model()

    def _load_or_mock_model(self):
        """
        Loads the trained RandomForest model. If it doesn't exist or sklearn is not installed,
        falls back cleanly so the platform works 100% reliably out-of-the-box.
        """
        if joblib and RandomForestClassifier and os.path.exists(MODEL_PATH):
            try:
                print("🧠 [META-CLASSIFIER] Loading pre-trained Ensemble Model...")
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"⚠️ [META-CLASSIFIER] Could not load model ({e}). Training fresh...")
                self._train_mock_model()
        elif joblib and RandomForestClassifier:
            print("⚠️ [META-CLASSIFIER] Model file not found. Training a fresh Sandbox-Ensemble model on the fly...")
            self._train_mock_model()
        else:
            print("ℹ️ [META-CLASSIFIER] Running in lightweight rule-weighted ensemble mode (Scikit-Learn optional).")
            self.model = None

    def _train_mock_model(self):
        """
        Trains the Scikit-Learn RandomForestClassifier using a dataset of features:
        [nlp_score, typosquat_risk, sandbox_threat_score, mimics_login]
        """
        if not (joblib and RandomForestClassifier and np):
            return

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
        if self.model is not None and np is not None:
            try:
                feature_vector = np.array([[nlp_score, typosquat_risk, sandbox_threat, has_password_field]])
                probabilities = self.model.predict_proba(feature_vector)[0]
                threat_score = probabilities[1] * 100 if len(probabilities) > 1 else (100.0 if self.model.predict(feature_vector)[0] == 1 else 0.0)
            except Exception as e:
                print(f"⚠️ [META-CLASSIFIER] Predict error ({e}), using weighted scoring.")
                threat_score = min(100.0, max(0.0, 0.3 * nlp_score + (35.0 if typosquat_risk else 0.0) + 0.35 * sandbox_threat + (20.0 if has_password_field else 0.0)))
        else:
            threat_score = min(100.0, max(0.0, 0.3 * nlp_score + (35.0 if typosquat_risk else 0.0) + 0.35 * sandbox_threat + (20.0 if has_password_field else 0.0)))
        
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
