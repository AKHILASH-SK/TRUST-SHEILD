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
        ])
        
        y_train = np.array([0, 0, 1, 1, 1, 1])
        
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Save it for future runs
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        print("✅ [META-CLASSIFIER] Ensemble Model trained and saved successfully.")

    def predict_verdict(self, nlp_score: float, typosquat_risk: int, sandbox_threat: float, has_password_field: int) -> dict:
        """
        Runs the final prediction.
        """
        # Prepare the feature vector exactly as the model expects it
        feature_vector = np.array([[nlp_score, typosquat_risk, sandbox_threat, has_password_field]])
        
        # Get the prediction (0 = Legitimate, 1 = Phishing)
        prediction_class = self.model.predict(feature_vector)[0]
        
        # Get the confidence percentage of that prediction
        probabilities = self.model.predict_proba(feature_vector)[0]
        confidence = probabilities[prediction_class] * 100
        
        if prediction_class == 1:
            if confidence >= 80:
                verdict = "CRITICAL FRAUD / PHISHING"
            else:
                verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"
            
        return {
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "meta_features_used": {
                "nlp_score": nlp_score,
                "typosquat_risk": typosquat_risk,
                "sandbox_threat": sandbox_threat,
                "has_password_field": has_password_field
            }
        }
