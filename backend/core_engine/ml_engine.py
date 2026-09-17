import os
import sys
import re
import tldextract
import Levenshtein
from typing import List, Dict, Any

# Add parent directory to path to import existing V1 modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from good_domain_checker import GoodDomainChecker
except ImportError:
    GoodDomainChecker = None

try:
    from transformers import pipeline
except (ImportError, ModuleNotFoundError):
    pipeline = None

from core_engine.sandbox_engine import VirtualSandboxAnalyzer
from core_engine.meta_classifier import EnsembleMetaClassifier

class EmailNLPClassifier:
    """
    NLP Classifier for Email Text.
    Uses Transfer Learning (pre-trained HuggingFace models) when torch/transformers are available,
    or a fast, memory-safe heuristic analyzer in lightweight cloud environments (e.g. Render Free Tier).
    """
    def __init__(self, model_name: str = "ealvaradob/bert-finetuned-phishing"):
        self.classifier = None
        if pipeline is not None:
            try:
                print(f"🧠 Initializing NLP Classifier with model: {model_name}...")
                self.classifier = pipeline("text-classification", model=model_name, truncation=True, max_length=512)
                print("✅ Pre-trained NLP Classifier loaded successfully.")
            except Exception as e:
                print(f"⚠️ Warning: Could not load HuggingFace model ({e}). Using heuristic fallback.")
                self.classifier = None
        else:
            print("ℹ️ Transformers/Torch not installed (Lightweight Cloud Mode). Using heuristic NLP analyzer.")

    def analyze_text(self, subject: str, body: str) -> Dict[str, Any]:
        combined_text = f"Subject: {subject}\n\nBody: {body}".lower()
        if self.classifier is not None:
            try:
                results = self.classifier(combined_text[:512])
                prediction = results[0]
                label = prediction['label']
                score = prediction['score']
                
                if 'PHISH' in label.upper() or label.upper() == 'NEGATIVE':
                    risk_score = score * 100
                    threat_type = "Phishing / BEC Intent Detected"
                else:
                    risk_score = (1.0 - score) * 100
                    threat_type = "Legitimate / Safe"
                    
                return {
                    "risk_score": round(risk_score, 2),
                    "threat_type": threat_type,
                    "confidence": round(score * 100, 2),
                    "raw_label": label
                }
            except Exception as e:
                print(f"⚠️ NLP inference error ({e}), using heuristic fallback.")

        # Lightweight Heuristic Fallback (Runs in < 1ms, 0MB RAM)
        phish_keywords = [
            "urgent", "verify your account", "action required", "suspended",
            "password reset", "unauthorized access", "bank", "invoice", "wire transfer",
            "security alert", "confirm your identity", "login immediately", "threat detected"
        ]
        matches = [kw for kw in phish_keywords if kw in combined_text]
        if matches:
            risk_score = min(40.0 + len(matches) * 20.0, 95.0)
            threat_type = f"Suspicious Social Engineering Intent ({', '.join(matches[:2])})"
            confidence = 85.0
        else:
            risk_score = 10.0
            threat_type = "Legitimate / Standard Message"
            confidence = 80.0

        return {
            "risk_score": round(risk_score, 2),
            "threat_type": threat_type,
            "confidence": round(confidence, 2),
            "raw_label": "HEURISTIC"
        }

class LinkFeatureExtractor:
    """
    Deep Feature Engineering for URLs with Pre-Filtering for Global Domains.
    """
    def __init__(self, known_brands: List[str] = None):
        self.known_brands = known_brands or [
            "amazon", "paypal", "microsoft", "google", "apple", "netflix", 
            "facebook", "whatsapp", "apex-global", "forms", "drive", "dropbox",
            "instagram", "telegram", "twitter", "linkedin", "github", "zoom"
        ]
        
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_api_key and GoodDomainChecker:
            self.domain_checker = GoodDomainChecker(vt_api_key)
            print("🛡️ Global Popularity Whitelist Active (ChatGPT, Claude, Google will bypass ML).")
        else:
            self.domain_checker = None
            print("⚠️ VT API Key missing. Global Whitelist disabled.")

    def extract_features(self, url: str) -> Dict[str, Any]:
        # Pre-Filter: Is this a massively popular domain like ChatGPT.com?
        if self.domain_checker and self.domain_checker.is_known_good_domain(url):
            return {
                "heuristic_risk_score": 0,
                "status": "WHITELISTED",
                "message": "Top Global Legitimate Domain detected. Skipped heavy ML analysis."
            }

        features = {}
        features['url_length'] = len(url)
        
        ext = tldextract.extract(url)
        domain = ext.domain
        
        features['has_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ext.domain) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        min_distance = 999
        target_brand = None
        # Split domain by hyphens to catch 'amzon' in 'amzon-verify'
        domain_parts = domain.lower().split('-')
        
        for brand in self.known_brands:
            for part in domain_parts:
                dist = Levenshtein.distance(part, brand)
                if dist < min_distance:
                    min_distance = dist
                    target_brand = brand
                
        features['typosquat_risk'] = 1 if 0 < min_distance <= 2 else 0
        features['closest_brand'] = target_brand
        
        heuristic_score = 0
        if features['has_ip_address']: heuristic_score += 40
        if features['has_at_symbol']: heuristic_score += 30
        if features['typosquat_risk']: heuristic_score += 50
        
        features['heuristic_risk_score'] = min(100, heuristic_score)
        features['status'] = "ANALYZED"
        return features

class MultiModalFusionEngine:
    """
    Combines Text NLP output, Link Feature output, and Sandbox Analysis 
    into the Final Ensemble ML Meta-Classifier.
    """
    def __init__(self):
        self.nlp = None
        self.link_extractor = LinkFeatureExtractor()
        self.sandbox = VirtualSandboxAnalyzer()
        self.meta_classifier = EnsembleMetaClassifier()
        
    def _get_nlp(self):
        if self.nlp is None:
            self.nlp = EmailNLPClassifier()
        return self.nlp

    def analyze_email_comprehensive(self, subject: str, body: str, extracted_links: List[str]) -> Dict[str, Any]:
        # Decoupled NLP: Only invoke heavy BERT model when actual email body/subject exists (Web Portal .eml phase).
        # In Pure Link-Only Notification Listener mode, BERT is bypassed completely (nlp_score = 0.0).
        if (subject or "").strip() or (body or "").strip():
            text_results = self._get_nlp().analyze_text(subject, body)
            base_text_risk = text_results['risk_score']
        else:
            text_results = {
                "risk_score": 0.0,
                "threat_type": "Link-Only Notification Mode (BERT Bypassed)",
                "confidence": 0.0,
                "raw_label": "none"
            }
            base_text_risk = 0.0
        
        link_results = []
        highest_link_risk = 0.0
        
        for url in extracted_links:
            features = self.link_extractor.extract_features(url)
            link_results.append({"url": url, "features": features})
            if features['heuristic_risk_score'] > highest_link_risk:
                highest_link_risk = features['heuristic_risk_score']
                
        # Default values if no links are present
        highest_typosquat = 0
        highest_sandbox_threat = 0
        has_password_field = 0
        external_form_action = 0
        suspicious_exfiltration = 0
        newly_registered_domain = 0
        brand_impersonation = 0
        
        # 3. Sandbox Analysis (Only run for the most suspicious link to save time/API quota)
        if len(extracted_links) > 0:
            target_url = extracted_links[0] # Simplification for MVP: analyze the first link
            
            # Check if it was Whitelisted by Fast-Path
            if link_results[0]['features'].get('status') != 'WHITELISTED':
                sandbox_results = self.sandbox.analyze_link_in_sandbox(target_url)
                link_results[0]['sandbox_features'] = sandbox_results
                
                highest_typosquat = link_results[0]['features'].get('typosquat_risk', 0)
                highest_sandbox_threat = sandbox_results.get('sandbox_threat_score', 0)
                has_password_field = sandbox_results.get('sandbox_has_password_field', 0)
                external_form_action = sandbox_results.get('external_form_action', 0)
                suspicious_exfiltration = sandbox_results.get('suspicious_exfiltration', 0)
                newly_registered_domain = sandbox_results.get('newly_registered_domain', 0)
                brand_impersonation = sandbox_results.get('brand_impersonation', 0)
                
        # 4. Stage 6: The Ensemble Meta-Classifier
        meta_verdict = self.meta_classifier.predict_verdict(
            nlp_score=base_text_risk,
            typosquat_risk=highest_typosquat,
            sandbox_threat=highest_sandbox_threat,
            has_password_field=has_password_field,
            external_form_action=external_form_action,
            suspicious_exfiltration=suspicious_exfiltration,
            newly_registered_domain=newly_registered_domain,
            brand_impersonation=brand_impersonation
        )

        return {
            "final_threat_score": meta_verdict.get('threat_score', 0),
            "verdict": meta_verdict['verdict'],
            "text_analysis": text_results,
            "link_analysis": link_results,
            "meta_classifier_details": meta_verdict
        }
