import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_engine.ml_engine import MultiModalFusionEngine

def run_test():
    print("🚀 Initializing Test for SIH 2026 Phishing Detection Engine...\n")
    engine = MultiModalFusionEngine()
    
    # ---------------------------------------------------------
    # Test Case 1: Legitimate Email without Links
    # ---------------------------------------------------------
    print("\n--- Test Case 1: Legitimate Email ---")
    legit_subject = "Meeting Notes from Tuesday"
    legit_body = "Hi team, attached are the notes from our Tuesday standup. Let me know if you have questions."
    legit_links = []
    
    result1 = engine.analyze_email_comprehensive(legit_subject, legit_body, legit_links)
    print(f"Verdict: {result1['verdict']} (Score: {result1['final_threat_score']})")
    print(f"NLP Threat: {result1['text_analysis']['threat_type']}")
    
    # ---------------------------------------------------------
    # Test Case 2: BEC / Phishing Email with Typosquatting Link
    # ---------------------------------------------------------
    print("\n--- Test Case 2: Phishing / BEC Email with Malicious Link ---")
    phish_subject = "URGENT: Overdue Vendor Settlement - Wire Transfer Required"
    phish_body = "Alex, I am currently locked in a confidential board meeting. We have an overdue invoice of $64,200. Settle this immediately to avoid legal penalties via the link below."
    phish_links = ["http://login.amzon-verify.com/auth/session"]
    
    result2 = engine.analyze_email_comprehensive(phish_subject, phish_body, phish_links)
    print(f"Verdict: {result2['verdict']} (Score: {result2['final_threat_score']})")
    print(f"NLP Threat: {result2['text_analysis']['threat_type']}")
    print(f"Link Typosquatting detected: {result2['link_analysis'][0]['features']['closest_brand']}")

if __name__ == "__main__":
    run_test()
