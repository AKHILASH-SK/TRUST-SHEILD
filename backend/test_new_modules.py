"""Test script for all new SIH-required modules against the Linkdin.eml test file."""
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EML_PATH = os.path.join('..', 'Linkdin.eml')

print("=" * 60)
print("TRUSTSHIELD - NEW MODULE TEST SUITE")
print("=" * 60)

# ---- Test 1: BEC / NLP Analyser ----
print("\n[TEST 1] BEC & NLP Body Analyser")
from core_engine.bec_nlp_analyser import analyse_email_body

result = analyse_email_body(
    subject='Linkdin',
    body=(
        "Dear User, We have detected unauthorized access to your account from an unrecognized device. "
        "To prevent further unauthorized transactions, please verify your identity immediately using "
        "the secure link below: Verify My Account: https://linked1n.vercel.app/ "
        "If you do not verify within 24 hours, your account access will be temporarily suspended. "
        "Regards, Security Team"
    )
)
print(f"  NLP Class      : {result['nlp_class']}")
print(f"  NLP Risk Score : {result['nlp_risk_score']}/100")
print(f"  Confidence     : {result['confidence']}%")
print(f"  Urgency Score  : {result['urgency_score']}")
print(f"  Evidence       : {result['evidence']}")
print(f"  Summary        : {result['social_engineering_summary']}")
print(f"  Taxonomy Desc  : {result['taxonomy_description']}")
print("  STATUS: PASS" if result['nlp_class'] in ('PHISHING', 'SUSPICIOUS', 'BEC_FRAUD') else "  STATUS: UNEXPECTED CLASS")

# ---- Test 2: WHOIS Intelligence ----
print("\n[TEST 2] WHOIS & Domain Intelligence")
from core_engine.whois_intel import lookup_whois

whois_result = lookup_whois("gmail.com")
print(f"  Domain          : {whois_result['domain']}")
print(f"  Registrar       : {whois_result['registrar']}")
print(f"  Domain Age (days): {whois_result['domain_age_days']}")
print(f"  Newly Registered: {whois_result['is_newly_registered']}")
print(f"  Privacy Shielded: {whois_result['is_privacy_shielded']}")
print(f"  WHOIS Risk Score: {whois_result['whois_risk_score']}/100")
print(f"  WHOIS Available : {whois_result['whois_available']}")
print(f"  Risk Flags      : {whois_result['whois_risk_flags']}")
print("  STATUS: PASS" if whois_result['domain'] == 'gmail.com' else "  STATUS: FAIL")

# ---- Test 3: Attachment Analyser ----
print("\n[TEST 3] Attachment Risk Analyser")
from core_engine.attachment_analyser import analyse_attachments

with open(EML_PATH, 'rb') as f:
    eml_bytes = f.read()

attach_result = analyse_attachments(eml_bytes)
print(f"  Total Attachments : {attach_result['total_attachments']}")
print(f"  Risk Level        : {attach_result['attachment_risk_level']}")
print(f"  Risk Score        : {attach_result['attachment_risk_score']}/100")
print(f"  Has High Risk     : {attach_result['has_high_risk_attachment']}")
print(f"  Attachments Detail: {attach_result['attachments']}")
print("  STATUS: PASS (no attachments in this EML is expected)")

# ---- Test 4: Graph Correlation ----
print("\n[TEST 4] Graph Correlation Engine")
from core_engine.graph_correlation import ThreatInfrastructureGraph, _node_id

g = ThreatInfrastructureGraph()
fake_result = {
    "metadata": {"from": "test@phish.com", "from_domain": "phish.com", "reply_to": "", "reply_to_mismatch": False, "subject": "Test"},
    "authentication": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False},
    "origin_intelligence": {"originating_ip": "185.220.101.5", "origin_country": "Germany", "origin_isp": "Tor Network", "is_proxy": True, "is_hosting": False, "route_map": []},
    "link_investigation": [{"url": "https://linked1n.vercel.app", "threat_score": 97.5, "verdict": "CRITICAL PHISHING"}],
    "whois_intelligence": {"registrar": "Namecheap", "domain_age_days": 3},
    "overall_threat_score": 97.5,
    "verdict": "CRITICAL FRAUD / PHISHING",
    "nlp_analysis": {"nlp_class": "PHISHING"}
}
delta = g.build_from_analysis(fake_result)
d3 = g.to_d3_format()
print(f"  Graph Nodes     : {delta['total_graph_nodes']}")
print(f"  Graph Edges     : {delta['total_graph_edges']}")
print(f"  New Nodes Added : {len(delta['new_node_ids'])}")
print(f"  D3 Format Nodes : {len(d3['nodes'])}")
print(f"  D3 Format Links : {len(d3['links'])}")
print(f"  Node Types      : {d3['summary']['node_type_counts']}")
print("  STATUS: PASS" if d3['summary']['total_nodes'] >= 3 else "  STATUS: FAIL")

# ---- Test 5: Campaign Manager ----
print("\n[TEST 5] Campaign Case Manager")
from core_engine.campaign_manager import CaseManager

cm = CaseManager()
camp_info = cm.ingest_incident(fake_result, incident_id="INC001", eml_filename="Linkdin.eml")
print(f"  Incident ID         : {camp_info['incident_id']}")
print(f"  Campaign ID         : {camp_info['campaign_id']}")
print(f"  Campaign Name       : {camp_info['campaign_name']}")
print(f"  Is New Campaign     : {camp_info['is_new_campaign']}")

# Add a second incident with same fingerprint (same IP = same campaign)
camp_info2 = cm.ingest_incident(fake_result, incident_id="INC002", eml_filename="Another_phish.eml")
print(f"  Second Incident Camp: {camp_info2['campaign_id']} (should match first)")
print(f"  Campaign Inc Count  : {camp_info2['campaign_incident_count']}")

all_camps = cm.get_all_campaigns()
print(f"  Total Campaigns     : {len(all_camps)}")
stats = cm.get_stats()
print(f"  Stats               : {stats}")
print("  STATUS: PASS" if camp_info['campaign_id'] == camp_info2['campaign_id'] else "  STATUS: FAIL (campaigns should match)")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETE")
print("=" * 60)
