"""
TrustShield V2 - Campaign Case Manager (campaign_manager.py)
Groups related fraudulent emails into campaign clusters based on shared:
  - Originating IP address
  - Sender domain
  - Registrar / ASN fingerprint
  - Typosquat target brand
  - URL pattern / domain

Provides:
  - A searchable case list for the SOC Investigation Console
  - Campaign-level summary statistics
  - Per-campaign incident timeline
  - REST-API-ready serialization

In-memory store (no external DB required for demo). Can be backed by PostgreSQL
via the existing database.py integration.
"""

import hashlib
import logging
import threading
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Origin IPs whose ISP/ASN string matches a shared mail provider say nothing about the actor
# (millions of unrelated senders share them), so the IP is excluded from fingerprints.
_SHARED_MAIL_PROVIDER_MARKERS = (
    "google", "gmail", "microsoft", "outlook", "office365", "amazon", "yahoo", "zoho",
    "mailgun", "sendgrid", "proofpoint", "mimecast", "sendinblue", "mailchimp", "protonmail",
)
MIN_INGEST_SCORE = 40.0
MAX_CAMPAIGNS = 500
MAX_INCIDENTS_PER_CAMPAIGN = 500


def _is_shared_mail_provider(isp: str, asn: str = "") -> bool:
    hay = f"{isp or ''} {asn or ''}".lower()
    return any(m in hay for m in _SHARED_MAIL_PROVIDER_MARKERS)


def _first_malicious_url_domain(analysis_result: Dict[str, Any]) -> str:
    try:
        import tldextract
        ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    except Exception:
        ext = None
    for link in analysis_result.get("link_investigation", []) or []:
        if float(link.get("threat_score", 0) or 0) >= 50.0 and link.get("url"):
            url = str(link["url"])
            if ext:
                reg = ext(url).registered_domain
                if reg:
                    return reg.lower()
            return url.split("//")[-1].split("/")[0].lower()
    return ""


def _fingerprint(analysis_result: Dict[str, Any]) -> str:
    """
    Campaign fingerprint = origin IP + sender domain + registrable domain of the first malicious
    URL (whichever are present). The origin IP is skipped when it belongs to a shared mail
    provider. With no signal at all the key is the constant 'UNKNOWN:' (no timestamp).
    """
    origin = analysis_result.get("origin_intelligence", {}) or {}
    metadata = analysis_result.get("metadata", {}) or {}
    whois = analysis_result.get("whois_intelligence", {}) or {}

    orig_ip = origin.get("originating_ip", "") or ""
    if orig_ip == "Unknown" or _is_shared_mail_provider(origin.get("origin_isp", ""), origin.get("origin_asn", "")):
        orig_ip = ""
    from_domain = (metadata.get("from_domain", "") or "").lower()
    url_domain = _first_malicious_url_domain(analysis_result)

    parts = []
    if orig_ip:
        parts.append(f"IP:{orig_ip}")
    if from_domain:
        parts.append(f"DOMAIN:{from_domain}")
    if url_domain:
        parts.append(f"URL:{url_domain}")
    if not parts:
        registrar = whois.get("registrar", "") or ""
        isp = origin.get("origin_isp", "") or ""
        if registrar and registrar != "Unknown":
            parts.append(f"REGISTRAR:{registrar}")
        elif isp and isp != "Unknown" and not _is_shared_mail_provider(isp):
            parts.append(f"ISP:{isp}")
        else:
            parts.append("UNKNOWN:")

    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class CaseManager:
    """
    In-memory case management system for grouping related phishing incidents
    into named campaigns and providing searchable case history.
    """

    def __init__(self):
        # campaign_id → campaign dict
        self._lock = threading.RLock()
        self._campaigns: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        # fingerprint → campaign_id
        self._fingerprint_index: Dict[str, str] = {}
        # incident_id → campaign_id
        self._incident_index: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Core: Ingest
    # ------------------------------------------------------------------
    def ingest_incident(
        self,
        analysis_result: Dict[str, Any],
        incident_id: Optional[str] = None,
        eml_filename: str = "",
        min_score: float = MIN_INGEST_SCORE
    ) -> Dict[str, Any]:
        """
        Ingests an analysis result as a new incident.
        Automatically groups it into an existing or new campaign.
        Incidents scoring below ``min_score`` (default 40) are NOT ingested.
        Returns the campaign it was assigned to.
        """
        if not incident_id:
            incident_id = uuid.uuid4().hex
        score_in = float(analysis_result.get("overall_threat_score", 0.0) or 0.0)
        if score_in < min_score:
            return {"incident_id": incident_id, "campaign_id": None, "campaign_name": "",
                    "campaign_incident_count": 0, "is_new_campaign": False, "ingested": False,
                    "reason": f"threat_score {score_in} below min_score {min_score}"}
        with self._lock:
            return self._ingest_locked(analysis_result, incident_id, eml_filename)

    def _ingest_locked(self, analysis_result: Dict[str, Any], incident_id: str, eml_filename: str) -> Dict[str, Any]:
        fp = _fingerprint(analysis_result)
        campaign_id = self._fingerprint_index.get(fp)

        if not campaign_id:
            # Create new campaign
            campaign_id = f"CAMP-{uuid.uuid4().hex[:16].upper()}"
            self._campaigns[campaign_id] = {
                "campaign_id": campaign_id,
                "fingerprint": fp,
                "first_seen": _utcnow_iso(),
                "last_seen": _utcnow_iso(),
                "incident_count": 0,
                "incidents": [],
                "threat_score_max": 0.0,
                "threat_score_avg": 0.0,
                "infrastructure": {
                    "originating_ips": [],
                    "sender_domains": [],
                    "registrars": [],
                    "isps": [],
                    "malicious_urls": [],
                    "target_brands": [],
                },
                "verdict_distribution": {
                    "CRITICAL FRAUD / PHISHING": 0,
                    "SUSPICIOUS / UNVERIFIED ORIGIN": 0,
                    "LEGITIMATE / AUTHENTICATED": 0
                },
                "nlp_classes": [],
                "campaign_name": ""  # Auto-generated below
            }
            self._fingerprint_index[fp] = campaign_id
            while len(self._campaigns) > MAX_CAMPAIGNS:
                old_id, old = self._campaigns.popitem(last=False)
                self._fingerprint_index.pop(old.get("fingerprint"), None)
                for inc in old.get("incidents", []):
                    self._incident_index.pop(inc.get("incident_id"), None)

        self._campaigns.move_to_end(campaign_id)
        campaign = self._campaigns[campaign_id]
        campaign["last_seen"] = _utcnow_iso()
        campaign["incident_count"] += 1

        # Update infrastructure intelligence
        origin = analysis_result.get("origin_intelligence", {})
        metadata = analysis_result.get("metadata", {})
        whois = analysis_result.get("whois_intelligence", {})
        links = analysis_result.get("link_investigation", [])
        nlp = analysis_result.get("nlp_analysis", {})

        infra = campaign["infrastructure"]
        _add_unique(infra["originating_ips"], origin.get("originating_ip", ""))
        _add_unique(infra["sender_domains"], metadata.get("from_domain", ""))
        _add_unique(infra["registrars"], whois.get("registrar", ""))
        _add_unique(infra["isps"], origin.get("origin_isp", ""))

        for link in links:
            if float(link.get("threat_score", 0)) >= 50.0:
                _add_unique(infra["malicious_urls"], link.get("url", ""))

        # NLP class
        nlp_class = nlp.get("nlp_class", "")
        if nlp_class:
            _add_unique(campaign["nlp_classes"], nlp_class)

        # Threat score tracking
        score = float(analysis_result.get("overall_threat_score", 0.0))
        campaign["threat_score_max"] = max(campaign["threat_score_max"], score)
        # Recalculate running average
        all_scores = [inc["threat_score"] for inc in campaign["incidents"]] + [score]
        campaign["threat_score_avg"] = round(sum(all_scores) / len(all_scores), 1)

        # Verdict distribution
        verdict = analysis_result.get("verdict", "")
        if verdict in campaign["verdict_distribution"]:
            campaign["verdict_distribution"][verdict] += 1

        # Create incident record
        incident_record = {
            "incident_id": incident_id,
            "eml_filename": eml_filename,
            "timestamp": _utcnow_iso(),
            "threat_score": score,
            "verdict": verdict,
            "nlp_class": nlp_class,
            "sender": metadata.get("from", ""),
            "subject": metadata.get("subject", ""),
            "originating_ip": origin.get("originating_ip", "Unknown"),
            "origin_country": origin.get("origin_country", "Unknown"),
            "evidence_hash_sha256": analysis_result.get("evidence_hash_sha256", ""),
        }
        campaign["incidents"].append(incident_record)
        if len(campaign["incidents"]) > MAX_INCIDENTS_PER_CAMPAIGN:
            dropped = campaign["incidents"].pop(0)
            self._incident_index.pop(dropped.get("incident_id"), None)
        self._incident_index[incident_id] = campaign_id

        # Auto-generate campaign name on first incident
        if not campaign["campaign_name"]:
            campaign["campaign_name"] = self._generate_campaign_name(analysis_result, campaign_id)

        return {
            "incident_id": incident_id,
            "campaign_id": campaign_id,
            "campaign_name": campaign["campaign_name"],
            "campaign_incident_count": campaign["incident_count"],
            "is_new_campaign": campaign["incident_count"] == 1,
            "ingested": True,
        }

    def _generate_campaign_name(self, analysis_result: Dict[str, Any], campaign_id: str) -> str:
        """Auto-generates a descriptive campaign name from infrastructure signals."""
        origin = analysis_result.get("origin_intelligence", {})
        metadata = analysis_result.get("metadata", {})
        whois = analysis_result.get("whois_intelligence", {})
        links = analysis_result.get("link_investigation", [])

        country = origin.get("origin_country", "")
        domain = metadata.get("from_domain", "")
        top_link_verdict = ""
        for link in links:
            if float(link.get("threat_score", 0)) >= 70.0:
                top_link_verdict = link.get("verdict", "")
                break

        if "CREDENTIAL" in top_link_verdict.upper() or "PHISHING" in top_link_verdict.upper():
            category = "Credential Theft"
        elif analysis_result.get("nlp_analysis", {}).get("nlp_class") == "BEC_FRAUD":
            category = "BEC Fraud"
        else:
            category = "Phishing"

        name_parts = [category]
        if country and country != "Unknown":
            name_parts.append(f"[{country}]")
        if domain:
            name_parts.append(f"via {domain}")

        return " ".join(name_parts) + f" ({campaign_id})"

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def get_all_campaigns(self, min_incidents: int = 1) -> List[Dict[str, Any]]:
        """Returns all campaigns, sorted by last_seen descending."""
        result = [
            c for c in list(self._campaigns.values())
            if c["incident_count"] >= min_incidents
        ]
        result.sort(key=lambda x: x["last_seen"], reverse=True)
        return result

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        return self._campaigns.get(campaign_id)

    def get_campaign_for_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        cid = self._incident_index.get(incident_id)
        if cid:
            return self._campaigns.get(cid)
        return None

    def search_campaigns(self, query: str) -> List[Dict[str, Any]]:
        """
        Searches campaigns by: campaign name, sender domain, originating IP,
        registrar, or campaign ID.
        """
        q = query.lower().strip()
        if not q:
            return self.get_all_campaigns()

        results = []
        for camp in list(self._campaigns.values()):
            infra = camp.get("infrastructure", {})
            searchable = " ".join([
                camp.get("campaign_name", ""),
                camp.get("campaign_id", ""),
                " ".join(infra.get("originating_ips", [])),
                " ".join(infra.get("sender_domains", [])),
                " ".join(infra.get("registrars", [])),
                " ".join(infra.get("isps", [])),
            ]).lower()
            if q in searchable:
                results.append(camp)

        results.sort(key=lambda x: x["last_seen"], reverse=True)
        return results

    def get_stats(self) -> Dict[str, Any]:
        total_incidents = sum(c["incident_count"] for c in self._campaigns.values())
        return {
            "total_campaigns": len(self._campaigns),
            "total_incidents": total_incidents,
            "active_campaigns": sum(1 for c in self._campaigns.values() if c["incident_count"] > 1),
            "avg_incidents_per_campaign": round(total_incidents / max(1, len(self._campaigns)), 1)
        }


def _add_unique(lst: list, val: str) -> None:
    """Adds val to lst if not already present and val is non-empty."""
    if val and val not in ("Unknown", "") and val not in lst:
        lst.append(val)


# ============================================================================
# Singleton instance
# ============================================================================
_GLOBAL_CASE_MANAGER = CaseManager()


def get_case_manager() -> CaseManager:
    return _GLOBAL_CASE_MANAGER
