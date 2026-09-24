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
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(analysis_result: Dict[str, Any]) -> str:
    """
    Generates a campaign fingerprint from the strongest infrastructure signals.
    Emails sharing the same fingerprint are grouped into the same campaign.
    """
    origin = analysis_result.get("origin_intelligence", {})
    metadata = analysis_result.get("metadata", {})
    whois = analysis_result.get("whois_intelligence", {})

    # Primary: originating IP (most reliable infra signal)
    orig_ip = origin.get("originating_ip", "") or ""
    # Secondary: sender domain
    from_domain = metadata.get("from_domain", "") or ""
    # Tertiary: registrar (shared registrar = shared infra)
    registrar = whois.get("registrar", "") or ""
    # Quaternary: ASN
    isp = origin.get("origin_isp", "") or ""

    # Build fingerprint from strongest available signals
    if orig_ip and orig_ip != "Unknown":
        raw = f"IP:{orig_ip}"
    elif from_domain:
        raw = f"DOMAIN:{from_domain}"
    elif registrar and registrar != "Unknown":
        raw = f"REGISTRAR:{registrar}"
    elif isp and isp != "Unknown":
        raw = f"ISP:{isp}"
    else:
        raw = f"UNKNOWN:{_utcnow_iso()}"

    return hashlib.md5(raw.encode()).hexdigest()[:16]


class CaseManager:
    """
    In-memory case management system for grouping related phishing incidents
    into named campaigns and providing searchable case history.
    """

    def __init__(self):
        # campaign_id → campaign dict
        self._campaigns: Dict[str, Dict[str, Any]] = {}
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
        eml_filename: str = ""
    ) -> Dict[str, Any]:
        """
        Ingests an analysis result as a new incident.
        Automatically groups it into an existing or new campaign.
        Returns the campaign it was assigned to.
        """
        if not incident_id:
            incident_id = str(uuid.uuid4())[:8].upper()

        fp = _fingerprint(analysis_result)
        campaign_id = self._fingerprint_index.get(fp)

        if not campaign_id:
            # Create new campaign
            campaign_id = f"CAMP-{str(uuid.uuid4())[:6].upper()}"
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
            c for c in self._campaigns.values()
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
        for camp in self._campaigns.values():
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
