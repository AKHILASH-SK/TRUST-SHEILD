"""
TrustShield V2 - Graph Correlation Engine (graph_correlation.py)
Builds a relationship graph linking sender domains, originating IPs, reply-to aliases,
relay hops, and embedded URLs to:
  - Identify shared infrastructure across multiple incidents (campaign-level attribution)
  - Detect repeated threat actors using the same hosting provider, ASN, or domain cluster
  - Produce a graph-ready data structure (nodes + edges) for D3.js frontend visualization

The graph is persisted in-memory (and optionally to the database) so that:
  - Each new analysis ADDS nodes/edges to the cumulative knowledge graph
  - Analysts can query whether a new email shares infrastructure with a prior case

No external library required: pure Python adjacency representation.
Optional: networkx is used for centrality analysis if installed.
"""

import hashlib
import logging
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger(__name__)

# ============================================================================
# NODE TYPES
# ============================================================================
NODE_TYPES = {
    "DOMAIN":     {"color": "#4A90D9", "shape": "circle",  "label": "Domain"},
    "IP":         {"color": "#E74C3C", "shape": "diamond", "label": "IP Address"},
    "ASN":        {"color": "#F39C12", "shape": "square",  "label": "ASN / ISP"},
    "URL":        {"color": "#9B59B6", "shape": "circle",  "label": "Malicious URL"},
    "EMAIL":      {"color": "#2ECC71", "shape": "triangle","label": "Email Address"},
    "CAMPAIGN":   {"color": "#E67E22", "shape": "star",    "label": "Campaign"},
}

EDGE_TYPES = {
    "SENDS_FROM":       "Sender domain → originating IP",
    "RELAY_HOP":        "IP → next relay hop IP",
    "HOSTS_URL":        "IP/Domain → embedded malicious URL",
    "REPLY_TO":         "From address → reply-to address",
    "SHARES_ASN":       "IP → ASN (shared network)",
    "SAME_REGISTRAR":   "Domain → registrar (shared registrar)",
    "LINKED_CAMPAIGN":  "Incident → campaign cluster",
}


def _node_id(node_type: str, value: str) -> str:
    """Generates a stable, unique node ID for a given type+value pair."""
    key = f"{node_type}::{value.lower().strip()}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


class ThreatInfrastructureGraph:
    """
    In-memory threat infrastructure graph.
    Nodes represent entities (domains, IPs, ASNs, URLs, email addresses).
    Edges represent observed relationships between entities.
    Designed to accumulate data across multiple analysis sessions.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}  # node_id → node_data
        self.edges: List[Dict[str, Any]] = []        # list of edge dicts
        self._edge_set: Set[str] = set()             # dedup edge keys

    def add_node(self, node_type: str, value: str, metadata: Optional[Dict] = None) -> str:
        """Add or update a node. Returns its node_id."""
        nid = _node_id(node_type, value)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "type": node_type,
                "value": value,
                "label": f"{value[:40]}",
                "color": NODE_TYPES.get(node_type, {}).get("color", "#888"),
                "shape": NODE_TYPES.get(node_type, {}).get("shape", "circle"),
                "type_label": NODE_TYPES.get(node_type, {}).get("label", node_type),
                "incident_count": 0,
                "metadata": metadata or {}
            }
        self.nodes[nid]["incident_count"] = self.nodes[nid].get("incident_count", 0) + 1
        return nid

    def add_edge(self, from_id: str, to_id: str, edge_type: str, label: str = "") -> None:
        """Add a directed edge between two nodes (deduplicated)."""
        if not from_id or not to_id or from_id == to_id:
            return
        edge_key = f"{from_id}→{to_id}→{edge_type}"
        if edge_key in self._edge_set:
            return
        self._edge_set.add(edge_key)
        self.edges.append({
            "source": from_id,
            "target": to_id,
            "type": edge_type,
            "label": label or EDGE_TYPES.get(edge_type, edge_type)
        })

    def build_from_analysis(self, analysis_result: Dict[str, Any], incident_id: str = "") -> Dict[str, Any]:
        """
        Ingests a unified pipeline analysis result and adds all entities
        and relationships to the graph.

        Returns the graph delta (new nodes + edges added by this incident).
        """
        new_node_ids = []
        new_edge_count_before = len(self.edges)

        metadata = analysis_result.get("metadata", {})
        auth = analysis_result.get("authentication", {})
        origin = analysis_result.get("origin_intelligence", {})
        links = analysis_result.get("link_investigation", [])
        whois = analysis_result.get("whois_intelligence", {})
        route_map = origin.get("route_map", [])

        # --- Sender domain node ---
        from_domain = metadata.get("from_domain", "")
        from_email = metadata.get("from", "")
        if from_domain:
            domain_nid = self.add_node("DOMAIN", from_domain, {
                "spf_pass": auth.get("spf_pass"),
                "dkim_pass": auth.get("dkim_pass"),
                "dmarc_pass": auth.get("dmarc_pass"),
                "registrar": whois.get("registrar", "Unknown"),
                "domain_age_days": whois.get("domain_age_days"),
                "is_newly_registered": whois.get("is_newly_registered", False),
            })
            new_node_ids.append(domain_nid)

        # --- From email address node ---
        if from_email:
            email_nid = self.add_node("EMAIL", from_email)
            new_node_ids.append(email_nid)
            if from_domain:
                self.add_edge(email_nid, domain_nid, "SENDS_FROM")

        # --- Reply-To node (BEC indicator) ---
        reply_to = metadata.get("reply_to", "")
        if reply_to and metadata.get("reply_to_mismatch"):
            reply_nid = self.add_node("EMAIL", reply_to)
            new_node_ids.append(reply_nid)
            if from_email:
                self.add_edge(email_nid, reply_nid, "REPLY_TO",
                              "Reply-To diverges from From (BEC indicator)")

        # --- Originating IP node ---
        orig_ip = origin.get("originating_ip", "")
        if orig_ip and orig_ip != "Unknown":
            ip_nid = self.add_node("IP", orig_ip, {
                "country": origin.get("origin_country", "Unknown"),
                "isp": origin.get("origin_isp", "Unknown"),
                "is_proxy": origin.get("is_proxy", False),
                "is_hosting": origin.get("is_hosting", False),
            })
            new_node_ids.append(ip_nid)
            if from_domain:
                self.add_edge(domain_nid, ip_nid, "SENDS_FROM")

            # ASN node
            asn = origin.get("origin_isp", "")
            if asn and asn != "Unknown":
                asn_nid = self.add_node("ASN", asn)
                new_node_ids.append(asn_nid)
                self.add_edge(ip_nid, asn_nid, "SHARES_ASN")

        # --- Relay hop nodes ---
        prev_hop_nid = None
        for hop in route_map:
            hop_ip = hop.get("ip", "")
            if not hop_ip or hop_ip == orig_ip:
                continue
            hop_nid = self.add_node("IP", hop_ip, {
                "city": hop.get("city"),
                "country": hop.get("country"),
                "isp": hop.get("isp"),
            })
            new_node_ids.append(hop_nid)
            if prev_hop_nid:
                self.add_edge(prev_hop_nid, hop_nid, "RELAY_HOP")
            prev_hop_nid = hop_nid

        # --- Malicious URL nodes ---
        for link_entry in links:
            url = link_entry.get("url", "")
            score = float(link_entry.get("threat_score", 0.0))
            if url and score >= 50.0:
                url_nid = self.add_node("URL", url, {
                    "threat_score": score,
                    "verdict": link_entry.get("verdict", ""),
                })
                new_node_ids.append(url_nid)
                if orig_ip and orig_ip != "Unknown":
                    self.add_edge(ip_nid, url_nid, "HOSTS_URL")
                elif from_domain:
                    self.add_edge(domain_nid, url_nid, "HOSTS_URL")

        # --- Registrar node (shared infrastructure signal) ---
        registrar = whois.get("registrar", "")
        if registrar and registrar not in ("Unknown", ""):
            reg_nid = self.add_node("ASN", f"Registrar:{registrar}")
            if from_domain:
                self.add_edge(domain_nid, reg_nid, "SAME_REGISTRAR")

        new_edges = self.edges[new_edge_count_before:]
        return {
            "new_node_ids": list(set(new_node_ids)),
            "new_edges_count": len(new_edges),
            "total_graph_nodes": len(self.nodes),
            "total_graph_edges": len(self.edges),
        }

    def to_d3_format(self) -> Dict[str, Any]:
        """
        Exports the graph in D3.js force-directed graph format:
        { nodes: [...], links: [...] }
        """
        return {
            "nodes": list(self.nodes.values()),
            "links": [
                {
                    "source": e["source"],
                    "target": e["target"],
                    "type": e["type"],
                    "label": e["label"]
                }
                for e in self.edges
            ],
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_type_counts": self._count_by_type()
            }
        }

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for node in self.nodes.values():
            t = node["type"]
            counts[t] = counts.get(t, 0) + 1
        return counts

    def find_shared_infrastructure(self, target_ip: str = "", target_domain: str = "") -> List[Dict[str, Any]]:
        """
        Finds all nodes connected to a given IP or domain through any edge.
        Useful for campaign-level correlation: 'Who else uses this IP/domain?'
        """
        results = []
        target_nid = None
        if target_ip:
            target_nid = _node_id("IP", target_ip)
        elif target_domain:
            target_nid = _node_id("DOMAIN", target_domain)

        if not target_nid or target_nid not in self.nodes:
            return []

        connected_ids = set()
        for edge in self.edges:
            if edge["source"] == target_nid:
                connected_ids.add(edge["target"])
            elif edge["target"] == target_nid:
                connected_ids.add(edge["source"])

        for nid in connected_ids:
            if nid in self.nodes:
                results.append(self.nodes[nid])

        return results

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": self._count_by_type()
        }


# ============================================================================
# Singleton graph instance (persists across requests in a single process)
# ============================================================================
_GLOBAL_GRAPH = ThreatInfrastructureGraph()


def get_global_graph() -> ThreatInfrastructureGraph:
    """Returns the singleton global threat graph for cross-incident correlation."""
    return _GLOBAL_GRAPH


def ingest_analysis_to_graph(analysis_result: Dict[str, Any], incident_id: str = "") -> Dict[str, Any]:
    """Ingests a completed analysis result into the global threat graph."""
    return _GLOBAL_GRAPH.build_from_analysis(analysis_result, incident_id)


def get_graph_d3_data() -> Dict[str, Any]:
    """Returns the full global graph in D3.js format for frontend rendering."""
    return _GLOBAL_GRAPH.to_d3_format()
