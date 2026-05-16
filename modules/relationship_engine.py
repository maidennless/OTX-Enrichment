"""
Relationship detection engine using NetworkX.
Detects:
  - Same IP linked to multiple malware families
  - Domains sharing ASN
  - Repeated hashes across campaigns
  - Temporal clustering
Generates graph data for pyvis visualization.
"""
import json
import os
from collections import defaultdict
from datetime import datetime, timezone

import networkx as nx
from pyvis.network import Network

from modules import database as db

GRAPH_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "graphs")
os.makedirs(GRAPH_OUTPUT_DIR, exist_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── CLUSTER DETECTORS ───────────────────────────────────────────────────────

def detect_ip_multi_malware(iocs: list) -> list:
    """Find IPs linked to more than one malware family across pulses."""
    ip_malware = defaultdict(set)
    ip_ids = defaultdict(list)

    for ioc in iocs:
        if ioc["ioc_type"] == "IPv4":
            mf = ioc.get("malware_family", "Unknown")
            if mf != "Unknown":
                ip_malware[ioc["indicator"]].add(mf)
                ip_ids[ioc["indicator"]].append(ioc["id"])

    clusters = []
    for ip, families in ip_malware.items():
        if len(families) > 1:
            clusters.append({
                "cluster_type": "ip_malware",
                "cluster_name": f"IP {ip} → {len(families)} Malware Families",
                "description": f"IP address {ip} is associated with {len(families)} distinct malware families: {', '.join(sorted(families))}",
                "severity": "critical" if len(families) >= 3 else "high",
                "ioc_ids": json.dumps(list(set(ip_ids[ip]))),
                "metadata": json.dumps({"ip": ip, "families": list(families)}),
                "detected_at": _now(),
            })
    return clusters


def detect_asn_domain_sharing(iocs: list) -> list:
    """Find domains that share the same ASN."""
    asn_domains = defaultdict(list)
    asn_ids = defaultdict(list)

    for ioc in iocs:
        if ioc["ioc_type"] in ("domain", "hostname", "URL"):
            asn = ioc.get("asn", "Unknown")
            if asn and asn != "Unknown":
                asn_domains[asn].append(ioc["indicator"])
                asn_ids[asn].append(ioc["id"])

    clusters = []
    for asn, domains in asn_domains.items():
        if len(domains) > 1:
            unique_domains = list(set(domains))
            clusters.append({
                "cluster_type": "asn_domain",
                "cluster_name": f"ASN {asn} → {len(unique_domains)} Domains",
                "description": f"{len(unique_domains)} malicious domains share ASN {asn}: {', '.join(unique_domains[:5])}{'...' if len(unique_domains) > 5 else ''}",
                "severity": "high" if len(unique_domains) >= 3 else "medium",
                "ioc_ids": json.dumps(list(set(asn_ids[asn]))),
                "metadata": json.dumps({"asn": asn, "domains": unique_domains}),
                "detected_at": _now(),
            })
    return clusters


def detect_hash_across_campaigns(iocs: list) -> list:
    """Find file hashes that appear in multiple pulses/campaigns."""
    hash_pulses = defaultdict(set)
    hash_ids = defaultdict(list)
    hash_types = {}

    for ioc in iocs:
        if "FileHash" in ioc.get("ioc_type", "") or ioc.get("ioc_type", "") in ("MD5", "SHA1", "SHA256"):
            pulse_id = ioc.get("pulse_id", "")
            if pulse_id:
                hash_pulses[ioc["indicator"]].add(pulse_id)
                hash_ids[ioc["indicator"]].append(ioc["id"])
                hash_types[ioc["indicator"]] = ioc["ioc_type"]

    clusters = []
    for h, pulses in hash_pulses.items():
        if len(pulses) > 1:
            clusters.append({
                "cluster_type": "hash_campaign",
                "cluster_name": f"Hash in {len(pulses)} Campaigns",
                "description": f"File hash {h[:16]}... appears across {len(pulses)} distinct campaigns, suggesting shared tooling or infrastructure reuse.",
                "severity": "critical" if len(pulses) >= 3 else "high",
                "ioc_ids": json.dumps(list(set(hash_ids[h]))),
                "metadata": json.dumps({"hash": h, "hash_type": hash_types.get(h, "unknown"), "campaign_count": len(pulses)}),
                "detected_at": _now(),
            })
    return clusters


def detect_temporal_clusters(iocs: list, window_hours: int = 24) -> list:
    """Find IOCs created within a tight time window (same campaign burst)."""
    from collections import Counter

    day_iocs = defaultdict(list)
    for ioc in iocs:
        created = ioc.get("created", "")
        if created and len(created) >= 10:
            day = created[:10]  # YYYY-MM-DD
            day_iocs[day].append(ioc)

    clusters = []
    for day, day_ioc_list in day_iocs.items():
        if len(day_ioc_list) >= 5:
            # Group by pulse
            pulse_counts = Counter(i.get("pulse_id", "") for i in day_ioc_list)
            dominant_pulse = pulse_counts.most_common(1)[0][0] if pulse_counts else ""
            clusters.append({
                "cluster_type": "temporal",
                "cluster_name": f"Burst: {len(day_ioc_list)} IOCs on {day}",
                "description": f"Temporal cluster of {len(day_ioc_list)} IOCs created on {day}, suggesting coordinated campaign activity. Dominant pulse: {dominant_pulse[:12]}...",
                "severity": "medium",
                "ioc_ids": json.dumps([i["id"] for i in day_ioc_list[:20]]),
                "metadata": json.dumps({"date": day, "count": len(day_ioc_list), "pulse_breakdown": dict(list(pulse_counts.items())[:5])}),
                "detected_at": _now(),
            })
    return clusters


def run_all_detectors() -> dict:
    """Run all relationship detectors and store results."""
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, indicator, ioc_type, pulse_id, malware_family, country, asn, created FROM iocs"
        ).fetchall()
    iocs = [dict(r) for r in rows]

    if not iocs:
        return {"clusters": 0, "relationships": 0}

    all_clusters = []
    all_clusters.extend(detect_ip_multi_malware(iocs))
    all_clusters.extend(detect_asn_domain_sharing(iocs))
    all_clusters.extend(detect_hash_across_campaigns(iocs))
    all_clusters.extend(detect_temporal_clusters(iocs))

    for cluster in all_clusters:
        db.insert_cluster(cluster)

    # Also build pairwise relationships from clusters
    rel_count = 0
    for cluster in all_clusters:
        ioc_ids = json.loads(cluster.get("ioc_ids", "[]"))
        for i in range(len(ioc_ids)):
            for j in range(i + 1, len(ioc_ids)):
                db.insert_relationship({
                    "source_ioc_id": ioc_ids[i],
                    "target_ioc_id": ioc_ids[j],
                    "relationship_type": cluster["cluster_type"],
                    "confidence": 80,
                    "description": cluster["cluster_name"],
                    "created": _now(),
                })
                rel_count += 1

    return {"clusters": len(all_clusters), "relationships": rel_count}


# ─── GRAPH BUILDER ───────────────────────────────────────────────────────────

TYPE_COLORS = {
    "IPv4": "#ef4444",
    "IPv6": "#f97316",
    "domain": "#3b82f6",
    "hostname": "#6366f1",
    "URL": "#8b5cf6",
    "FileHash-MD5": "#10b981",
    "FileHash-SHA1": "#14b8a6",
    "FileHash-SHA256": "#059669",
    "email": "#f59e0b",
    "CIDR": "#ec4899",
    "default": "#6b7280",
}

TYPE_SHAPES = {
    "IPv4": "dot",
    "domain": "square",
    "URL": "triangle",
    "FileHash-MD5": "diamond",
    "FileHash-SHA1": "diamond",
    "FileHash-SHA256": "diamond",
    "email": "star",
    "default": "ellipse",
}

REL_COLORS = {
    "ip_malware": "#ef4444",
    "asn_domain": "#3b82f6",
    "hash_campaign": "#10b981",
    "temporal": "#f59e0b",
    "related-to": "#9ca3af",
    "indicates": "#8b5cf6",
    "default": "#d1d5db",
}


def build_full_graph(max_nodes: int = 150) -> str:
    """Build full IOC relationship graph using pyvis."""
    G = nx.DiGraph()

    with db.get_db() as conn:
        iocs = conn.execute(
            "SELECT id, indicator, ioc_type, malware_family, country, pulse_id FROM iocs LIMIT ?",
            (max_nodes,)
        ).fetchall()
        rels = conn.execute(
            "SELECT source_ioc_id, target_ioc_id, relationship_type, confidence FROM ioc_relationships LIMIT 500"
        ).fetchall()
        pulses = conn.execute("SELECT id, name, adversary FROM pulses").fetchall()

    pulse_map = {p["id"]: dict(p) for p in pulses}
    ioc_map = {}

    for ioc in iocs:
        ioc = dict(ioc)
        node_id = f"ioc_{ioc['id']}"
        label = ioc["indicator"][:25] + ("…" if len(ioc["indicator"]) > 25 else "")
        color = TYPE_COLORS.get(ioc["ioc_type"], TYPE_COLORS["default"])
        shape = TYPE_SHAPES.get(ioc["ioc_type"], TYPE_SHAPES["default"])
        pulse_name = pulse_map.get(ioc["pulse_id"], {}).get("name", "Unknown")[:30]
        title = (
            f"<b>{ioc['indicator']}</b><br>"
            f"Type: {ioc['ioc_type']}<br>"
            f"Malware: {ioc['malware_family']}<br>"
            f"Country: {ioc['country']}<br>"
            f"Pulse: {pulse_name}"
        )
        G.add_node(node_id, label=label, color=color, shape=shape, title=title,
                   ioc_type=ioc["ioc_type"], size=18)
        ioc_map[ioc["id"]] = node_id

    for rel in rels:
        rel = dict(rel)
        src = ioc_map.get(rel["source_ioc_id"])
        tgt = ioc_map.get(rel["target_ioc_id"])
        if src and tgt and src != tgt:
            color = REL_COLORS.get(rel["relationship_type"], REL_COLORS["default"])
            G.add_edge(src, tgt, color=color, title=rel["relationship_type"],
                       width=max(1, rel["confidence"] // 25))

    net = Network(height="700px", width="100%", directed=True, bgcolor="#ffffff", font_color="#1e293b")
    net.from_nx(G)
    net.set_options(json.dumps({
        "physics": {
            "enabled": True,
            "barnesHut": {
                "gravitationalConstant": -4000,
                "centralGravity": 0.3,
                "springLength": 120,
                "springConstant": 0.04,
                "damping": 0.09
            },
            "stabilization": {"iterations": 150}
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 100,
            "navigationButtons": True,
            "keyboard": True
        },
        "edges": {
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.5}},
            "smooth": {"type": "dynamic"}
        }
    }))

    out_path = os.path.join(GRAPH_OUTPUT_DIR, "full_graph.html")
    net.save_graph(out_path)
    _inject_graph_styles(out_path)
    return out_path


def build_cluster_graph(cluster_id: int) -> str:
    """Build graph for a specific cluster."""
    with db.get_db() as conn:
        cluster = conn.execute(
            "SELECT * FROM relationship_clusters WHERE id=?", (cluster_id,)
        ).fetchone()
        if not cluster:
            return ""
        cluster = dict(cluster)
        ioc_ids = json.loads(cluster.get("ioc_ids", "[]"))
        if not ioc_ids:
            return ""

        placeholders = ",".join("?" * len(ioc_ids))
        iocs = conn.execute(
            f"SELECT * FROM iocs WHERE id IN ({placeholders})", ioc_ids
        ).fetchall()
        rels = conn.execute(
            f"""SELECT * FROM ioc_relationships
                WHERE source_ioc_id IN ({placeholders})
                OR target_ioc_id IN ({placeholders})""",
            ioc_ids + ioc_ids
        ).fetchall()

    G = nx.Graph()
    for ioc in iocs:
        ioc = dict(ioc)
        node_id = f"ioc_{ioc['id']}"
        label = ioc["indicator"][:20] + ("…" if len(ioc["indicator"]) > 20 else "")
        color = TYPE_COLORS.get(ioc["ioc_type"], TYPE_COLORS["default"])
        title = f"<b>{ioc['indicator']}</b><br>Type: {ioc['ioc_type']}<br>Malware: {ioc['malware_family']}"
        G.add_node(node_id, label=label, color=color, title=title, size=22)

    for rel in rels:
        rel = dict(rel)
        src = f"ioc_{rel['source_ioc_id']}"
        tgt = f"ioc_{rel['target_ioc_id']}"
        if G.has_node(src) and G.has_node(tgt):
            color = REL_COLORS.get(rel["relationship_type"], REL_COLORS["default"])
            G.add_edge(src, tgt, color=color, title=rel["relationship_type"])

    net = Network(height="500px", width="100%", bgcolor="#ffffff", font_color="#1e293b")
    net.from_nx(G)
    net.set_options(json.dumps({
        "physics": {"enabled": True, "stabilization": {"iterations": 100}},
        "interaction": {"hover": True, "tooltipDelay": 100}
    }))

    out_path = os.path.join(GRAPH_OUTPUT_DIR, f"cluster_{cluster_id}.html")
    net.save_graph(out_path)
    _inject_graph_styles(out_path)
    return out_path


def _inject_graph_styles(path: str):
    """Patch pyvis output to match dashboard light theme."""
    try:
        with open(path, "r") as f:
            html = f.read()
        html = html.replace(
            "background-color: #ffffff;",
            "background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;"
        )
        with open(path, "w") as f:
            f.write(html)
    except Exception:
        pass


def get_graph_stats() -> dict:
    """Return graph-level statistics for the dashboard."""
    with db.get_db() as conn:
        node_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        edge_count = conn.execute("SELECT COUNT(*) FROM ioc_relationships").fetchone()[0]
        cluster_count = conn.execute("SELECT COUNT(*) FROM relationship_clusters").fetchone()[0]
        cluster_types = conn.execute(
            "SELECT cluster_type, COUNT(*) as cnt FROM relationship_clusters GROUP BY cluster_type"
        ).fetchall()
        top_connected = conn.execute("""
            SELECT i.indicator, i.ioc_type, COUNT(*) as degree
            FROM ioc_relationships r
            JOIN iocs i ON r.source_ioc_id = i.id
            GROUP BY r.source_ioc_id
            ORDER BY degree DESC LIMIT 10
        """).fetchall()

    return {
        "node_count": node_count,
        "edge_count": edge_count,
        "cluster_count": cluster_count,
        "cluster_type_breakdown": [dict(r) for r in cluster_types],
        "top_connected_nodes": [dict(r) for r in top_connected],
    }
