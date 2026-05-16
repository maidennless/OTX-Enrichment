"""
Flask web application for IOC Dashboard.
All routes are database-heavy — minimal business logic in the view layer.
"""
import json
import os

from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS

from modules import database as db
from modules import otx_fetcher
from modules import relationship_engine
from modules import rule_generator

app = Flask(__name__)
CORS(app)

GRAPH_DIR = os.path.join(os.path.dirname(__file__), "static", "graphs")


# ─── INIT ────────────────────────────────────────────────────────────────────

@app.before_request
def ensure_db():
    db.init_db()


# ─── MAIN PAGES ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/static/graphs/<path:filename>")
def serve_graph(filename):
    return send_from_directory(GRAPH_DIR, filename)


# ─── STATS & DASHBOARD ───────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/sync/history")
def api_sync_history():
    return jsonify(db.get_sync_history())


# ─── IOC ENDPOINTS ───────────────────────────────────────────────────────────

@app.route("/api/iocs")
def api_iocs():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    ioc_type = request.args.get("type", None)
    search = request.args.get("search", None)
    pulse_id = request.args.get("pulse_id", None)
    return jsonify(db.get_iocs_paginated(page, per_page, ioc_type, search, pulse_id))


@app.route("/api/iocs/<int:ioc_id>")
def api_ioc_detail(ioc_id):
    detail = db.get_ioc_detail(ioc_id)
    if not detail:
        return jsonify({"error": "IOC not found"}), 404
    return jsonify(detail)


@app.route("/api/iocs/<int:ioc_id>/rules")
def api_ioc_rules(ioc_id):
    rules = rule_generator.generate_rules_for_ioc(ioc_id)
    return jsonify(rules)


@app.route("/api/iocs/<int:ioc_id>/stix")
def api_ioc_stix(ioc_id):
    detail = db.get_ioc_detail(ioc_id)
    if not detail:
        return jsonify({"error": "IOC not found"}), 404
    stix_json = detail["ioc"].get("stix_json", "{}")
    try:
        return jsonify(json.loads(stix_json))
    except Exception:
        return jsonify({})


# ─── PULSE ENDPOINTS ─────────────────────────────────────────────────────────

@app.route("/api/pulses")
def api_pulses():
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    return jsonify(db.get_all_pulses(limit, offset))


@app.route("/api/pulses/<pulse_id>")
def api_pulse_detail(pulse_id):
    pulse = db.get_pulse_by_id(pulse_id)
    if not pulse:
        return jsonify({"error": "Pulse not found"}), 404
    # Also attach its IOCs
    iocs = db.get_iocs_paginated(1, 100, pulse_id=pulse_id)
    return jsonify({"pulse": pulse, "iocs": iocs})


@app.route("/api/pulses/<pulse_id>/stix-bundle")
def api_pulse_stix_bundle(pulse_id):
    with db.get_db() as conn:
        row = conn.execute(
            "SELECT bundle_json FROM stix_bundles WHERE pulse_id=?", (pulse_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "No STIX bundle for this pulse"}), 404
    try:
        return jsonify(json.loads(row["bundle_json"]))
    except Exception:
        return jsonify({"error": "Invalid bundle JSON"}), 500


# ─── INGEST ENDPOINTS ────────────────────────────────────────────────────────

@app.route("/api/ingest/otx", methods=["POST"])
def api_ingest_otx():
    data = request.get_json() or {}
    api_key = data.get("api_key", "").strip()
    days_back = int(data.get("days_back", 30))
    if not api_key:
        return jsonify({"error": "api_key is required"}), 400
    result = otx_fetcher.ingest_otx(api_key, days_back=days_back)
    return jsonify(result)


@app.route("/api/ingest/demo", methods=["POST"])
def api_ingest_demo():
    result = otx_fetcher.load_demo_data()
    return jsonify(result)


# ─── RELATIONSHIP / GRAPH ENDPOINTS ──────────────────────────────────────────

@app.route("/api/relationships/detect", methods=["POST"])
def api_detect_relationships():
    result = relationship_engine.run_all_detectors()
    return jsonify(result)


@app.route("/api/relationships/clusters")
def api_clusters():
    return jsonify(db.get_all_clusters())


@app.route("/api/relationships/graph-data")
def api_graph_data():
    return jsonify(db.get_relationship_graph_data())


@app.route("/api/relationships/graph-stats")
def api_graph_stats():
    return jsonify(relationship_engine.get_graph_stats())


@app.route("/api/relationships/build-graph", methods=["POST"])
def api_build_graph():
    relationship_engine.build_full_graph(max_nodes=150)
    return jsonify({"status": "ok", "path": "/static/graphs/full_graph.html"})


@app.route("/api/relationships/cluster-graph/<int:cluster_id>", methods=["POST"])
def api_cluster_graph(cluster_id):
    path = relationship_engine.build_cluster_graph(cluster_id)
    if path:
        fname = os.path.basename(path)
        return jsonify({"status": "ok", "path": f"/static/graphs/{fname}"})
    return jsonify({"error": "Could not build cluster graph"}), 500


# ─── DETECTION RULES ─────────────────────────────────────────────────────────

@app.route("/api/rules")
def api_rules():
    rule_type = request.args.get("type", None)
    limit = int(request.args.get("limit", 100))
    return jsonify(db.get_rules(rule_type, limit))


@app.route("/api/rules/summary")
def api_rules_summary():
    return jsonify(rule_generator.get_rules_summary())


@app.route("/api/rules/generate-all", methods=["POST"])
def api_generate_all_rules():
    result = rule_generator.generate_all_rules()
    return jsonify(result)


@app.route("/api/rules/<int:rule_id>")
def api_rule_detail(rule_id):
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM detection_rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(dict(row))


# ─── STIX BUNDLES ────────────────────────────────────────────────────────────

@app.route("/api/stix/bundles")
def api_stix_bundles():
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, bundle_id, pulse_id, object_count, created_at FROM stix_bundles ORDER BY created_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5000, host="0.0.0.0")
