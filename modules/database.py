"""
Database module for IOC Dashboard.
SQLite-backed, heavily normalized, zero null values enforced.
"""
import sqlite3
import json
import os
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ioc_data.db")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ──────────────────────────────────────────────────────────────
-- PULSES  (OTX threat-intel campaigns / reports)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pulses (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT 'Unknown Pulse',
    description     TEXT NOT NULL DEFAULT 'No description provided',
    author_name     TEXT NOT NULL DEFAULT 'Unknown Author',
    tlp             TEXT NOT NULL DEFAULT 'white' CHECK(tlp IN ('white','green','amber','red')),
    created         TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    modified        TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    tags            TEXT NOT NULL DEFAULT '[]',          -- JSON array
    ref_links       TEXT NOT NULL DEFAULT '[]',          -- JSON array
    malware_families TEXT NOT NULL DEFAULT '[]',         -- JSON array
    attack_ids      TEXT NOT NULL DEFAULT '[]',          -- JSON array
    industries      TEXT NOT NULL DEFAULT '[]',          -- JSON array
    targeted_countries TEXT NOT NULL DEFAULT '[]',       -- JSON array
    ioc_count       INTEGER NOT NULL DEFAULT 0,
    revision        INTEGER NOT NULL DEFAULT 1,
    public          INTEGER NOT NULL DEFAULT 1,
    adversary       TEXT NOT NULL DEFAULT 'Unknown',
    raw_json        TEXT NOT NULL DEFAULT '{}'
);

-- ──────────────────────────────────────────────────────────────
-- IOCs
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pulse_id        TEXT NOT NULL REFERENCES pulses(id) ON DELETE CASCADE,
    indicator       TEXT NOT NULL,
    ioc_type        TEXT NOT NULL DEFAULT 'unknown',
    title           TEXT NOT NULL DEFAULT 'Untitled',
    description     TEXT NOT NULL DEFAULT 'No description',
    created         TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    is_active       INTEGER NOT NULL DEFAULT 1,
    role            TEXT NOT NULL DEFAULT 'unknown',
    -- Enrichment columns (never null)
    country         TEXT NOT NULL DEFAULT 'Unknown',
    asn             TEXT NOT NULL DEFAULT 'Unknown',
    reputation      INTEGER NOT NULL DEFAULT 0,
    malware_family  TEXT NOT NULL DEFAULT 'Unknown',
    -- STIX
    stix_id         TEXT NOT NULL DEFAULT '',
    stix_type       TEXT NOT NULL DEFAULT 'indicator',
    stix_json       TEXT NOT NULL DEFAULT '{}',
    -- Stats
    first_seen      TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    last_seen       TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    hit_count       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(pulse_id, indicator, ioc_type)
);

-- ──────────────────────────────────────────────────────────────
-- IOC ENRICHMENT DETAILS
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_enrichment (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE UNIQUE,
    whois_registrar TEXT NOT NULL DEFAULT 'Unknown',
    whois_created   TEXT NOT NULL DEFAULT 'Unknown',
    whois_expires   TEXT NOT NULL DEFAULT 'Unknown',
    whois_org       TEXT NOT NULL DEFAULT 'Unknown',
    geo_city        TEXT NOT NULL DEFAULT 'Unknown',
    geo_region      TEXT NOT NULL DEFAULT 'Unknown',
    geo_country     TEXT NOT NULL DEFAULT 'Unknown',
    geo_latitude    REAL NOT NULL DEFAULT 0.0,
    geo_longitude   REAL NOT NULL DEFAULT 0.0,
    asn_number      TEXT NOT NULL DEFAULT 'Unknown',
    asn_name        TEXT NOT NULL DEFAULT 'Unknown',
    asn_cidr        TEXT NOT NULL DEFAULT '0.0.0.0/0',
    file_hash_md5   TEXT NOT NULL DEFAULT '',
    file_hash_sha1  TEXT NOT NULL DEFAULT '',
    file_hash_sha256 TEXT NOT NULL DEFAULT '',
    file_type       TEXT NOT NULL DEFAULT 'Unknown',
    file_size       INTEGER NOT NULL DEFAULT 0,
    url_domain      TEXT NOT NULL DEFAULT '',
    url_path        TEXT NOT NULL DEFAULT '',
    url_protocol    TEXT NOT NULL DEFAULT 'https',
    pulse_references TEXT NOT NULL DEFAULT '[]',
    raw_enrichment  TEXT NOT NULL DEFAULT '{}'
);

-- ──────────────────────────────────────────────────────────────
-- IOC RELATIONSHIPS
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_relationships (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ioc_id   INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    target_ioc_id   INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL DEFAULT 'related-to',
    confidence      INTEGER NOT NULL DEFAULT 50 CHECK(confidence BETWEEN 0 AND 100),
    description     TEXT NOT NULL DEFAULT 'Related IOCs',
    created         TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    UNIQUE(source_ioc_id, target_ioc_id, relationship_type)
);

-- ──────────────────────────────────────────────────────────────
-- RELATIONSHIP CLUSTERS (detected patterns)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS relationship_clusters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_type    TEXT NOT NULL DEFAULT 'generic',  -- ip_malware, asn_domain, hash_campaign, temporal
    cluster_name    TEXT NOT NULL DEFAULT 'Unnamed Cluster',
    description     TEXT NOT NULL DEFAULT 'No description',
    severity        TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('low','medium','high','critical')),
    ioc_ids         TEXT NOT NULL DEFAULT '[]',  -- JSON array of ioc ids
    metadata        TEXT NOT NULL DEFAULT '{}',
    detected_at     TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'
);

-- ──────────────────────────────────────────────────────────────
-- DETECTION RULES
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type       TEXT NOT NULL DEFAULT 'sigma' CHECK(rule_type IN ('sigma','yara','suricata','snort')),
    rule_name       TEXT NOT NULL DEFAULT 'Unnamed Rule',
    rule_content    TEXT NOT NULL DEFAULT '',
    ioc_id          INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    pulse_id        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT 'Auto-generated detection rule',
    severity        TEXT NOT NULL DEFAULT 'medium',
    tags            TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    is_valid        INTEGER NOT NULL DEFAULT 1
);

-- ──────────────────────────────────────────────────────────────
-- STIX BUNDLES (stored complete bundles)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS stix_bundles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id       TEXT NOT NULL UNIQUE DEFAULT '',
    pulse_id        TEXT NOT NULL DEFAULT '',
    bundle_json     TEXT NOT NULL DEFAULT '{}',
    object_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'
);

-- ──────────────────────────────────────────────────────────────
-- SYNC LOG
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sync_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_type       TEXT NOT NULL DEFAULT 'otx_fetch',
    status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','success','error')),
    started_at      TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    completed_at    TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    pulses_fetched  INTEGER NOT NULL DEFAULT 0,
    iocs_fetched    INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT NOT NULL DEFAULT ''
);

-- ──────────────────────────────────────────────────────────────
-- INDEXES for performance
-- ──────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_iocs_type        ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_pulse       ON iocs(pulse_id);
CREATE INDEX IF NOT EXISTS idx_iocs_indicator   ON iocs(indicator);
CREATE INDEX IF NOT EXISTS idx_iocs_country     ON iocs(country);
CREATE INDEX IF NOT EXISTS idx_iocs_asn         ON iocs(asn);
CREATE INDEX IF NOT EXISTS idx_iocs_malware     ON iocs(malware_family);
CREATE INDEX IF NOT EXISTS idx_rels_source      ON ioc_relationships(source_ioc_id);
CREATE INDEX IF NOT EXISTS idx_rels_target      ON ioc_relationships(target_ioc_id);
CREATE INDEX IF NOT EXISTS idx_rules_type       ON detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_rules_ioc        ON detection_rules(ioc_id);

-- ──────────────────────────────────────────────────────────────
-- VIEWS for dashboard queries
-- ──────────────────────────────────────────────────────────────
CREATE VIEW IF NOT EXISTS v_ioc_summary AS
SELECT
    i.id,
    i.pulse_id,
    p.name          AS pulse_name,
    p.adversary,
    i.indicator,
    i.ioc_type,
    i.title,
    i.description,
    i.country,
    i.asn,
    i.reputation,
    i.malware_family,
    i.created,
    i.first_seen,
    i.last_seen,
    i.stix_id,
    i.stix_type,
    i.is_active,
    p.tlp,
    p.tags          AS pulse_tags
FROM iocs i
JOIN pulses p ON i.pulse_id = p.id;

CREATE VIEW IF NOT EXISTS v_stats AS
SELECT
    (SELECT COUNT(*) FROM iocs)                             AS total_iocs,
    (SELECT COUNT(*) FROM pulses)                           AS total_pulses,
    (SELECT COUNT(*) FROM iocs WHERE ioc_type='IPv4')       AS ip_count,
    (SELECT COUNT(*) FROM iocs WHERE ioc_type='domain')     AS domain_count,
    (SELECT COUNT(*) FROM iocs WHERE ioc_type LIKE '%hash%' OR ioc_type LIKE 'FileHash%') AS hash_count,
    (SELECT COUNT(*) FROM iocs WHERE ioc_type='URL')        AS url_count,
    (SELECT COUNT(*) FROM detection_rules)                  AS rule_count,
    (SELECT COUNT(*) FROM ioc_relationships)                AS relationship_count,
    (SELECT COUNT(*) FROM relationship_clusters)            AS cluster_count;
"""


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
    print(f"[DB] Initialized at {DB_PATH}")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── PULSE CRUD ──────────────────────────────────────────────────────────────

def upsert_pulse(pulse: dict) -> str:
    sql = """
    INSERT INTO pulses (id, name, description, author_name, tlp, created, modified,
        tags, ref_links, malware_families, attack_ids, industries,
        targeted_countries, ioc_count, revision, public, adversary, raw_json)
    VALUES (:id,:name,:description,:author_name,:tlp,:created,:modified,
        :tags,:ref_links,:malware_families,:attack_ids,:industries,
        :targeted_countries,:ioc_count,:revision,:public,:adversary,:raw_json)
    ON CONFLICT(id) DO UPDATE SET
        name=excluded.name, description=excluded.description,
        modified=excluded.modified, ioc_count=excluded.ioc_count,
        tags=excluded.tags, malware_families=excluded.malware_families,
        raw_json=excluded.raw_json
    """
    with get_db() as conn:
        conn.execute(sql, pulse)
    return pulse["id"]


def get_all_pulses(limit=50, offset=0):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM pulses ORDER BY modified DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    return [dict(r) for r in rows]


def get_pulse_by_id(pid: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM pulses WHERE id=?", (pid,)).fetchone()
    return dict(row) if row else None


# ─── IOC CRUD ────────────────────────────────────────────────────────────────

def upsert_ioc(ioc: dict) -> int:
    sql = """
    INSERT INTO iocs (pulse_id, indicator, ioc_type, title, description, created,
        is_active, role, country, asn, reputation, malware_family,
        stix_id, stix_type, stix_json, first_seen, last_seen, hit_count)
    VALUES (:pulse_id,:indicator,:ioc_type,:title,:description,:created,
        :is_active,:role,:country,:asn,:reputation,:malware_family,
        :stix_id,:stix_type,:stix_json,:first_seen,:last_seen,:hit_count)
    ON CONFLICT(pulse_id, indicator, ioc_type) DO UPDATE SET
        title=excluded.title, description=excluded.description,
        country=excluded.country, asn=excluded.asn,
        reputation=excluded.reputation, malware_family=excluded.malware_family,
        stix_id=excluded.stix_id, stix_type=excluded.stix_type,
        stix_json=excluded.stix_json, last_seen=excluded.last_seen,
        hit_count=iocs.hit_count+1
    RETURNING id
    """
    with get_db() as conn:
        row = conn.execute(sql, ioc).fetchone()
        return row[0] if row else None


def upsert_enrichment(enrichment: dict):
    sql = """
    INSERT INTO ioc_enrichment (ioc_id, whois_registrar, whois_created, whois_expires,
        whois_org, geo_city, geo_region, geo_country, geo_latitude, geo_longitude,
        asn_number, asn_name, asn_cidr, file_hash_md5, file_hash_sha1,
        file_hash_sha256, file_type, file_size, url_domain, url_path,
        url_protocol, pulse_references, raw_enrichment)
    VALUES (:ioc_id,:whois_registrar,:whois_created,:whois_expires,
        :whois_org,:geo_city,:geo_region,:geo_country,:geo_latitude,:geo_longitude,
        :asn_number,:asn_name,:asn_cidr,:file_hash_md5,:file_hash_sha1,
        :file_hash_sha256,:file_type,:file_size,:url_domain,:url_path,
        :url_protocol,:pulse_references,:raw_enrichment)
    ON CONFLICT(ioc_id) DO UPDATE SET
        whois_registrar=excluded.whois_registrar, geo_city=excluded.geo_city,
        geo_country=excluded.geo_country, asn_number=excluded.asn_number,
        asn_name=excluded.asn_name, raw_enrichment=excluded.raw_enrichment
    """
    with get_db() as conn:
        conn.execute(sql, enrichment)


def get_iocs_paginated(page=1, per_page=25, ioc_type=None, search=None, pulse_id=None):
    conditions = ["1=1"]
    params = []
    if ioc_type:
        conditions.append("ioc_type=?")
        params.append(ioc_type)
    if search:
        conditions.append("(indicator LIKE ? OR title LIKE ? OR malware_family LIKE ?)")
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]
    if pulse_id:
        conditions.append("pulse_id=?")
        params.append(pulse_id)

    where = " AND ".join(conditions)
    offset = (page - 1) * per_page

    with get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM v_ioc_summary WHERE {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM v_ioc_summary WHERE {where} ORDER BY created DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()
    return {"total": total, "page": page, "per_page": per_page, "data": [dict(r) for r in rows]}


def get_ioc_detail(ioc_id: int):
    with get_db() as conn:
        ioc = conn.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not ioc:
            return None
        enrichment = conn.execute("SELECT * FROM ioc_enrichment WHERE ioc_id=?", (ioc_id,)).fetchone()
        rules = conn.execute("SELECT * FROM detection_rules WHERE ioc_id=?", (ioc_id,)).fetchall()
        rels = conn.execute("""
            SELECT r.*, i2.indicator AS related_indicator, i2.ioc_type AS related_type
            FROM ioc_relationships r
            JOIN iocs i2 ON r.target_ioc_id = i2.id
            WHERE r.source_ioc_id=?
        """, (ioc_id,)).fetchall()

    return {
        "ioc": dict(ioc),
        "enrichment": dict(enrichment) if enrichment else {},
        "rules": [dict(r) for r in rules],
        "relationships": [dict(r) for r in rels]
    }


# ─── RELATIONSHIP CRUD ───────────────────────────────────────────────────────

def insert_relationship(rel: dict):
    sql = """
    INSERT OR IGNORE INTO ioc_relationships
        (source_ioc_id, target_ioc_id, relationship_type, confidence, description, created)
    VALUES (:source_ioc_id,:target_ioc_id,:relationship_type,:confidence,:description,:created)
    """
    with get_db() as conn:
        conn.execute(sql, rel)


def insert_cluster(cluster: dict):
    sql = """
    INSERT OR REPLACE INTO relationship_clusters
        (cluster_type, cluster_name, description, severity, ioc_ids, metadata, detected_at)
    VALUES (:cluster_type,:cluster_name,:description,:severity,:ioc_ids,:metadata,:detected_at)
    """
    with get_db() as conn:
        conn.execute(sql, cluster)


def get_all_clusters():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM relationship_clusters ORDER BY detected_at DESC").fetchall()
    return [dict(r) for r in rows]


# ─── RULE CRUD ───────────────────────────────────────────────────────────────

def insert_rule(rule: dict):
    sql = """
    INSERT OR IGNORE INTO detection_rules
        (rule_type, rule_name, rule_content, ioc_id, pulse_id, description,
         severity, tags, created_at, is_valid)
    VALUES (:rule_type,:rule_name,:rule_content,:ioc_id,:pulse_id,:description,
        :severity,:tags,:created_at,:is_valid)
    """
    with get_db() as conn:
        conn.execute(sql, rule)


def get_rules(rule_type=None, limit=100):
    with get_db() as conn:
        if rule_type:
            rows = conn.execute(
                "SELECT * FROM detection_rules WHERE rule_type=? ORDER BY created_at DESC LIMIT ?",
                (rule_type, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM detection_rules ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


# ─── STIX BUNDLE CRUD ────────────────────────────────────────────────────────

def store_stix_bundle(bundle: dict):
    sql = """
    INSERT OR REPLACE INTO stix_bundles (bundle_id, pulse_id, bundle_json, object_count, created_at)
    VALUES (:bundle_id,:pulse_id,:bundle_json,:object_count,:created_at)
    """
    with get_db() as conn:
        conn.execute(sql, bundle)


# ─── STATS ───────────────────────────────────────────────────────────────────

def get_stats():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM v_stats").fetchone()
        type_dist = conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC"
        ).fetchall()
        country_dist = conn.execute(
            "SELECT country, COUNT(*) as cnt FROM iocs GROUP BY country ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        malware_dist = conn.execute(
            "SELECT malware_family, COUNT(*) as cnt FROM iocs GROUP BY malware_family ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        recent_iocs = conn.execute(
            "SELECT * FROM v_ioc_summary ORDER BY created DESC LIMIT 5"
        ).fetchall()
        asn_dist = conn.execute(
            "SELECT asn, COUNT(*) as cnt FROM iocs WHERE asn != 'Unknown' GROUP BY asn ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        timeline = conn.execute(
            """SELECT substr(created,1,10) as day, COUNT(*) as cnt
               FROM iocs GROUP BY day ORDER BY day DESC LIMIT 30"""
        ).fetchall()

    return {
        "summary": dict(row) if row else {},
        "type_distribution": [dict(r) for r in type_dist],
        "country_distribution": [dict(r) for r in country_dist],
        "malware_distribution": [dict(r) for r in malware_dist],
        "recent_iocs": [dict(r) for r in recent_iocs],
        "asn_distribution": [dict(r) for r in asn_dist],
        "timeline": [dict(r) for r in timeline],
    }


# ─── GRAPH DATA ──────────────────────────────────────────────────────────────

def get_relationship_graph_data(limit=200):
    with get_db() as conn:
        nodes_raw = conn.execute(
            "SELECT id, indicator, ioc_type, malware_family, country, reputation FROM iocs LIMIT ?",
            (limit,)
        ).fetchall()
        edges_raw = conn.execute(
            """SELECT source_ioc_id, target_ioc_id, relationship_type, confidence
               FROM ioc_relationships LIMIT ?""",
            (limit * 2,)
        ).fetchall()
    return {
        "nodes": [dict(r) for r in nodes_raw],
        "edges": [dict(r) for r in edges_raw]
    }


# ─── SYNC LOG ────────────────────────────────────────────────────────────────

def log_sync(sync_type="otx_fetch") -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO sync_log (sync_type, status, started_at, completed_at) VALUES (?,?,?,?)",
            (sync_type, "running", now_iso(), now_iso())
        )
        return cur.lastrowid


def update_sync_log(log_id: int, status: str, pulses=0, iocs=0, error=""):
    with get_db() as conn:
        conn.execute(
            """UPDATE sync_log SET status=?, completed_at=?,
               pulses_fetched=?, iocs_fetched=?, error_message=? WHERE id=?""",
            (status, now_iso(), pulses, iocs, error, log_id)
        )


def get_sync_history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sync_log ORDER BY started_at DESC LIMIT 20").fetchall()
    return [dict(r) for r in rows]
