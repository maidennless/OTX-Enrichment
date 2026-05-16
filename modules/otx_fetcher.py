"""
OTX → STIX converter and IOC fetcher.
Pulls threat intel from AlienVault OTX, converts to STIX 2.1,
and stores everything in SQLite via the database module.
"""
import json
import re
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
import stix2

from modules import database as db

# ─── OTX API HELPERS ─────────────────────────────────────────────────────────

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _headers(api_key: str) -> dict:
    return {"X-OTX-API-KEY": api_key, "Content-Type": "application/json"}


def fetch_subscribed_pulses(api_key: str, days_back: int = 30, max_pages: int = 5) -> list:
    """Fetch pulses from OTX subscribed feed."""
    since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S")
    pulses = []
    page = 1
    while page <= max_pages:
        url = f"{OTX_BASE}/pulses/subscribed?modified_since={since}&page={page}&limit=20"
        try:
            r = requests.get(url, headers=_headers(api_key), timeout=30)
            r.raise_for_status()
            data = r.json()
            batch = data.get("results", [])
            pulses.extend(batch)
            if not data.get("next"):
                break
            page += 1
        except Exception as e:
            print(f"[OTX] Error on page {page}: {e}")
            break
    return pulses


def fetch_pulse_detail(api_key: str, pulse_id: str) -> dict:
    url = f"{OTX_BASE}/pulses/{pulse_id}"
    try:
        r = requests.get(url, headers=_headers(api_key), timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[OTX] Failed to fetch pulse {pulse_id}: {e}")
        return {}


def fetch_indicator_details(api_key: str, ioc_type: str, indicator: str) -> dict:
    """Fetch enrichment details for an IOC."""
    type_map = {
        "IPv4": "IPv4",
        "domain": "domain",
        "hostname": "hostname",
        "URL": "url",
        "FileHash-MD5": "file",
        "FileHash-SHA1": "file",
        "FileHash-SHA256": "file",
    }
    otx_type = type_map.get(ioc_type, "")
    if not otx_type:
        return {}
    url = f"{OTX_BASE}/indicators/{otx_type}/{indicator}/general"
    try:
        r = requests.get(url, headers=_headers(api_key), timeout=20)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ─── NORMALIZATION ───────────────────────────────────────────────────────────

def _safe_str(v, default="Unknown") -> str:
    if v is None or v == "":
        return default
    return str(v).strip() or default


def _safe_json(v, default="[]") -> str:
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    if isinstance(v, str):
        try:
            json.loads(v)
            return v
        except Exception:
            return default
    return default


def _safe_date(v, default="1970-01-01T00:00:00Z") -> str:
    if not v:
        return default
    v = str(v)
    # Try common formats
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(v[:19], fmt[:len(fmt)])
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return default


def normalize_pulse(raw: dict) -> dict:
    return {
        "id": _safe_str(raw.get("id"), f"pulse-{uuid.uuid4()}"),
        "name": _safe_str(raw.get("name"), "Unknown Pulse"),
        "description": _safe_str(raw.get("description"), "No description provided"),
        "author_name": _safe_str(raw.get("author_name"), "Unknown Author"),
        "tlp": _safe_str(raw.get("tlp", "white")).lower() if raw.get("tlp", "white") in ["white","green","amber","red"] else "white",
        "created": _safe_date(raw.get("created")),
        "modified": _safe_date(raw.get("modified")),
        "tags": _safe_json(raw.get("tags", [])),
        "ref_links": _safe_json(raw.get("references", [])),
        "malware_families": _safe_json(raw.get("malware_families", [])),
        "attack_ids": _safe_json(raw.get("attack_ids", [])),
        "industries": _safe_json(raw.get("industries", [])),
        "targeted_countries": _safe_json(raw.get("targeted_countries", [])),
        "ioc_count": int(raw.get("indicator_count", 0) or 0),
        "revision": int(raw.get("revision", 1) or 1),
        "public": 1 if raw.get("public", True) else 0,
        "adversary": _safe_str(raw.get("adversary"), "Unknown"),
        "raw_json": json.dumps(raw),
    }


def normalize_ioc(raw: dict, pulse_id: str, pulse: dict) -> dict:
    itype = _safe_str(raw.get("type"), "unknown")
    malware = "Unknown"
    mfams = pulse.get("malware_families", [])
    if isinstance(mfams, str):
        try:
            mfams = json.loads(mfams)
        except Exception:
            mfams = []
    if mfams:
        malware = _safe_str(mfams[0] if isinstance(mfams[0], str) else mfams[0].get("display_name","Unknown"), "Unknown")

    return {
        "pulse_id": pulse_id,
        "indicator": _safe_str(raw.get("indicator"), "unknown"),
        "ioc_type": itype,
        "title": _safe_str(raw.get("title"), f"{itype} indicator"),
        "description": _safe_str(raw.get("description"), "Indicator from OTX pulse"),
        "created": _safe_date(raw.get("created")),
        "is_active": 1 if raw.get("is_active", True) else 0,
        "role": _safe_str(raw.get("role"), "unknown"),
        "country": "Unknown",
        "asn": "Unknown",
        "reputation": 0,
        "malware_family": malware,
        "stix_id": "",
        "stix_type": "indicator",
        "stix_json": "{}",
        "first_seen": _safe_date(raw.get("created")),
        "last_seen": _safe_date(raw.get("created")),
        "hit_count": 0,
    }


def normalize_enrichment(ioc_id: int, ioc_indicator: str, ioc_type: str, raw: dict) -> dict:
    geo = raw.get("country_code", {}) or {}
    if isinstance(geo, str):
        geo = {}

    asn_raw = _safe_str(raw.get("asn", ""), "Unknown")

    # Parse URL components
    url_domain = url_path = ""
    url_protocol = "https"
    if ioc_type == "URL":
        try:
            p = urlparse(ioc_indicator)
            url_domain = p.netloc or ""
            url_path = p.path or ""
            url_protocol = p.scheme or "https"
        except Exception:
            pass

    pulse_refs = raw.get("pulse_info", {})
    if isinstance(pulse_refs, dict):
        pulse_refs = pulse_refs.get("pulses", [])

    return {
        "ioc_id": ioc_id,
        "whois_registrar": _safe_str(raw.get("whois_registrar"), "Unknown"),
        "whois_created": _safe_str(raw.get("whois_created"), "Unknown"),
        "whois_expires": _safe_str(raw.get("whois_expires"), "Unknown"),
        "whois_org": _safe_str(raw.get("whois_org"), "Unknown"),
        "geo_city": _safe_str(raw.get("city"), "Unknown"),
        "geo_region": _safe_str(raw.get("region"), "Unknown"),
        "geo_country": _safe_str(raw.get("country_name"), "Unknown"),
        "geo_latitude": float(raw.get("latitude") or 0.0),
        "geo_longitude": float(raw.get("longitude") or 0.0),
        "asn_number": asn_raw.split(" ")[0] if asn_raw != "Unknown" else "Unknown",
        "asn_name": " ".join(asn_raw.split(" ")[1:]) if " " in asn_raw else "Unknown",
        "asn_cidr": _safe_str(raw.get("cidr"), "0.0.0.0/0"),
        "file_hash_md5": _safe_str(raw.get("md5"), ""),
        "file_hash_sha1": _safe_str(raw.get("sha1"), ""),
        "file_hash_sha256": _safe_str(raw.get("sha256"), ""),
        "file_type": _safe_str(raw.get("file_type"), "Unknown"),
        "file_size": int(raw.get("filesize") or 0),
        "url_domain": url_domain,
        "url_path": url_path,
        "url_protocol": url_protocol,
        "pulse_references": json.dumps(pulse_refs[:5] if isinstance(pulse_refs, list) else []),
        "raw_enrichment": json.dumps(raw),
    }


# ─── STIX CONVERSION ─────────────────────────────────────────────────────────

def ioc_to_stix_pattern(ioc_type: str, indicator: str) -> str:
    """Convert OTX IOC type + value to a STIX 2.1 pattern string."""
    type_map = {
        "IPv4": f"[ipv4-addr:value = '{indicator}']",
        "IPv6": f"[ipv6-addr:value = '{indicator}']",
        "domain": f"[domain-name:value = '{indicator}']",
        "hostname": f"[domain-name:value = '{indicator}']",
        "URL": f"[url:value = '{indicator}']",
        "FileHash-MD5": f"[file:hashes.'MD5' = '{indicator}']",
        "FileHash-SHA1": f"[file:hashes.'SHA-1' = '{indicator}']",
        "FileHash-SHA256": f"[file:hashes.'SHA-256' = '{indicator}']",
        "email": f"[email-addr:value = '{indicator}']",
        "CIDR": f"[ipv4-addr:value = '{indicator}']",
        "Mutex": f"[mutex:name = '{indicator}']",
        "CVE": f"[vulnerability:name = '{indicator}']",
    }
    return type_map.get(ioc_type, f"[artifact:payload_bin = '{indicator}']")


def build_stix_indicator(ioc_row: dict, pulse_row: dict) -> stix2.Indicator:
    pattern = ioc_to_stix_pattern(ioc_row["ioc_type"], ioc_row["indicator"])
    try:
        indicator = stix2.Indicator(
            name=_safe_str(ioc_row.get("title"), ioc_row["indicator"])[:128],
            description=_safe_str(ioc_row.get("description"), "OTX indicator"),
            pattern=pattern,
            pattern_type="stix",
            valid_from=ioc_row.get("first_seen", "1970-01-01T00:00:00Z"),
            labels=[ioc_row.get("malware_family", "unknown").lower().replace(" ", "-")],
            confidence=50,
            external_references=[
                stix2.ExternalReference(
                    source_name="AlienVault OTX",
                    url=f"https://otx.alienvault.com/pulse/{ioc_row['pulse_id']}",
                    external_id=ioc_row["pulse_id"],
                )
            ],
        )
        return indicator
    except Exception as e:
        print(f"[STIX] Error building indicator for {ioc_row['indicator']}: {e}")
        return None


def build_stix_bundle(pulse_row: dict, ioc_rows: list) -> dict:
    """Build a full STIX 2.1 bundle from a pulse and its IOCs."""
    objects = []
    identity = stix2.Identity(
        name=_safe_str(pulse_row.get("author_name"), "AlienVault OTX"),
        identity_class="organization",
    )
    objects.append(identity)

    malware_obj = None
    mfam = pulse_row.get("malware_families", "[]")
    if isinstance(mfam, str):
        try:
            mfam = json.loads(mfam)
        except Exception:
            mfam = []
    if mfam:
        fname = mfam[0] if isinstance(mfam[0], str) else mfam[0].get("display_name", "Unknown")
        try:
            malware_obj = stix2.Malware(
                name=fname,
                is_family=True,
                description=f"Malware family referenced in pulse: {pulse_row.get('name','')}",
            )
            objects.append(malware_obj)
        except Exception:
            pass

    indicator_objects = []
    for ioc_row in ioc_rows:
        ind = build_stix_indicator(ioc_row, pulse_row)
        if ind:
            indicator_objects.append(ind)
            objects.append(ind)
            if malware_obj:
                rel = stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=ind.id,
                    target_ref=malware_obj.id,
                )
                objects.append(rel)

    try:
        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        return json.loads(bundle.serialize())
    except Exception as e:
        print(f"[STIX] Bundle error: {e}")
        return {"type": "bundle", "objects": []}


# ─── MAIN INGEST ─────────────────────────────────────────────────────────────

def ingest_otx(api_key: str, days_back: int = 30, enrich: bool = True) -> dict:
    """Full ingest: fetch OTX → normalize → store in DB → build STIX bundles."""
    log_id = db.log_sync("otx_fetch")
    total_pulses = 0
    total_iocs = 0

    try:
        raw_pulses = fetch_subscribed_pulses(api_key, days_back=days_back)

        for raw_pulse in raw_pulses:
            pulse = normalize_pulse(raw_pulse)
            db.upsert_pulse(pulse)
            total_pulses += 1

            indicators = raw_pulse.get("indicators", [])
            ioc_rows = []

            for raw_ioc in indicators:
                ioc = normalize_ioc(raw_ioc, pulse["id"], pulse)
                ioc_id = db.upsert_ioc(ioc)
                if ioc_id is None:
                    continue
                total_iocs += 1
                ioc["id"] = ioc_id

                # Enrich first 5 per pulse to avoid rate limits
                if enrich and len(ioc_rows) < 5:
                    raw_enrich = fetch_indicator_details(api_key, ioc["ioc_type"], ioc["indicator"])
                    enrichment = normalize_enrichment(ioc_id, ioc["indicator"], ioc["ioc_type"], raw_enrich)
                    db.upsert_enrichment(enrichment)
                    # Update country/asn back on ioc row
                    if raw_enrich.get("country_name") or raw_enrich.get("asn"):
                        with db.get_db() as conn:
                            conn.execute(
                                "UPDATE iocs SET country=?, asn=? WHERE id=?",
                                (
                                    _safe_str(raw_enrich.get("country_name"), "Unknown"),
                                    _safe_str(raw_enrich.get("asn"), "Unknown"),
                                    ioc_id
                                )
                            )
                else:
                    # Insert blank enrichment to keep zero nulls
                    try:
                        db.upsert_enrichment(normalize_enrichment(ioc_id, ioc["indicator"], ioc["ioc_type"], {}))
                    except Exception:
                        pass

                # Build STIX for this IOC
                stix_ind = build_stix_indicator(ioc, pulse)
                if stix_ind:
                    stix_dict = json.loads(stix_ind.serialize())
                    with db.get_db() as conn:
                        conn.execute(
                            "UPDATE iocs SET stix_id=?, stix_json=? WHERE id=?",
                            (stix_ind.id, json.dumps(stix_dict), ioc_id)
                        )
                ioc_rows.append(ioc)

            # Build & store STIX bundle for this pulse
            bundle = build_stix_bundle(pulse, ioc_rows)
            db.store_stix_bundle({
                "bundle_id": f"bundle--{pulse['id']}",
                "pulse_id": pulse["id"],
                "bundle_json": json.dumps(bundle),
                "object_count": len(bundle.get("objects", [])),
                "created_at": db.now_iso(),
            })

        db.update_sync_log(log_id, "success", total_pulses, total_iocs)
        return {"status": "success", "pulses": total_pulses, "iocs": total_iocs}

    except Exception as e:
        db.update_sync_log(log_id, "error", total_pulses, total_iocs, str(e))
        return {"status": "error", "error": str(e)}


def load_demo_data(api_key: str = ""):
    """Load demo data when OTX key isn't available or for testing."""
    import random

    sample_pulses = [
        {
            "id": "demo-pulse-001",
            "name": "APT29 - Cozy Bear Infrastructure",
            "description": "C2 infrastructure linked to Russian APT29 group targeting government entities",
            "author_name": "AlienVault",
            "tlp": "white",
            "created": "2024-12-01T10:00:00Z",
            "modified": "2025-01-15T10:00:00Z",
            "tags": ["apt29", "russia", "government", "espionage"],
            "references": ["https://example.com/report1"],
            "malware_families": ["SUNBURST", "Cobalt Strike"],
            "attack_ids": ["T1566", "T1071"],
            "industries": ["Government", "Defense"],
            "targeted_countries": ["US", "EU"],
            "adversary": "APT29",
            "indicators": [
                {"type": "IPv4", "indicator": "185.220.101.45", "title": "C2 Server", "description": "Known C2 endpoint"},
                {"type": "IPv4", "indicator": "194.165.16.29", "title": "Exfil Server", "description": "Data exfiltration server"},
                {"type": "domain", "indicator": "update-service.net", "title": "C2 Domain", "description": "Domain mimicking update service"},
                {"type": "domain", "indicator": "microsoft-cdn.info", "title": "Phishing Domain", "description": "Typosquatting Microsoft"},
                {"type": "FileHash-SHA256", "indicator": "a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4", "title": "SUNBURST DLL", "description": "Backdoor DLL"},
                {"type": "URL", "indicator": "https://update-service.net/solarwinds/update.php", "title": "Malware Drop URL", "description": "Payload delivery URL"},
            ]
        },
        {
            "id": "demo-pulse-002",
            "name": "LockBit 3.0 Ransomware Campaign",
            "description": "LockBit ransomware infrastructure targeting healthcare sector",
            "author_name": "CISA",
            "tlp": "green",
            "created": "2025-01-05T08:00:00Z",
            "modified": "2025-02-20T08:00:00Z",
            "tags": ["ransomware", "lockbit", "healthcare", "extortion"],
            "references": [],
            "malware_families": ["LockBit"],
            "attack_ids": ["T1486", "T1490"],
            "industries": ["Healthcare"],
            "targeted_countries": ["US", "UK", "AU"],
            "adversary": "LockBit Group",
            "indicators": [
                {"type": "IPv4", "indicator": "45.142.212.100", "title": "LockBit C2", "description": "C2 server"},
                {"type": "IPv4", "indicator": "185.220.101.45", "title": "Shared C2", "description": "Also used by APT29"},
                {"type": "domain", "indicator": "lockbit-news.onion.ly", "title": "Leak Site Mirror", "description": "Extortion site"},
                {"type": "FileHash-MD5", "indicator": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6", "title": "LockBit Binary", "description": "Ransomware executable"},
                {"type": "FileHash-SHA256", "indicator": "a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4", "title": "Shared Hash", "description": "Also seen in APT29"},
                {"type": "email", "indicator": "lockbit@protonmail.com", "title": "Contact Email", "description": "Ransom contact"},
            ]
        },
        {
            "id": "demo-pulse-003",
            "name": "Phishing Campaign - Banking Sector",
            "description": "Mass phishing targeting European banking customers",
            "author_name": "CERT-EU",
            "tlp": "amber",
            "created": "2025-02-10T12:00:00Z",
            "modified": "2025-03-01T12:00:00Z",
            "tags": ["phishing", "banking", "credential-theft"],
            "references": [],
            "malware_families": ["AgentTesla"],
            "attack_ids": ["T1566.001"],
            "industries": ["Financial Services"],
            "targeted_countries": ["DE", "FR", "NL"],
            "adversary": "Unknown",
            "indicators": [
                {"type": "domain", "indicator": "secure-banklogin.de", "title": "Phishing Domain DE", "description": "German bank phishing"},
                {"type": "domain", "indicator": "banque-secure-auth.fr", "title": "Phishing Domain FR", "description": "French bank phishing"},
                {"type": "URL", "indicator": "https://secure-banklogin.de/login/verify", "title": "Phishing URL", "description": "Credential harvesting page"},
                {"type": "IPv4", "indicator": "104.21.45.67", "title": "Phishing Server", "description": "Cloudflare-proxied phishing"},
                {"type": "FileHash-SHA1", "indicator": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "title": "AgentTesla", "description": "Stealer payload"},
            ]
        },
        {
            "id": "demo-pulse-004",
            "name": "Cobalt Strike Beacon Infrastructure",
            "description": "Mass scanner-detected Cobalt Strike C2 servers",
            "author_name": "Shodan Intel",
            "tlp": "white",
            "created": "2025-03-15T00:00:00Z",
            "modified": "2025-04-01T00:00:00Z",
            "tags": ["cobaltstrike", "pentesting", "c2", "redteam"],
            "references": [],
            "malware_families": ["Cobalt Strike"],
            "attack_ids": ["T1071.001", "T1573"],
            "industries": ["Multiple"],
            "targeted_countries": [],
            "adversary": "Multiple Actors",
            "indicators": [
                {"type": "IPv4", "indicator": "192.168.100.55", "title": "CS Beacon #1", "description": "Open CS listener"},
                {"type": "IPv4", "indicator": "10.10.10.20", "title": "CS Beacon #2", "description": "CS HTTPS listener"},
                {"type": "IPv4", "indicator": "45.142.212.100", "title": "CS Beacon #3", "description": "Also LockBit infra"},
                {"type": "domain", "indicator": "cs-cdn-1.azureedge-cdn.com", "title": "CS Domain #1", "description": "Azure-masking CS"},
                {"type": "domain", "indicator": "update-service.net", "title": "Shared Domain", "description": "Also in APT29 campaign"},
            ]
        },
    ]

    # Country/ASN data for demo enrichment
    countries = ["United States", "Russia", "China", "Germany", "Netherlands", "Unknown"]
    asns = ["AS15169 GOOGLE", "AS209 CENTURYLINK", "AS3257 GTT", "AS8075 MICROSOFT", "Unknown"]

    for raw_pulse in sample_pulses:
        pulse = normalize_pulse(raw_pulse)
        db.upsert_pulse(pulse)

        for raw_ioc in raw_pulse.get("indicators", []):
            ioc = normalize_ioc(raw_ioc, pulse["id"], pulse)
            ioc["country"] = random.choice(countries)
            ioc["asn"] = random.choice(asns)
            ioc["reputation"] = random.randint(-10, 0)
            ioc_id = db.upsert_ioc(ioc)
            if ioc_id:
                ioc["id"] = ioc_id
                # Build enrichment
                enrich_raw = {
                    "country_name": ioc["country"],
                    "asn": ioc["asn"],
                    "city": random.choice(["Moscow", "Beijing", "Frankfurt", "Amsterdam", "Unknown"]),
                    "region": "Unknown",
                    "latitude": random.uniform(-90, 90),
                    "longitude": random.uniform(-180, 180),
                }
                enrichment = normalize_enrichment(ioc_id, ioc["indicator"], ioc["ioc_type"], enrich_raw)
                db.upsert_enrichment(enrichment)

                stix_ind = build_stix_indicator(ioc, pulse)
                if stix_ind:
                    stix_dict = json.loads(stix_ind.serialize())
                    with db.get_db() as conn:
                        conn.execute(
                            "UPDATE iocs SET stix_id=?, stix_json=? WHERE id=?",
                            (stix_ind.id, json.dumps(stix_dict), ioc_id)
                        )

        ioc_rows_for_bundle = []
        with db.get_db() as conn:
            rows = conn.execute("SELECT * FROM iocs WHERE pulse_id=?", (pulse["id"],)).fetchall()
            ioc_rows_for_bundle = [dict(r) for r in rows]

        bundle = build_stix_bundle(pulse, ioc_rows_for_bundle)
        db.store_stix_bundle({
            "bundle_id": f"bundle--{pulse['id']}",
            "pulse_id": pulse["id"],
            "bundle_json": json.dumps(bundle),
            "object_count": len(bundle.get("objects", [])),
            "created_at": db.now_iso(),
        })

    print("[DEMO] Loaded demo data successfully")
    return {"status": "success", "pulses": len(sample_pulses)}
