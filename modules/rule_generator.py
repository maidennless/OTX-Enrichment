"""
Detection Rule Generator.
Automatically generates Sigma, YARA, Suricata, and Snort rules
from IOC patterns stored in the database.
"""
import json
import re
import uuid
from datetime import datetime, timezone

from modules import database as db


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slugify(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", s)[:64].strip("_") or "indicator"


def _severity_from_rep(reputation: int) -> str:
    if reputation <= -7:
        return "critical"
    if reputation <= -4:
        return "high"
    if reputation <= -1:
        return "medium"
    return "low"


# ─── SIGMA ───────────────────────────────────────────────────────────────────

def generate_sigma(ioc: dict, pulse: dict) -> str:
    """Generate a Sigma rule for the given IOC."""
    ioc_type = ioc.get("ioc_type", "unknown")
    indicator = ioc.get("indicator", "")
    malware = ioc.get("malware_family", "Unknown Malware")
    severity = _severity_from_rep(ioc.get("reputation", 0))
    rule_id = str(uuid.uuid4())
    pulse_name = pulse.get("name", "Unknown Pulse")
    adversary = pulse.get("adversary", "Unknown")
    tags = json.loads(pulse.get("tags", "[]")) if isinstance(pulse.get("tags"), str) else []

    # Build detection condition based on IOC type
    if ioc_type == "IPv4":
        detection = f"""detection:
    selection_dst:
        dst_ip: '{indicator}'
    selection_src:
        src_ip: '{indicator}'
    condition: selection_dst or selection_src"""
        logsource = """logsource:
    category: firewall
    product: any"""

    elif ioc_type in ("domain", "hostname"):
        detection = f"""detection:
    selection_dns:
        dns.question.name|contains: '{indicator}'
    selection_http:
        http.virtual_host|contains: '{indicator}'
    condition: selection_dns or selection_http"""
        logsource = """logsource:
    category: network
    product: any"""

    elif ioc_type == "URL":
        url_escaped = indicator.replace("'", "\\'")
        detection = f"""detection:
    selection:
        http.url|contains: '{url_escaped}'
    condition: selection"""
        logsource = """logsource:
    category: proxy
    product: any"""

    elif "FileHash" in ioc_type or ioc_type in ("MD5", "SHA1", "SHA256"):
        hash_field = {
            "FileHash-MD5": "md5",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
        }.get(ioc_type, "sha256")
        detection = f"""detection:
    selection:
        hashes|contains: '{indicator}'
    selection_sysmon:
        {hash_field}: '{indicator}'
    condition: selection or selection_sysmon"""
        logsource = """logsource:
    category: process_creation
    product: windows"""

    elif ioc_type == "email":
        detection = f"""detection:
    selection:
        sender|contains: '{indicator}'
        recipient|contains: '{indicator}'
    condition: 1 of selection*"""
        logsource = """logsource:
    category: email
    product: any"""

    else:
        detection = f"""detection:
    selection:
        message|contains: '{indicator}'
    condition: selection"""
        logsource = """logsource:
    category: application
    product: any"""

    atk_tags = ""
    if tags:
        atk_tags = "\n    - " + "\n    - ".join(f"'{t}'" for t in tags[:5])

    rule = f"""title: '{malware} - {ioc_type} Indicator'
id: {rule_id}
status: experimental
description: 'Auto-generated detection for {ioc_type} indicator associated with {malware}. Source: {pulse_name}. Adversary: {adversary}.'
references:
    - 'https://otx.alienvault.com/pulse/{ioc.get("pulse_id", "")}'
author: 'IOC Dashboard Auto-Generator'
date: {datetime.now(timezone.utc).strftime("%Y/%m/%d")}
modified: {datetime.now(timezone.utc).strftime("%Y/%m/%d")}
tags:{atk_tags if atk_tags else " []"}
{logsource}
{detection}
falsepositives:
    - 'Low - Legitimate traffic to this indicator is unlikely'
level: {severity}
"""
    return rule.strip()


# ─── YARA ────────────────────────────────────────────────────────────────────

def generate_yara(ioc: dict, pulse: dict) -> str:
    """Generate a YARA rule for file-hash or string-based IOCs."""
    ioc_type = ioc.get("ioc_type", "unknown")
    indicator = ioc.get("indicator", "")
    malware = _slugify(ioc.get("malware_family", "Unknown_Malware"))
    pulse_name = pulse.get("name", "Unknown Pulse")
    adversary = pulse.get("adversary", "Unknown")
    rule_name = f"IOC_{malware}_{_slugify(indicator[:16])}"

    if "FileHash" in ioc_type or ioc_type in ("MD5", "SHA1", "SHA256"):
        hash_type = {
            "FileHash-MD5": "md5",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
        }.get(ioc_type, "sha256")
        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects file matching {malware} hash from OTX pulse: {pulse_name}"
        author = "IOC Dashboard Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"
        reference = "https://otx.alienvault.com/pulse/{ioc.get('pulse_id', '')}"
        adversary = "{adversary}"
        malware_family = "{ioc.get('malware_family', 'Unknown')}"
        severity = "{_severity_from_rep(ioc.get('reputation', 0))}"
        hash_{hash_type} = "{indicator}"

    condition:
        {hash_type} == "{indicator}"
}}"""

    elif ioc_type in ("domain", "hostname", "URL"):
        str_val = indicator.encode("utf-8").hex()
        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects network artifact associated with {malware}: {pulse_name}"
        author = "IOC Dashboard Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"
        reference = "https://otx.alienvault.com/pulse/{ioc.get('pulse_id', '')}"
        adversary = "{adversary}"
        severity = "{_severity_from_rep(ioc.get('reputation', 0))}"

    strings:
        $indicator_str = "{indicator}" ascii wide nocase
        $indicator_hex = {{ {' '.join(str_val[i:i+2] for i in range(0, min(len(str_val), 40), 2))} }}

    condition:
        any of them
}}"""

    elif ioc_type == "IPv4":
        octets = indicator.split(".")
        if len(octets) == 4:
            hex_ip = "".join(f"{int(o):02X}" for o in octets)
            rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects hardcoded IP {indicator} associated with {malware}"
        author = "IOC Dashboard Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"
        adversary = "{adversary}"
        severity = "{_severity_from_rep(ioc.get('reputation', 0))}"

    strings:
        $ip_string = "{indicator}" ascii wide
        $ip_hex = {{ {hex_ip} }}

    condition:
        any of them
}}"""
        else:
            rule = f"""rule {rule_name}
{{
    meta:
        description = "IP indicator {indicator} for {malware}"
        author = "IOC Dashboard Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"

    strings:
        $ip = "{indicator}" ascii wide

    condition:
        $ip
}}"""
    else:
        rule = f"""rule {rule_name}
{{
    meta:
        description = "Generic indicator rule for {malware}: {ioc.get('title', indicator)}"
        author = "IOC Dashboard Auto-Generator"
        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"
        severity = "{_severity_from_rep(ioc.get('reputation', 0))}"

    strings:
        $indicator = "{indicator}" ascii wide nocase

    condition:
        $indicator
}}"""

    return rule.strip()


# ─── SURICATA ────────────────────────────────────────────────────────────────

def generate_suricata(ioc: dict, pulse: dict, sid: int = None) -> str:
    """Generate a Suricata IDS rule."""
    ioc_type = ioc.get("ioc_type", "unknown")
    indicator = ioc.get("indicator", "")
    malware = ioc.get("malware_family", "Unknown")
    pulse_name = pulse.get("name", "Unknown Pulse")
    adversary = pulse.get("adversary", "Unknown")
    severity = _severity_from_rep(ioc.get("reputation", 0))
    classtype_map = {"critical": "trojan-activity", "high": "trojan-activity",
                     "medium": "policy-violation", "low": "misc-activity"}
    classtype = classtype_map.get(severity, "misc-activity")
    sid = sid or (hash(indicator) % 9000000 + 1000000)
    msg = f"{malware} - {ioc_type} IOC [{adversary}]"
    metadata = f"pulse_id {ioc.get('pulse_id', 'unknown')}, malware {_slugify(malware)}, severity {severity}"

    if ioc_type == "IPv4":
        rules = [
            f'alert ip any any -> {indicator} any (msg:"{msg}"; sid:{sid}; rev:1; classtype:{classtype}; metadata:{metadata};)',
            f'alert ip {indicator} any -> any any (msg:"{msg} - Outbound"; sid:{sid+1}; rev:1; classtype:{classtype}; metadata:{metadata};)',
        ]
        return "\n".join(rules)

    elif ioc_type in ("domain", "hostname"):
        return f'alert dns any any -> any any (msg:"{msg}"; dns.query; content:"{indicator}"; nocase; sid:{sid}; rev:1; classtype:{classtype}; metadata:{metadata};)'

    elif ioc_type == "URL":
        parsed_host = ""
        parsed_uri = indicator
        try:
            from urllib.parse import urlparse
            p = urlparse(indicator)
            parsed_host = p.netloc
            parsed_uri = p.path or "/"
        except Exception:
            pass
        if parsed_host:
            return f'alert http any any -> any any (msg:"{msg}"; http.host; content:"{parsed_host}"; nocase; http.uri; content:"{parsed_uri}"; nocase; sid:{sid}; rev:1; classtype:{classtype}; metadata:{metadata};)'
        else:
            return f'alert http any any -> any any (msg:"{msg}"; http.uri; content:"{parsed_uri}"; nocase; sid:{sid}; rev:1; classtype:{classtype}; metadata:{metadata};)'

    elif "FileHash" in ioc_type:
        return f'# Suricata file hash detection requires filestore + Lua\n# Hash: {indicator}\n# Malware: {malware}\n# Use: alert http any any -> any any (msg:"{msg}"; filesha256:"{indicator}"; sid:{sid}; rev:1; classtype:{classtype};)'

    else:
        return f'alert tcp any any -> any any (msg:"{msg}"; content:"{indicator}"; nocase; sid:{sid}; rev:1; classtype:{classtype}; metadata:{metadata};)'


# ─── SNORT ───────────────────────────────────────────────────────────────────

def generate_snort(ioc: dict, pulse: dict, sid: int = None) -> str:
    """Generate a Snort 3 IDS rule."""
    ioc_type = ioc.get("ioc_type", "unknown")
    indicator = ioc.get("indicator", "")
    malware = ioc.get("malware_family", "Unknown")
    pulse_name = pulse.get("name", "Unknown")
    adversary = pulse.get("adversary", "Unknown")
    severity = _severity_from_rep(ioc.get("reputation", 0))
    priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    priority = priority_map.get(severity, 3)
    sid = sid or (hash(indicator) % 8000000 + 2000000)
    msg = f"{malware} {ioc_type} indicator [{adversary}]"

    if ioc_type == "IPv4":
        rules = [
            f'alert ip any any -> {indicator} any (msg:"{msg}"; priority:{priority}; sid:{sid}; rev:1; metadata:pulse_id {ioc.get("pulse_id","")};)',
            f'alert ip {indicator} any -> any any (msg:"{msg} - SRC"; priority:{priority}; sid:{sid+1}; rev:1;)',
        ]
        return "\n".join(rules)

    elif ioc_type in ("domain", "hostname"):
        return f'alert udp any any -> any 53 (msg:"{msg}"; content:"|00|{"|00|".join(p.encode().hex() for p in indicator.split("."))}"; nocase; sid:{sid}; rev:1; priority:{priority};)'

    elif ioc_type == "URL":
        try:
            from urllib.parse import urlparse
            p = urlparse(indicator)
            host = p.netloc or indicator
            path = p.path or "/"
            return f'alert tcp any any -> any $HTTP_PORTS (msg:"{msg}"; flow:to_server,established; content:"Host: {host}"; nocase; content:"{path}"; nocase; sid:{sid}; rev:1; priority:{priority};)'
        except Exception:
            return f'alert tcp any any -> any $HTTP_PORTS (msg:"{msg}"; content:"{indicator}"; nocase; sid:{sid}; rev:1; priority:{priority};)'

    elif "FileHash" in ioc_type:
        return f'# Snort 3 file hash detection\n# Use snort3-file-magic rules\n# Hash ({ioc_type}): {indicator}\n# alert file (msg:"{msg}"; file_data; sid:{sid}; rev:1; priority:{priority};)'

    else:
        return f'alert tcp any any -> any any (msg:"{msg}"; content:"{indicator}"; nocase; sid:{sid}; rev:1; priority:{priority};)'


# ─── BATCH GENERATOR ─────────────────────────────────────────────────────────

def generate_rules_for_ioc(ioc_id: int) -> dict:
    """Generate all 4 rule types for a single IOC and store them."""
    detail = db.get_ioc_detail(ioc_id)
    if not detail:
        return {"error": "IOC not found"}

    ioc = detail["ioc"]
    pulse = db.get_pulse_by_id(ioc.get("pulse_id", "")) or {}

    rules_generated = {"sigma": None, "yara": None, "suricata": None, "snort": None}
    sid_base = hash(ioc["indicator"]) % 7000000 + 3000000

    for rule_type, gen_fn, sid_offset in [
        ("sigma", generate_sigma, 0),
        ("yara", generate_yara, 0),
        ("suricata", generate_suricata, sid_base),
        ("snort", generate_snort, sid_base + 100),
    ]:
        try:
            if rule_type in ("suricata", "snort"):
                content = gen_fn(ioc, pulse, sid_offset)
            else:
                content = gen_fn(ioc, pulse)

            tags = json.loads(pulse.get("tags", "[]")) if isinstance(pulse.get("tags"), str) else []
            rule_rec = {
                "rule_type": rule_type,
                "rule_name": f"{rule_type.upper()}: {ioc.get('malware_family','Unknown')} - {ioc['ioc_type']}",
                "rule_content": content,
                "ioc_id": ioc_id,
                "pulse_id": ioc.get("pulse_id", ""),
                "description": f"Auto-generated {rule_type.upper()} rule for {ioc['indicator']}",
                "severity": _severity_from_rep(ioc.get("reputation", 0)),
                "tags": json.dumps(tags[:5]),
                "created_at": _now(),
                "is_valid": 1,
            }
            db.insert_rule(rule_rec)
            rules_generated[rule_type] = content
        except Exception as e:
            rules_generated[rule_type] = f"# Error generating {rule_type} rule: {e}"

    return rules_generated


def generate_all_rules() -> dict:
    """Generate rules for all IOCs in the database."""
    with db.get_db() as conn:
        ioc_ids = [r[0] for r in conn.execute("SELECT id FROM iocs").fetchall()]

    total = 0
    for ioc_id in ioc_ids:
        result = generate_rules_for_ioc(ioc_id)
        if "error" not in result:
            total += 1

    return {"rules_generated_for": total, "ioc_count": len(ioc_ids)}


def get_rules_summary() -> dict:
    """Return rules grouped by type with counts."""
    with db.get_db() as conn:
        by_type = conn.execute(
            "SELECT rule_type, COUNT(*) as cnt FROM detection_rules GROUP BY rule_type"
        ).fetchall()
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM detection_rules GROUP BY severity"
        ).fetchall()
        recent = conn.execute(
            "SELECT dr.*, i.indicator, i.ioc_type FROM detection_rules dr JOIN iocs i ON dr.ioc_id=i.id ORDER BY dr.created_at DESC LIMIT 10"
        ).fetchall()
    return {
        "by_type": [dict(r) for r in by_type],
        "by_severity": [dict(r) for r in by_severity],
        "recent_rules": [dict(r) for r in recent],
    }
