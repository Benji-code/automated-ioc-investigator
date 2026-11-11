"""What kind of behaviour a case shows (tunnelling, beaconing, web browsing
on shared infrastructure, ...), decided in code from the evidence.

The category drives the report's wording and next steps. It is generic: it
reads ports, traffic shape, names and the knowledge base's service profiles,
never a specific service or indicator.
"""
from __future__ import annotations

from . import signals

WEB_PORTS = {80, 443}
DOWNLOAD_MIN_BYTES = 500_000
DOWNLOAD_MIN_RATIO = 5.0

CATEGORIES = {
    "tunnel_client": "Tunnelling",
    "remote_access_client": "Remote access (VPN)",
    "tunnel_public_port": "Connection to a tunnel's public port",
    "beaconing": "C2-like beaconing",
    "periodic_explained": "Periodic check-ins by a recognised app or service",
    "persistent_connection": "Persistent connection to an unrecognised service",
    "download": "File download",
    "web_visit_flagged": "Web visit to the flagged site",
    "web_shared": "Web browsing through shared infrastructure",
    "web": "Web traffic",
    "other": "Other traffic",
    "no_traffic": "No traffic observed",
}


def _ports(ev: dict) -> list[tuple[int, str]]:
    return signals._ports(ev.get("flows", {}))


def _signal(ev: dict, name: str) -> dict:
    return next((s for s in ev.get("signals", []) if s["name"] == name), {})


def _name_matches_indicator(ev: dict) -> bool:
    return (ev["identity"].get("indicator_type") == "domain"
            and _signal(ev, "sni_matches_indicator").get("value") not in (None, "no name seen"))


def _is_download(ev: dict) -> bool:
    up, down = signals._total_bytes(ev.get("flows", {}))
    return down >= DOWNLOAD_MIN_BYTES and down >= DOWNLOAD_MIN_RATIO * max(up, 1)


def classify(ev: dict) -> dict:
    """{'key', 'label'} for the case's main behaviour."""
    if not signals.has_evidence(ev):
        return _category("no_traffic")
    expected = ev.get("expected", {})
    service = expected.get("service")
    fits = signals._service_fits(expected)
    if service and fits:
        kind = service["profile"].get("kind", "tunnel")
        return _category("remote_access_client" if kind == "remote_access" else "tunnel_client")
    if service and fits is False:
        return _category("tunnel_public_port")

    flows = ev.get("flows", {})
    classification = flows.get("classification", {})
    ports = _ports(ev)
    web_only = bool(ports) and all(port in WEB_PORTS for port, _ in ports)
    contact = _signal(ev, "contact_pattern")
    pattern = (ev.get("contact") or {}).get("pattern")
    if pattern == "periodic_checkin" and contact.get("direction") == signals.SUPPORTS:
        return _category("beaconing")
    if pattern == "periodic_checkin":
        return _category("periodic_explained")
    held = classification.get("held_open") or pattern == "held_open"
    if held and not web_only:
        return _category("persistent_connection")
    threat_type = (ev["identity"].get("threat_type") or "").lower()
    if threat_type == "payload_delivery" and _is_download(ev):
        return _category("download")
    if web_only and _name_matches_indicator(ev):
        return _category("web_visit_flagged")
    if web_only and _signal(ev, "shared_infrastructure").get("direction") == signals.AGAINST:
        return _category("web_shared")
    if web_only:
        return _category("web")
    return _category("other")


def _category(key: str) -> dict:
    return {"key": key, "label": CATEGORIES[key]}


def exposes_host(key: str) -> bool:
    """Categories where the host itself may be reachable from outside."""
    return key in ("tunnel_client", "remote_access_client", "persistent_connection")
