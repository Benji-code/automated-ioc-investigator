"""Cross-case correlation: domains that sit behind more than one flagged
indicator in the same feed.

A CDN-fronted C2 or malicious site is often reported as several IP:port
indicators, one per edge address it happened to resolve to. When hosts
reached two different flagged IPs under the SAME domain, the domain is more
likely the real indicator than either IP. The same visit can also produce
two cases (one host, one site, two flagged IPs); those are linked as
duplicates.

Uses only the feed's own records (the names each match was seen with), so it
runs before any case is assessed and needs no database.
"""
from __future__ import annotations

from . import domain_features as dfeat


def _case_domains(rows: list[dict]) -> set[str]:
    """Registered domains the feed recorded for one case (SNI, DNS, root
    domain), without the ECH placeholder."""
    domains: set[str] = set()
    for record in rows:
        for a in record.get("evidence", {}).get("subscriber_activity", []):
            for field in ("sni", "dns", "root_domain"):
                name = a.get(field)
                if not name:
                    continue
                domain = dfeat.registered_domain(name)
                if domain and not dfeat.is_ech_placeholder(domain):
                    domains.add(domain)
    return domains


def correlate(cases: list[tuple[dict, list[dict]]]) -> dict:
    """{'domains': {domain: {indicators, hosts, cases}},
        'by_case': {(indicator, host): [linked domains]}}
    for every domain seen behind two or more DIFFERENT flagged indicators."""
    seen: dict[str, dict] = {}
    case_domains: dict[tuple[str, str], set[str]] = {}
    for identity, rows in cases:
        key = (identity["indicator"], identity["affected_asset"])
        domains = _case_domains(rows)
        case_domains[key] = domains
        for domain in domains:
            entry = seen.setdefault(domain, {"indicators": set(), "hosts": set(), "cases": []})
            entry["indicators"].add(identity["indicator"])
            entry["hosts"].add(identity["affected_asset"])
            entry["cases"].append(key)
    linked = {d: e for d, e in seen.items() if len(e["indicators"]) >= 2}
    domains = {d: {"indicators": sorted(e["indicators"]), "hosts": sorted(e["hosts"]), "cases": e["cases"]}
               for d, e in linked.items()}
    by_case = {key: sorted(d for d in doms if d in domains) for key, doms in case_domains.items()}
    return {"domains": domains, "by_case": {k: v for k, v in by_case.items() if v}}


def shared_provider(indicators: list[str]) -> str | None:
    """The shared range (e.g. Cloudflare) all these IP indicators sit in, if
    one does: then several flagged addresses for one site is normal (each
    proxied site gets more than one) and not extra evidence."""
    names = set()
    for indicator in indicators:
        match = dfeat.ip_range_match(indicator.split(":")[0])
        if not match:
            return None
        names.add(match["name"].split(" (")[0])
    return names.pop() if len(names) == 1 else None


def same_visits(cases: list[tuple[dict, list[dict]]], correlation: dict) -> dict[tuple, tuple]:
    """{duplicate case: primary case} for one host reaching the same linked
    site through two flagged IPs: one visit, so one card. The first such
    case (in assessment order) is the primary."""
    domains_of = {(i["indicator"], i["affected_asset"]): _case_domains(rows) for i, rows in cases}
    primary_for: dict[tuple, tuple] = {}
    seen: dict[tuple, tuple] = {}
    for identity, _ in cases:
        key = (identity["indicator"], identity["affected_asset"])
        linked = frozenset(correlation.get("by_case", {}).get(key, []))
        if not linked or domains_of[key] != set(linked):
            continue
        group = (identity["affected_asset"], linked)
        if group in seen:
            primary_for[key] = seen[group]
        else:
            seen[group] = key
    return primary_for


def for_case(correlation: dict, key: tuple[str, str], checks: dict | None = None) -> dict | None:
    """What one case shares with others: the linked domains (with their
    campus checks, if run) and the related cases. A related case with the
    same host and domain is the same visit seen through another flagged IP."""
    domains = correlation.get("by_case", {}).get(key)
    if not domains:
        return None
    indicator, host = key
    linked = []
    related = []
    for domain in domains:
        info = correlation["domains"][domain]
        linked.append({"domain": domain, "indicators": info["indicators"], "hosts": info["hosts"],
                       "case_count": len(info["cases"]), **((checks or {}).get(domain) or {})})
        for other in info["cases"]:
            if other == key or any(r["indicator"] == other[0] and r["host"] == other[1] for r in related):
                continue
            related.append({"indicator": other[0], "host": other[1], "domain": domain,
                            "same_visit": other[1] == host})
    return {"domains": linked, "related_cases": related}
