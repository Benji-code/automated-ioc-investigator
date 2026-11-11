"""Anonymise investigation results for the public stand demo.

    python -m demo.anonymise output/assessments.json            # -> demo/bundle/ (gitignored)
    python -m demo.anonymise output/assessments.json --no-pdf   # skip compiling the PDFs

Everything shown at the stand goes through Anonymiser first:
  - campus IPs (CAMPUS_CIDR in .env, comma-separated) -> stable labels: Host A, Host B, ...
  - each case host's name (reverse DNS) -> its role label, e.g. "campus web proxy";
    any other name under CAMPUS_DOMAINS -> "campus host name"
  - names of sites the host visited -> their kind and a number, e.g. "adult content site 2",
    so the story survives but the browsing does not
  - public indicators, ad networks and well-known service domains stay as they are
  - the raw case file, the queries run, the model's raw reply and subscriber IDs are dropped
Case text, charts, flow tables and the facts all live in the result dict, so
anonymising the dict and rendering from it covers the HTML and the PDF alike.
The bundle is results.json, one PDF per case (compiled from the anonymised
results with tectonic or latexmk) and intel.json, a snapshot of the latest
public threat intel for the Threat board.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import re
from pathlib import Path

from agent import config, domain_features, knowledge
from demo import latest_intel

HERE = Path(__file__).resolve().parent
BUNDLE_DIR = HERE / "bundle"
SAMPLE_DIR = HERE / "sample"
DROPPED_FIELDS = ("case_file", "tool_calls", "model_reply_raw", "match_ids", "refinement")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
DOMAIN_RE = re.compile(r"(?i)(?<![\w@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-])")
READ_FIRST = ("HEADLINE", "SECTIONS", "LIKELY_USER", "HOST_ROLE", "FLOW_NOTES")
KEEP_ALWAYS = ("cloudflare-ech.com",)  # the Encrypted Client Hello placeholder, not a site


def _networks(cidrs) -> list:
    if isinstance(cidrs, str):
        cidrs = cidrs.split(",")
    return [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs if c and c.strip()]


def _public_domains() -> set[str]:
    """Shared, public infrastructure that is not personal browsing."""
    keep = set(KEEP_ALWAYS) | set(knowledge.AD_NETWORK_DOMAINS)
    for profile in knowledge.SERVICE_PROFILES.values():
        keep |= set(profile.get("domains") or [])
    for markers in knowledge.PLATFORM_HINT_DOMAINS.values():
        keep |= set(markers)
    return keep


class Anonymiser:
    """Stable replacements across a whole bundle (Host A is the same host in every case)."""

    def __init__(self, campus_cidrs=None, campus_domains=None, keep_domains=()):
        self.networks = _networks(config.CAMPUS_CIDR if campus_cidrs is None else campus_cidrs)
        self.campus_domains = [d.lower() for d in (config.CAMPUS_DOMAINS if campus_domains is None else campus_domains)]
        self.keep = _public_domains() | {d.lower() for d in keep_domains}
        self.hosts: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.sites: dict[str, str] = {}
        self.site_counts: dict[str, int] = {}

    # --- single values -----------------------------------------------------------------

    def is_campus_ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in net for net in self.networks)

    def host_label(self, ip: str) -> str:
        if ip not in self.hosts:
            n = len(self.hosts)
            self.hosts[ip] = "Host " + (chr(ord("A") + n) if n < 26 else f"{n + 1}")
        return self.hosts[ip]

    def is_campus_name(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        return any(name == d or name.endswith("." + d) for d in self.campus_domains)

    def _kept(self, name: str) -> bool:
        name = name.lower()
        return any(name == k or name.endswith("." + k) or k.endswith("." + name) for k in self.keep)

    def site_label(self, name: str) -> str:
        """A visited site -> "<kind> site N", the same label for its subdomains."""
        root = domain_features.registered_domain(name)
        if root not in self.sites:
            kind = knowledge.destination_kind(root) or "web"
            self.site_counts[kind] = self.site_counts.get(kind, 0) + 1
            self.sites[root] = f"{kind} site {self.site_counts[kind]}"
        return self.sites[root]

    def _domain(self, match: re.Match) -> str:
        name = match.group(1)
        lowered = name.lower().rstrip(".")
        if lowered in self.names:
            return self.names[lowered]
        if self.is_campus_name(lowered):
            return "campus host name"
        parts = domain_features._extractor()(lowered)
        if not (parts.domain and parts.suffix) or self._kept(lowered):
            return name  # not a real domain (a file name, say), or public infrastructure
        return self.site_label(lowered)

    def text(self, value: str) -> str:
        value = IPV4_RE.sub(lambda m: self.host_label(m.group(1)) if self.is_campus_ip(m.group(1)) else m.group(1),
                            value)
        return DOMAIN_RE.sub(self._domain, value)

    # --- whole results -----------------------------------------------------------------

    def walk(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, dict):
            return {self.walk(k) if isinstance(k, str) else k: self.walk(v) for k, v in value.items()}
        return value

    def learn_host(self, result: dict) -> None:
        """The case host's own name becomes its role label."""
        ev = result.get("evidence") or {}
        name = ((ev.get("host") or {}).get("hostname") or "").lower().rstrip(".")
        if name:
            role = ((ev.get("host_type") or {}).get("name") or "host").split(" (")[0]
            self.names[name] = f"campus {role}"

    def result(self, result: dict) -> dict:
        """An anonymised copy of one result, ready to render."""
        out = {k: copy.deepcopy(v) for k, v in result.items() if k not in DROPPED_FIELDS}
        host = (out.get("evidence") or {}).get("host")
        if isinstance(host, dict):
            host.pop("subscriber_ids", None)
        self.learn_host(out)
        for key in READ_FIRST:  # number sites in the order a reader meets them
            self.walk(out.get(key))
        return self.walk(out)


def indicator_names(results: list[dict]) -> set[str]:
    """The indicators' own names: public, so they stay."""
    names = set()
    for r in results:
        indicator = str(r.get("indicator") or "")
        if not IPV4_RE.match(indicator):
            names.add(indicator.lower())
    return names


def anonymise_results(results: list[dict], anonymiser: Anonymiser | None = None) -> list[dict]:
    if anonymiser is None:
        if not config.CAMPUS_CIDR:
            raise SystemExit("Set CAMPUS_CIDR (and CAMPUS_DOMAINS) in .env before building a demo bundle: "
                             "without them campus addresses cannot be recognised.")
        anonymiser = Anonymiser(keep_domains=indicator_names(results))
    for r in results:  # names first, so a host's name gets its role label wherever it appears
        anonymiser.learn_host(r)
    for r in results:  # then the report text, so sites are numbered in the order a reader meets them
        for key in READ_FIRST:
            anonymiser.walk(r.get(key))
    return [anonymiser.result(r) for r in results if r.get("VERDICT") != "ERROR"]


def write_pdfs(results: list[dict], folder: Path) -> int:
    """Compile each (anonymised) case to folder/pdf/<case>.pdf. The LaTeX and
    chart files are built in a temporary folder; only the PDFs are kept, and
    PDFs left from an earlier bundle are removed. Returns how many compiled."""
    import shutil
    import tempfile

    from agent import latex

    pdf_dir = folder / "pdf"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    for old in pdf_dir.glob("*.pdf"):
        old.unlink()
    if not latex.tex_engine():
        print("  warning: no TeX engine (tectonic or latexmk) on PATH: the bundle has no PDFs.")
        return 0
    made = 0
    with tempfile.TemporaryDirectory() as work:
        for r in results:
            pdf = latex.compile_tex(latex.write_case_tex(r, Path(work)))
            if pdf:
                shutil.copy(pdf, pdf_dir / pdf.name)
                made += 1
    return made


def write_bundle(results: list[dict], folder: Path, pdf: bool = True, intel: dict | None = None) -> Path:
    """results.json (already anonymised), one PDF per case (pdf=True) and the
    latest-intel snapshot, if given."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "results.json"
    path.write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    if pdf:
        print(f"  {write_pdfs(results, folder)} of {len(results)} PDF(s) compiled")
    if intel is not None:
        latest_intel.save(intel, folder)
    return path


def load_bundle() -> tuple[list[dict], Path]:
    """The real anonymised bundle if one was built, else the tracked sample."""
    for folder in (BUNDLE_DIR, SAMPLE_DIR):
        path = folder / "results.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8")), folder
    return [], SAMPLE_DIR


def main() -> None:
    import assess

    parser = argparse.ArgumentParser(description="Build the anonymised demo bundle from saved results.")
    parser.add_argument("assessments", type=Path, help="an assessments.json written by assess.py")
    parser.add_argument("--out", type=Path, default=BUNDLE_DIR)
    parser.add_argument("--no-pdf", action="store_true", help="skip compiling the PDF reports")
    parser.add_argument("--no-intel", action="store_true",
                        help="skip the latest-intel snapshot (ThreatFox API and the local MISP)")
    args = parser.parse_args()
    results = anonymise_results(assess.read_results(args.assessments))
    intel = None
    if not args.no_intel:
        intel = latest_intel.fetch_snapshot()
        for error in intel["errors"]:
            print(f"  warning: latest intel: {error}")
    path = write_bundle(results, args.out, pdf=not args.no_pdf, intel=intel)
    print(f"Wrote {len(results)} anonymised case(s) to {path}")


if __name__ == "__main__":
    main()
