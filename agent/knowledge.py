"""Local knowledge base: what a threat type, malware family or known service
normally looks like on the wire.

The agent has no internet access, so this file stands in for the background
research an analyst would do. It is general reference knowledge, not per-case
evidence. Add entries as new families and services show up in the feed;
lookups fall back to a default profile for anything not listed.

Anything marked "(uncertain)" is from general knowledge and has not been
checked against the service's source code or documentation.
"""
from __future__ import annotations

THREAT_TYPE_PROFILES: dict[str, dict] = {
    "payload_delivery": {
        "ioc_role": "payload delivery site",
        "match_means": "the host downloaded malicious software or a malicious script from it",
        "victim_traffic": "download a file or script from the site, usually in one short burst",
        "expected_traffic_shape": (
            "Download-heavy: down_bytes much greater than up_bytes, usually "
            "within one short burst/session rather than spread thin."
        ),
        "expected_recurrence": (
            "Often a single occurrence, or a short cluster on one day. Ongoing "
            "recurrence across many days is not required for a genuine hit."
        ),
        "false_positive_pattern": (
            "A tiny transfer (a few KB, typical of ordinary page/asset loads), "
            "or no clear payload-sized download at all."
        ),
    },
    "botnet_cc": {
        "ioc_role": "command-and-control (C2) server",
        "match_means": "the host is infected and being controlled by an attacker",
        "victim_traffic": ("connect out to the C2 server repeatedly, with regular short check-ins or one "
                           "persistent connection to the C2 port, and send stolen data back over it"),
        "expected_traffic_shape": (
            "The victim connects OUT to the C2 host on the operator's chosen port. "
            "Either repeated short check-ins at a regular interval, or one "
            "persistent connection to the C2 port, with bursts of upload when "
            "data is stolen."
        ),
        "expected_recurrence": (
            "Recurring contact across days. Daily presence alone is not a beacon: "
            "any service used daily is present daily. Look for regular short "
            "check-ins, or a persistent session to the C2 port."
        ),
        "false_positive_pattern": (
            "Traffic that fits a known legitimate service on that IP and port, "
            "a shared cloud/CDN IP where many unrelated hosts and hostnames also "
            "appear, or a single isolated contact."
        ),
        "shared_ip_rule": (
            "An ip:443 indicator on a CDN or shared cloud front end (Cloudflare, "
            "AWS Global Accelerator, CloudFront, Akamai, Fastly) is weak on its "
            "own: one IP serves thousands of unrelated sites. It only counts "
            "with an SNI/domain match to a bad domain, or a non-web traffic "
            "shape (regular check-ins, a custom protocol on a non-web port)."
        ),
    },
    "c2": {  # some feeds use "c2" instead of "botnet_cc" for the same thing
        "ioc_role": "command-and-control (C2) server",
        "match_means": "the host is infected and being controlled by an attacker",
        "victim_traffic": ("connect out to the C2 server repeatedly, with regular short check-ins or one "
                           "persistent connection to the C2 port"),
        "expected_traffic_shape": "Same as botnet_cc.",
        "expected_recurrence": "Same as botnet_cc.",
        "false_positive_pattern": "Same as botnet_cc.",
    },
}

DEFAULT_THREAT_TYPE_PROFILE = {
    "ioc_role": "malicious indicator",
    "match_means": "the host is compromised or was exposed to malicious content",
    "victim_traffic": "show traffic that fits the threat, which has no profile on file",
    "expected_traffic_shape": "No profile on file for this threat type. Judge the shape on its own merits.",
    "expected_recurrence": "No profile on file for this threat type.",
    "false_positive_pattern": "No profile on file for this threat type.",
}

MALWARE_PROFILES: dict[str, dict] = {
    "win.nanocore": {
        "family": "NanoCore RAT",
        "notes": (
            "Windows remote-access trojan, usually delivered by phishing. Used to "
            "steal credentials, log keystrokes and spy through the webcam. The "
            "victim opens an outbound TCP connection to a C2 host and port set by "
            "the operator (often a dynamic-DNS name or a tunnelling service) and "
            "sends stolen data back over it. The C2 channel is NanoCore's own "
            "binary protocol over plain TCP: not normal HTTPS browsing (no TLS "
            "SNI to a website) and never QUIC (UDP/443)."
        ),
        "platform": "windows",
        "transport": "custom_tcp",
        "victim_traffic": ("hold a connection to its C2 host on an operator-chosen TCP port using "
                           "NanoCore's own protocol, not normal HTTPS browsing or QUIC, and send stolen data back"),
    },
    "elf.shadowv2": {
        "family": "ShadowV2 (Linux/ELF botnet)",
        "notes": (
            "Linux ELF botnet malware, typically delivered as a downloaded "
            "binary/script (payload_delivery) before it starts its own C2 "
            "activity. Look for a download-shaped fetch, not a check-in."
        ),
        "platform": "linux",
    },
    "js.clearfake": {
        "family": "ClearFake",
        "notes": (
            "JavaScript injected into compromised legitimate websites that shows "
            "a fake browser/software update, which then delivers the real payload. "
            "The flagged domain is often the compromised site itself, not "
            "attacker infrastructure."
        ),
        "transport": "web",
    },
    "js.iclickfix": {
        "family": "ClickFix-style loader",
        "notes": (
            "Social-engineering JavaScript that tricks the user into pasting and "
            "running an attacker-supplied command (fake CAPTCHA or 'fix an error' "
            "prompt). Initial contact is usually a small page load, not a large "
            "transfer."
        ),
        "transport": "web",
    },
}

DEFAULT_MALWARE_PROFILE = {
    "family": "unknown / not in the knowledge base",
    "notes": "No profile on file for this malware family. Rely on the threat type profile and observed behaviour.",
}

# Known tunnelling and remote-access services. These are often listed as C2
# indicators because attackers hide behind them, but most campus traffic to
# them is the service's normal client. "ports" are the ports the CLIENT
# connects to. Only ports marked distinctive are matched on port alone.
SERVICE_PROFILES: dict[str, dict] = {
    "bore": {
        "name": "bore (open-source reverse TCP tunnel)",
        "kind": "tunnel",
        "domains": ["bore.pub"],
        "ports": [{"port": 7835, "protocol": "tcp", "role": "control", "distinctive": True}],
        "what_it_does": (
            "Exposes a TCP service on a host behind NAT/firewall to the internet. "
            "The client connects to the server's control port 7835 and asks for a "
            "public port. When someone connects to that public port, the server "
            "sends the client an ID and the client opens a NEW connection to 7835 "
            "to carry that visitor's session."
        ),
        "normal_client_traffic": (
            "One held-open TCP connection to port 7835 lasting hours or days. The "
            "server sends a 12-byte JSON heartbeat every 500 ms: about 2 packets/s "
            "down at about 66 bytes/packet including headers; the client only ACKs "
            "(about 2 packets/s up at about 60 bytes/packet). Each visitor adds a "
            "short extra connection to 7835; if the local service sends data to the "
            "visitor, these are upload-heavy. The client has no built-in reconnect, "
            "so quick reconnects after a drop mean something (a script or service "
            "manager) is relaunching it."
        ),
        "abuse": (
            "Backdoor access into a network, or hiding a C2 server behind "
            "bore.pub's IP. The IP then appears on threat feeds even though most "
            "users are ordinary developers."
        ),
        "c2_victim_would_show": (
            "A victim of C2 hosted behind bore connects to the tunnel's random "
            "public port on the same IP, NOT to 7835. Traffic only on 7835 means "
            "the host is running a bore client itself."
        ),
    },
    "cloudflare_tunnel": {
        "name": "Cloudflare Tunnel (cloudflared)",
        "kind": "tunnel",
        "domains": ["argotunnel.com", "cftunnel.com"],
        "ports": [
            {"port": 7844, "protocol": "udp", "role": "tunnel (QUIC, default)", "distinctive": True},
            {"port": 7844, "protocol": "tcp", "role": "tunnel (HTTP/2 fallback)", "distinctive": True},
        ],
        "what_it_does": (
            "Publishes a local service through Cloudflare's network without any "
            "inbound firewall rule. cloudflared dials out to Cloudflare edge servers."
        ),
        "normal_client_traffic": (
            "Several long-lived connections (usually 4, to two regions) on port "
            "7844, UDP/QUIC by default, falling back to TCP. Upload-heavy when the "
            "local service sends content to visitors."
        ),
        "abuse": (
            "Used by attackers for persistent remote access and to expose C2 or "
            "phishing pages from inside a network. Bypasses inbound firewall rules."
        ),
        "c2_victim_would_show": (
            "A victim of C2 hosted on Cloudflare would contact a Cloudflare anycast "
            "IP on 443 (shared by many sites), not hold 7844 tunnels."
        ),
    },
    "tailscale": {
        "name": "Tailscale (WireGuard-based mesh VPN)",
        "kind": "remote_access",
        "domains": ["tailscale.com", "tailscale.io", "ts.net"],
        "ports": [
            {"port": 41641, "protocol": "udp", "role": "direct WireGuard peer traffic (default)", "distinctive": True},
            {"port": 3478, "protocol": "udp", "role": "STUN (NAT discovery)", "distinctive": False},
            {"port": 443, "protocol": "tcp", "role": "control plane and DERP relays", "distinctive": False},
        ],
        "what_it_does": (
            "Joins the device to a private mesh network so the owner's other "
            "devices can reach it from anywhere."
        ),
        "normal_client_traffic": (
            "A long-lived HTTPS connection to the control server (controlplane."
            "tailscale.com), relay traffic to derp*.tailscale.com on 443 when a "
            "direct path fails, and UDP to peers (default port 41641). Volume "
            "depends on what the owner does over it."
        ),
        "abuse": (
            "Reported in intrusions as a way to keep remote access into a network "
            "(uncertain: specific campaigns not listed here)."
        ),
        "c2_victim_would_show": "Not a typical C2 host; traffic goes to Tailscale's own servers and the owner's peers.",
    },
    "ngrok": {
        "name": "ngrok (reverse tunnel service)",
        "kind": "tunnel",
        "domains": ["ngrok.io", "ngrok.com", "ngrok-agent.com", "ngrok.app", "ngrok-free.app", "ngrok.dev"],
        "ports": [{"port": 443, "protocol": "tcp", "role": "agent session (uncertain for older agents)", "distinctive": False}],
        "what_it_does": "Publishes a local service at a public ngrok URL or TCP address.",
        "normal_client_traffic": (
            "The agent holds one long-lived TLS session to ngrok's servers "
            "(connect.ngrok-agent.com:443 for current agents; uncertain for older "
            "versions) with periodic heartbeats; visitor traffic is multiplexed "
            "over it."
        ),
        "abuse": "Widely used to host phishing pages and to reach C2 servers or backdoors inside networks.",
        "c2_victim_would_show": (
            "A victim of C2 behind ngrok would connect to an ngrok tunnel hostname "
            "(e.g. *.ngrok.io / *.ngrok-free.app, or a tcp ngrok address and port) "
            "rather than the agent endpoint (uncertain)."
        ),
    },
    "playit": {
        "name": "playit.gg (game-server tunnel)",
        "kind": "tunnel",
        "domains": ["playit.gg", "ply.gg", "joinmc.link"],
        "ports": [],  # agent ports uncertain, so no port-only match
        "what_it_does": "Exposes a local game server (or any TCP/UDP port) through playit's edge servers.",
        "normal_client_traffic": (
            "A long-lived tunnel from the agent to playit's servers (uncertain: "
            "exact ports and protocol). Visitor traffic flows over it."
        ),
        "abuse": (
            "*.ply.gg hostnames are often listed on threat feeds as C2 for "
            "commodity RATs (e.g. AsyncRAT, XWorm) hidden behind the tunnel."
        ),
        "c2_victim_would_show": (
            "A victim would connect to a *.ply.gg tunnel hostname and port, not "
            "run the playit agent (uncertain)."
        ),
    },
}

# IP ranges that front many unrelated services. Checked offline, before any
# ASN lookup, so a flagged IP on them is recognised even without flow rows.
SHARED_IP_RANGES: dict[str, dict] = {
    "aws_global_accelerator": {
        "name": "AWS Global Accelerator (anycast)",
        "cidrs": ["13.248.0.0/16", "76.223.0.0/16"],
        "kind": "cdn",
        "notes": (
            "Anycast front end that many unrelated AWS customers put in front of "
            "their services (web hosts, site builders, APIs). One IP serves many "
            "unrelated sites, so the IP alone says little about which one the "
            "host visited."
        ),
    },
    "cloudflare": {
        "name": "Cloudflare (published edge ranges)",
        "cidrs": ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
                  "141.101.64.0/18", "108.162.192.0/18", "188.114.96.0/20", "190.93.240.0/20",
                  "197.234.240.0/22", "198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22",
                  "103.22.200.0/22", "103.31.4.0/22", "131.0.72.0/22"],
        "kind": "cdn",
        "notes": "Cloudflare's reverse-proxy edge: one IP fronts thousands of unrelated websites.",
    },
}

# ASNs whose IPs are shared by many unrelated customers. "cdn" = a front end
# where one IP serves many sites; "cloud" = shared cloud edge; "hosting" = VPS,
# where one IP is usually one customer's server (which may itself be a
# public service used by many, like bore.pub).
SHARED_ASNS: dict[str, dict] = {
    "13335": {"org": "Cloudflare", "kind": "cdn"},
    "16509": {"org": "Amazon (AWS)", "kind": "cloud"},
    "14618": {"org": "Amazon (AWS)", "kind": "cloud"},
    "15169": {"org": "Google", "kind": "cloud"},
    "396982": {"org": "Google Cloud", "kind": "cloud"},
    "8075": {"org": "Microsoft", "kind": "cloud"},
    "20940": {"org": "Akamai", "kind": "cdn"},
    "16625": {"org": "Akamai", "kind": "cdn"},
    "54113": {"org": "Fastly", "kind": "cdn"},
    "14061": {"org": "DigitalOcean", "kind": "hosting"},
}

# Dynamic DNS providers (registered domains). NanoCore and other commodity
# RATs often use these for C2, so a hit is a threat signal.
DYNAMIC_DNS_DOMAINS = (
    "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info", "noip.com", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net", "serveftp.com", "servehttp.com", "myftp.biz",
    "myftp.org", "redirectme.net", "servebeer.com", "freeddns.org", "dynu.net", "dynu.com",
    "dyndns.org", "dyndns.biz", "changeip.com", "afraid.org", "mooo.com", "3utilities.com",
    "bounceme.net", "ddnsking.com", "gotdns.ch", "linkpc.net", "publicvm.com", "kozow.com",
)
# Free hosting / site builders often used for throwaway phishing or payloads.
FREE_HOSTING_DOMAINS = (
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "glitch.me", "firebaseapp.com",
    "web.app", "herokuapp.com", "repl.co", "godaddysites.com", "square.site",
)

# Root domains that hint at the host's operating system (step 7 platform
# check). Weak on their own: many are also used by other platforms.
PLATFORM_HINT_DOMAINS: dict[str, tuple[str, ...]] = {
    "windows": ("windowsupdate.com", "windows.com", "msftconnecttest.com", "msftncsi.com"),
    "apple": ("apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "aaplimg.com"),
    "android": ("android.com",),
    "linux": ("ubuntu.com", "debian.org", "canonical.com", "snapcraft.io", "archlinux.org",
              "fedoraproject.org", "centos.org"),
}

# Root domains that hint at what a host is used for (report: "what is this
# host?"). Generic and incomplete on purpose; a hint, never proof.
HOST_ACTIVITY_HINTS: dict[str, tuple[str, ...]] = {
    "self-hosted media": (
        "jellyfin.org", "plex.tv", "plex.direct", "emby.media", "lidarr.audio", "sonarr.tv", "radarr.video",
        "readarr.com", "prowlarr.com", "opensubtitles.org", "opensubtitles.com", "thetvdb.com", "themoviedb.org",
        "trakt.tv", "musicbrainz.org", "fanart.tv", "newshosting.com", "eweka.nl", "easynews.com",
        "usenetserver.com", "nzbgeek.info", "nzbplanet.net", "1337x.to", "nyaa.si", "thepiratebay.org",
    ),
    "home lab or self-hosted services": (
        "home-assistant.io", "hacs.xyz", "nabucasa.com", "talos.dev", "rancher.io", "k3s.io", "proxmox.com",
        "truenas.com", "unraid.net", "portainer.io", "docker.io", "docker.com", "ghcr.io", "linuxserver.io",
    ),
    "software development": (
        "github.com", "githubusercontent.com", "gitlab.com", "npmjs.org", "npmjs.com", "pypi.org",
        "pythonhosted.org", "crates.io", "rust-lang.org", "golang.org", "stackoverflow.com", "jetbrains.com",
        "visualstudio.com", "anaconda.org", "huggingface.co",
    ),
    "gaming": (
        "steampowered.com", "steamcontent.com", "steamserver.net", "epicgames.com", "riotgames.com",
        "xboxlive.com", "playstation.net", "minecraft.net", "mojang.com", "battle.net", "ea.com", "roblox.com",
    ),
    "streaming and social media": (
        "youtube.com", "googlevideo.com", "netflix.com", "nflxvideo.net", "spotify.com", "tiktokcdn.com",
        "tiktokv.com", "instagram.com", "facebook.com", "fbcdn.net", "twitch.tv", "discord.com", "discord.gg",
    ),
}

# ASN organisations whose IPs are shared front-ends for many unrelated sites.
SHARED_FRONTEND_ASN_KEYWORDS = ("cloudflare", "akamai", "fastly", "incapsula", "cdn77", "edgecast")
# Cloud/VPS providers: one IP is usually one customer's server, but that
# customer may be a public service shared by many users (e.g. bore.pub).
CLOUD_VPS_ASN_KEYWORDS = (
    "digitalocean", "amazon", "google", "microsoft", "ovh", "hetzner", "linode",
    "vultr", "choopa", "contabo", "oracle", "alibaba", "m247",
)

PROTOCOL_NAMES = {6: "tcp", 17: "udp"}


def protocol_name(number) -> str:
    try:
        return PROTOCOL_NAMES.get(int(number), str(number))
    except (TypeError, ValueError):
        return str(number)


def get_profile(malware: str | None, threat_type: str | None) -> dict:
    """Malware family and threat type profiles for one case."""
    malware_key = (malware or "").strip().lower()
    threat_key = (threat_type or "").strip().lower()
    return {
        "malware_profile": MALWARE_PROFILES.get(malware_key, DEFAULT_MALWARE_PROFILE),
        "threat_type_profile": THREAT_TYPE_PROFILES.get(threat_key, DEFAULT_THREAT_TYPE_PROFILE),
    }


def _domain_matches(domain: str, service_domain: str) -> bool:
    return domain == service_domain or domain.endswith("." + service_domain)


def match_service(domain: str | None = None, port: int | None = None,
                  protocol: str | None = None) -> dict | None:
    """Find the service profile for a domain and/or port.

    A domain match wins. A port-only match needs the port to be marked
    distinctive, and the protocol to agree when one is given.
    Returns {"key", "profile", "matched_on"} or None.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    for key, profile in SERVICE_PROFILES.items():
        if domain and any(_domain_matches(domain, d) for d in profile["domains"]):
            return {"key": key, "profile": profile, "matched_on": f"domain {domain}"}

    if port is None:
        return None
    for key, profile in SERVICE_PROFILES.items():
        for entry in profile["ports"]:
            if not entry["distinctive"] or entry["port"] != int(port):
                continue
            if protocol and entry["protocol"] != protocol:
                continue
            return {"key": key, "profile": profile, "matched_on": f"port {port}/{entry['protocol']}"}
    return None


def expected_service_port(service_key: str, port: int, protocol: str | None = None) -> dict | None:
    """The profile's entry for this port, if the service normally uses it."""
    profile = SERVICE_PROFILES.get(service_key)
    if not profile:
        return None
    for entry in profile["ports"]:
        if entry["port"] == int(port) and (protocol is None or entry["protocol"] == protocol):
            return entry
    return None


def classify_asn(asn_org: str | None) -> str | None:
    """'shared_frontend', 'cloud_vps' or None for an ASN organisation name."""
    org = (asn_org or "").lower()
    if not org:
        return None
    if any(k in org for k in SHARED_FRONTEND_ASN_KEYWORDS):
        return "shared_frontend"
    if any(k in org for k in CLOUD_VPS_ASN_KEYWORDS):
        return "cloud_vps"
    return None
