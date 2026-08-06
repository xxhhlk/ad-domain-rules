#!/usr/bin/env python3
"""Convert AdGuard Home filter rules from multiple sources into a Surge domain-set file.

Supported input syntaxes (auto-detected per line):
  - AdGuard Home:  ||example.com^   ||example.com^$important   ||*.example.com^
  - AdGuard w/ wildcard in the middle:  ||*pcdn*.biliapi.net^$important
  - Hosts style:   0.0.0.0 example.com   /   127.0.0.1 example.com
  - Plain domain:  example.com
  - Surge/Clash style:  DOMAIN,example.com   DOMAIN-SUFFIX,example.com

Lines that are skipped on purpose:
  - comments (! or #), cosmetic rules (## #@# #?# #$#)
  - regex rules (/.../), whitelist exceptions (@@...)
  - disabled meta-rules ($badfilter)
  - IP addresses and anything that is not a valid domain
"""
import re
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

# All upstream rule sources (order does not matter; output is sorted & deduped).
SOURCES = [
    # --- AdGuardTeam Hostlists Registry (AdGuard DNS filter syntax) ---
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_45.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    # --- anti-AD (discretion branch) ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/privacy-protection-tools/anti-AD/refs/heads/master/discretion/pcdn.txt",
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/privacy-protection-tools/anti-AD/refs/heads/master/discretion/dns.txt",
    # --- PCDN / p2pcdn blocklists ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/susetao/PCDNFilter-CHN-/refs/heads/main/PCDNFilter.txt",
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/thhbdd/Block-pcdn-domains/refs/heads/main/ban.txt",
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/Womsxd/MyAdBlockRules/refs/heads/master/p2pcdnblock.txt",
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/Womsxd/MyAdBlockRules/refs/heads/master/httpdnsblock.txt",
    # --- GetSomeFries HTTPDNS block (Surge DOMAIN, style) ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/VirgilClyne/GetSomeFries/refs/heads/main/ruleset/HTTPDNS.Block.list",
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/VirgilClyne/GetSomeFries/refs/heads/main/ruleset/HTTPDNS.Block.list",
    # --- AdGuard-AntiPCDN-Rules ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/xianhongtao/AdGuard-AntiPCDN-Rules/refs/heads/main/adguard.txt",
    # --- Cats-Team AdRules DNS rules ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/Cats-Team/AdRules/refs/heads/script/mod/rules/dns-rules.txt",
    # --- miaoermua AdguardFilter ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/miaoermua/AdguardFilter/main/rule.txt",
    # --- ShadowWhisperer BlockLists (DNS resolvers) ---
    "https://globalbal.xxhhlk.com:8880/rawgoodhouse/ShadowWhisperer/BlockLists/refs/heads/master/Lists/DNS",
    # --- Live AdGuardHome rule dump ---
    "https://globalbal.xxhhlk.com:8880/agh-api/rules",
]

OUTPUT = "ad-domain-set.txt"
TIMEOUT = 60
USER_AGENT = "ad-domain-rules-builder/1.0"

# A valid domain: at least one letter somewhere; every label must START and END
# with an alphanumeric (so no leading/trailing hyphens like "-ad" or "ad-").
_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
DOMAIN_RE = re.compile(r"^(?=.*[a-z])(?:" + _LABEL + r"\.)+[a-z]{2,}$", re.I)
HOSTS_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}\s+(\S+)")
SURGE_RE = re.compile(r"^(?:DOMAIN|DOMAIN-SUFFIX),(\S+)", re.I)


def fetch(url):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return resp.read().decode("utf-8", "ignore")


def normalize(raw):
    """Turn a raw token into a clean, lower-cased domain or return None if invalid."""
    if not raw:
        return None
    dom = raw.strip().lower().strip(".")
    if not dom:
        return None
    # Wildcard handling: keep the longest static suffix after the last '*'.
    # If that fragment itself starts with '-' it is an ambiguous artifact of a
    # rule like ||v*-ad.example.com^ and cannot be safely turned into a domain,
    # so we drop it rather than inventing a wrong/leading-hyphen domain.
    if "*" in dom:
        frag = dom.rsplit("*", 1)[-1].strip(".")
        if not frag or frag.startswith("-"):
            return None
        dom = frag
    # Defensive: never let a leading hyphen survive.
    dom = dom.lstrip("-")
    if not dom:
        return None
    # Drop any leftover anchor pipes.
    dom = dom.replace("|", "")
    # Reject anything that is not a clean domain (paths, spaces, backslashes).
    if "/" in dom or " " in dom or "\\" in dom:
        return None
    if not DOMAIN_RE.match(dom):
        return None
    return dom


def extract(line):
    s = line.strip()
    if not s:
        return None
    # Comments / cosmetic rules / regex / whitelist exceptions / disabled meta-rules.
    if s.startswith("!"):
        return None
    # Rule-level negation / exception (whitelist) rules: "-domain^" or "-domain".
    # These mean "do NOT block", so they must never enter a blocklist.
    if s.startswith("-"):
        return None
    if s.startswith("#"):
        return None
    if s.startswith("@@"):
        return None
    if "##" in s or "#@#" in s or "#?#" in s or "#$#" in s:
        return None
    if s.startswith("/") and s.endswith("/"):
        return None
    if "badfilter" in s.lower():
        return None
    # Surge / Clash style: DOMAIN,x  /  DOMAIN-SUFFIX,x
    m = SURGE_RE.match(s)
    if m:
        return normalize(m.group(1))
    # AdGuard Home style: ||domain^  (modifiers after ^ or $)
    if s.startswith("||"):
        rest = s[2:]
        if rest.startswith("-"):  # ||-domain^ is also a negation rule
            return None
        cand = re.split(r"[\^\$]", rest, maxsplit=1)[0]
        return normalize(cand)
    # Hosts style:  IP  domain
    m = HOSTS_RE.match(s)
    if m:
        return normalize(m.group(2))
    # Plain domain line.
    if DOMAIN_RE.match(s):
        return normalize(s)
    return None


def main():
    domains = set()
    stats = {"sources": 0, "failed": 0, "lines": 0}
    for url in SOURCES:
        stats["sources"] += 1
        try:
            text = fetch(url)
        except Exception as exc:  # noqa: BLE001 - keep going if one source is down
            stats["failed"] += 1
            print(f"[WARN] failed to fetch {url}: {exc}", file=sys.stderr)
            continue
        for line in text.splitlines():
            stats["lines"] += 1
            dom = extract(line)
            if dom:
                domains.add(dom)

    # Surge DOMAIN-SET semantics: a bare "example.com" is an EXACT match (does
    # not catch subdomains), while a leading-dot ".example.com" is a
    # DOMAIN-SUFFIX match (catches the domain AND all subdomains) -- this is the
    # form AdGuard's ||domain^ maps to and is what ad filtering wants. So we
    # always emit the leading-dot form.
    out = sorted(domains)
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        if out:
            fh.write("\n".join("." + d for d in out) + "\n")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(
        f"[INFO] sources={stats['sources']} failed={stats['failed']} "
        f"lines_scanned={stats['lines']} unique_domains={len(out)}"
    )
    print(f"[INFO] wrote {len(out)} domains to {OUTPUT} ({ts})")


if __name__ == "__main__":
    main()
