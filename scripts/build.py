#!/usr/bin/env python3
"""Convert AdGuard Home filter rules into Surge block lists.

Produces two files:

  1. ad-domain-set.txt  -- a Surge DOMAIN-SET (one domain per line) built from
     many AdGuard/DNS/PCDN/HTTPDNS sources. The domain-set conversion is
     *semantic*: each source rule type maps to the Surge form that preserves
     its original blocking scope (per the AdGuard DNS filtering syntax docs and
     Surge's domain-set spec):

  AdGuard rule                       AdGuard scope              Surge form
  --------------------------------  -------------------------  --------------------------
  ||example.com^        (no *)      domain + all subdomains    .example.com   (suffix)
  ||*.example.com^                    subdomains ONLY           *.example.com  (sub-only)
  ||sub.example.com^    (no *)      sub.example.com + subs     .sub.example.com (suffix)
  example.com           (plain)     domain ONLY (no subs)      example.com    (exact)
  0.0.0.0 example.com   (hosts)     host ONLY (no subs)        example.com    (exact)
  DOMAIN,example.com                  exact                     example.com    (exact)
  DOMAIN-SUFFIX,example.com           suffix                    .example.com   (suffix)

Notes:
  * A rule present as both "exact" and "sub-only" is merged to "suffix"
    (domain + subdomains = the union of the two intents).
  * AdGuard wildcard rules whose '*' is NOT a lone leading label
    (e.g. ||prebid-*.rubiconproject.com^, ||*example.com^, ||ex.*^) cannot be
    expressed faithfully in a Surge domain-set without over-blocking, so they
    are skipped on purpose. In practice most of their parent domains are
    already covered by a ||domain^ suffix rule.
  * Comments (!/#), cosmetic rules (## #@# #?# #$#), regex (/.../),
    whitelist exceptions (@@...), rule-level negations (-... / ||-...), and
    disabled meta-rules ($badfilter) are all skipped.
"""
import ipaddress
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

# Live AdGuardHome IP dump, converted into a Surge IP rule-set (action baked in).
IP_SOURCE = "https://globalbal.xxhhlk.com:8880/agh-api/ips"
IP_OUTPUT = "ad-ip-ruleset.txt"
IP_POLICY = "REJECT-NO-DROP"

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
    """Return (form, domain) where form is one of 'suffix' / 'subonly' / 'exact',
    or None if the line is not a usable blocking rule.

    Surge domain-set forms:
      'suffix'  -> ".domain"   (DOMAIN-SUFFIX: domain + all subdomains)
      'subonly' -> "*.domain"  (subdomains only, NOT the domain itself)
      'exact'   -> "domain"    (DOMAIN: exact match, no subdomains)
    """
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
        dom = normalize(m.group(1))
        if not dom:
            return None
        return ("suffix" if s.upper().startswith("DOMAIN-SUFFIX") else "exact", dom)
    # AdGuard Home style: ||domain^  (modifiers after ^ or $)
    if s.startswith("||"):
        rest = s[2:]
        if rest.startswith("-"):  # ||-domain^ is also a negation rule
            return None
        cand = re.split(r"[\^\$]", rest, maxsplit=1)[0]
        if "*" in cand:
            # The only wildcard we can express faithfully is a lone leading '*'
            # as the whole first label: ||*.example.com^  ->  *.example.com
            # (subdomains only, NOT the base domain). Anything else
            # (||prebid-*.x^, ||*x^, ||x*^, ||x.*^) cannot be represented in a
            # Surge domain-set without over-blocking, so we drop it.
            if cand.startswith("*.") and "*" not in cand[2:]:
                dom = normalize(cand[2:])
                if dom:
                    return ("subonly", dom)
            return None
        dom = normalize(cand)
        if dom:
            return ("suffix", dom)
        return None
    # Hosts style:  IP  domain  -> host only, not its subdomains.
    m = HOSTS_RE.match(s)
    if m:
        dom = normalize(m.group(2))
        if dom:
            return ("exact", dom)
        return None
    # Plain domain line -> domain only, not its subdomains.
    if DOMAIN_RE.match(s):
        dom = normalize(s)
        if dom:
            return ("exact", dom)
        return None
    return None


def build_domain_set():
    # domain -> set of forms seen ('suffix' / 'subonly' / 'exact')
    forms = {}
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
            r = extract(line)
            if r is None:
                continue
            form, dom = r
            forms.setdefault(dom, set()).add(form)

    # Merge forms per domain into a single Surge line:
    #   - 'suffix' present                       -> ".domain"
    #   - 'exact' + 'subonly' (union = dom+subs) -> ".domain"
    #   - 'subonly' only                         -> "*.domain"
    #   - 'exact' only                           -> "domain"
    out = []
    n_suffix = n_subonly = n_exact = 0
    for dom in sorted(forms):
        f = forms[dom]
        if "suffix" in f or ("subonly" in f and "exact" in f):
            out.append("." + dom)
            n_suffix += 1
        elif "subonly" in f:
            out.append("*." + dom)
            n_subonly += 1
        else:
            out.append(dom)
            n_exact += 1

    with open(OUTPUT, "w", encoding="utf-8") as fh:
        if out:
            fh.write("\n".join(out) + "\n")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(
        f"[INFO] sources={stats['sources']} failed={stats['failed']} "
        f"lines_scanned={stats['lines']} unique_domains={len(out)}"
    )
    print(
        f"[INFO] forms -> suffix={n_suffix} subonly={n_subonly} exact={n_exact} "
        f"(all in {OUTPUT}, {ts})"
    )


def parse_ip(line):
    """Parse a plain IPv4/IPv6 address or CIDR line into a Surge rule tuple
    (rule_type, normalized_cidr), or None if invalid / a comment.

    A bare address (no prefix) is normalized to its host route:
    IPv4 -> /32, IPv6 -> /128. This is the faithful, explicit form.
    """
    s = line.strip()
    if not s or s.startswith(("!", "#")):
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    rtype = "IP-CIDR" if net.version == 4 else "IP-CIDR6"
    return (rtype, str(net))


def build_ip_ruleset():
    """Fetch the live AdGuardHome IP dump and emit a Surge IP rule-set whose
    every line carries the REJECT-NO-DROP action, e.g.:

        IP-CIDR,1.2.3.4/32,REJECT-NO-DROP
        IP-CIDR6,2a11::/128,REJECT-NO-DROP

    A bare address is normalized to a host route (/32 for IPv4, /128 for IPv6).
    If the source is unreachable we skip writing so the last good file is kept.
    """
    rows = set()
    try:
        text = fetch(IP_SOURCE)
    except Exception as exc:  # noqa: BLE001 - keep the last good file on failure
        print(f"[WARN] failed to fetch {IP_SOURCE}: {exc}", file=sys.stderr)
        return
    scanned = 0
    for line in text.splitlines():
        scanned += 1
        p = parse_ip(line)
        if p:
            rows.add(p)
    out = sorted(rows)
    with open(IP_OUTPUT, "w", encoding="utf-8") as fh:
        if out:
            fh.write("\n".join(f"{t},{c},{IP_POLICY}" for t, c in out) + "\n")
    n4 = sum(1 for t, _ in out if t == "IP-CIDR")
    n6 = len(out) - n4
    print(
        f"[INFO] ip ruleset -> IPv4={n4} IPv6={n6} scanned={scanned} "
        f"(all in {IP_OUTPUT}, action={IP_POLICY})"
    )


def main():
    build_domain_set()
    build_ip_ruleset()


if __name__ == "__main__":
    main()
