# ad-domain-rules

A merged **Surge `DOMAIN-SET`** blocklist plus an **IP `RULE-SET`** blocklist,
automatically built from a set of AdGuard Home / anti-PCDN / anti-HTTPDNS rule
sources.

## Output

- **`ad-domain-set.txt`** — a sorted, de-duplicated list of domains in Surge
  **DOMAIN-SET** format. The conversion is *semantic*: each source rule type is
  mapped to the Surge form that preserves its original blocking scope (per the
  AdGuard DNS filtering syntax and Surge's domain-set spec). Three line forms
  may appear:

  | Source rule (AdGuard)        | Original scope              | Surge line form     | Meaning in Surge            |
  |------------------------------|-----------------------------|---------------------|-----------------------------|
  | `\|\|example.com^` (no `*`)  | domain **+ all subdomains** | `.example.com`      | `DOMAIN-SUFFIX` (dom + subs)|
  | `\|\|*.example.com^`         | **subdomains only**         | `*.example.com`     | subdomains only, not base   |
  | `example.com` (plain)        | domain **only** (no subs)   | `example.com`       | `DOMAIN` exact match        |
  | `0.0.0.0 example.com` (hosts)| host **only** (no subs)     | `example.com`       | `DOMAIN` exact match        |
  | `DOMAIN,example.com`         | exact                       | `example.com`       | `DOMAIN` exact match        |
  | `DOMAIN-SUFFIX,example.com`  | dom + subdomains            | `.example.com`      | `DOMAIN-SUFFIX`             |

  Notes:
  - A domain that appears both as an exact match **and** a subdomain-only match
    is merged to the suffix form `.domain` (the union of the two intents).
  - AdGuard wildcard rules whose `*` is **not** a lone leading label
    (e.g. `||prebid-*.rubiconproject.com^`, `||*example.com^`, `||ex.*^`) cannot
    be expressed faithfully in a Surge domain-set without over-blocking, so they
    are skipped. Most of their parent domains are already covered by a
    `||domain^` suffix rule anyway.

  Use it directly as a Surge domain-set:

  ```ini
  [Rule]
  DOMAIN-SET,https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/ad-domain-set.txt,REJECT
  ```

  (or `policy` / `DIRECT` / any policy you prefer instead of `REJECT`).

- **`ad-ip-ruleset.txt`** — a sorted, de-duplicated **Surge `RULE-SET`** of IP
  rules, one per line, each carrying the `REJECT-NO-DROP` action. IPv4 becomes
  `IP-CIDR,…` and IPv6 becomes `IP-CIDR6,…`; a bare address is normalized to a
  host route (`/32` for IPv4, `/128` for IPv6). It is built from the live
  AdGuardHome IP dump (`agh-api/ips`). Example lines:

  ```text
  IP-CIDR,1.2.3.4/32,REJECT-NO-DROP
  IP-CIDR6,2a11::/128,REJECT-NO-DROP
  ```

  Use it as a Surge rule-set:

  ```ini
  [Rule]
  RULE-SET,https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/ad-ip-ruleset.txt
  ```

  (the `REJECT-NO-DROP` action is already baked into every line, so no policy
  argument is needed when referencing it).

## How it is built

A GitHub Actions workflow (`.github/workflows/update.yml`) runs
`scripts/build.py` on a weekly schedule and on manual dispatch. The script:

1. Downloads every source listed in `SOURCES` inside `scripts/build.py`.
2. Parses each line and extracts domains, preserving scope per rule type:
   - AdGuard Home: `||example.com^` → suffix `.example.com`;
     `||*.example.com^` → subdomain-only `*.example.com`;
     `||sub.example.com^` → suffix `.sub.example.com`.
   - Hosts style: `0.0.0.0 example.com` → exact `example.com`.
   - Plain domains: `example.com` → exact `example.com`.
   - Surge/Clash style: `DOMAIN,example.com` → exact; `DOMAIN-SUFFIX,…` → suffix.
3. Drops comments, cosmetic rules, regex rules, whitelist exceptions (`@@…`),
   rule-level negations (`-…` / `||-…`), disabled meta-rules (`$badfilter`) and
   anything that is not a valid domain.
4. Sorts and de-duplicates, merging per-domain forms, then writes
   `ad-domain-set.txt`.
5. Separately fetches the live AdGuardHome IP dump (`agh-api/ips`), parses each
   plain IPv4/IPv6 address or CIDR (normalizing bare addresses to `/32`/`/128`),
   de-duplicates, and writes `ad-ip-ruleset.txt` with the `REJECT-NO-DROP`
   action on every line.
6. Commits both generated files back to the repo.

If a single source is temporarily unreachable, the build continues with the
others and just logs a warning — it never fails the whole job because one
mirror is down.

## Sources

See the `SOURCES` list in [`scripts/build.py`](scripts/build.py). They include
the AdGuardTeam Hostlists Registry DNS filters plus several anti-PCDN /
anti-HTTPDNS community lists.

## Update cadence

- Weekly (Mondays, 03:17 UTC) via the scheduled workflow.
- Immediately after any change to `scripts/` or the workflow file (push event).
- On demand from the **Actions → Build Surge Domain-Set → Run workflow** button.

## Shadowrocket modules

The `Update Shadowrocket Modules` workflow checks out and runs the
[Script-Hub source](https://github.com/SCript-Hub-Org/Script-Hub) locally. It
does not call the hosted conversion website. The generated files are:

- `shadowrocket/rewrite.sgmodule`
- `shadowrocket/XWebAds.sgmodule`
- `shadowrocket/weibo.sgmodule`

The workflow runs weekly, on changes to its workflow/converter files, or
manually from the Actions tab.
