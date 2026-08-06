# ad-domain-rules

A merged **Surge `DOMAIN-SET`** blocklist, automatically built from a set of
AdGuard Home / anti-PCDN / anti-HTTPDNS rule sources.

## Output

- **`ad-domain-set.txt`** — a plain, sorted, de-duplicated list of domains
  (one per line). Use it directly as a Surge domain-set:

  ```ini
  [Rule]
  DOMAIN-SET,https://raw.githubusercontent.com/xxhhlk/ad-domain-rules/main/ad-domain-set.txt,REJECT
  ```

  (or `policy` / `DIRECT` / any policy you prefer instead of `REJECT`).

## How it is built

A GitHub Actions workflow (`.github/workflows/update.yml`) runs
`scripts/build.py` on a weekly schedule and on manual dispatch. The script:

1. Downloads every source listed in `SOURCES` inside `scripts/build.py`.
2. Parses each line and extracts domains from several syntaxes:
   - AdGuard Home: `||example.com^`, `||example.com^$important`, `||*.example.com^`
   - Hosts style: `0.0.0.0 example.com`
   - Plain domains: `example.com`
   - Surge/Clash style: `DOMAIN,example.com`, `DOMAIN-SUFFIX,example.com`
3. Drops comments, cosmetic rules, regex rules, whitelist exceptions (`@@…`),
   disabled meta-rules (`$badfilter`) and anything that is not a valid domain.
4. Sorts and de-duplicates, then writes `ad-domain-set.txt` and commits it back.

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
