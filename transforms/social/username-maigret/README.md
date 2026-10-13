# Username OSINT (Maigret Adoption)

Uses an OGI-native checker with a vendored copy of Maigret's `data.json` site database instead of depending on the upstream `maigret` package at runtime.

This is an adoption-style community plugin: it preserves the valuable upstream site definitions while keeping the execution model compatible with OGI's current shared runtime.

## Input / Output

- Input: `SocialMedia`, `Person`, or `Username`
- Output: `SocialMedia` and `URL`

Recommended flow:
- `Person -> person_to_usernames -> Username OSINT (Maigret Adoption)`
- `Username -> Username OSINT (Maigret Adoption)`
- `SocialMedia` input works when `entity.value` already resembles a username/handle

## What Is Adopted

- Vendored site database from Maigret: `resources/data.json`
- Engine templates (XenForo, Discourse/DiscourseJson, MediaWiki/MediaWikiJson, Lemmy, Mastodon, Vanilla, phpBB, vBulletin, uCoz and others), applied the way Maigret applies them: lists and dicts combine, a value the site states itself wins
- The three check types: `message`, `status_code`, `response_url`
- Per-site URL templates, probe URLs, subpaths, headers, `regexCheck`, `requestMethod`/`requestPayload` (POST), `ignore403`, response `encoding`, ranks, tags and disabled flags
- Maigret's error detection: the site's own `errors` markers, the common CAPTCHA and bot-challenge markers, and 401/403/429/999/5xx answers all count as unknown, never as found or not found

One deliberate difference: on `message` sites a 404 or 410 answer counts as not found. Maigret ignores the status there, so once a site moves its profile URLs, a generic 404 page that lacks the site's absence strings reads as a claimed account for every username. About 200 sites in the database rely on absence strings alone.

## What Is Not Adopted

- Upstream Maigret Python package as a runtime dependency
- Sites marked with `protection` (TLS fingerprinting, Cloudflare challenges, IP reputation): skipped by default, because Maigret reaches them with curl_cffi or a Cloudflare bypass service and a plain HTTP client is refused. `include_protected_sites` probes them anyway.
- Sites with a `protocol` of `dns`, `tor` or `i2p`, which need gateways
- Cookies, proxies and activation hooks for site-specific auth refresh flows
- HTML/PDF/XMind reporting, the web UI, and recursive identifier extraction

## Settings

- `top_sites`: maximum number of sites to query, most popular first (10-1000, default 200)
- `site_tags`: comma-separated Maigret tags or engine names, such as `forum`, `wiki`, `de` or `DiscourseJson`; a site matches if it has any of them. Empty means the most popular sites. About 4,300 sites in the database have no popularity rank, so use tags to reach them.
- `include_disabled_sites`: include entries Maigret marks as disabled
- `include_protected_sites`: include bot-protected entries (see above)
- `timeout_seconds`: per-request timeout
- `max_results`: cap returned claimed accounts
- `concurrency`: maximum concurrent site checks

## Notes

- This plugin only emits claimed accounts. The run messages count sites found, not found, unknown (with the main reasons) and skipped.
- Results are evidence-based account-presence findings, not identity proof.
- Some upstream site definitions may require future adaptation as websites change.

## Refreshing the Vendored Database

1. Download `maigret/resources/data.json` from the Maigret release tag, for example `https://raw.githubusercontent.com/soxoj/maigret/v0.6.6/maigret/resources/data.json`, into `resources/data.json`.
2. Update `MAIGRET_VERSION` in `transforms/username_maigret.py` and the table below.
3. Run `pytest tests/`: the database tests check that every selectable site renders its URLs and POST bodies and that every `regexCheck` compiles.
4. Look at Maigret's `checking.py`, `sites.py` and `errors.py` for new check types, site fields or common error markers.

## Upstream Attribution

| | |
|---|---|
| Upstream project | Maigret |
| Upstream repository | https://github.com/soxoj/maigret |
| Upstream license | MIT, see `resources/MAIGRET_LICENSE` |
| Vendored asset | `maigret/resources/data.json` |
| Vendored release | v0.6.6 |
| sha256 | `ef6ca66efa174209c10205ff86f7e975b591128681710639fdc786ff05e662da` |

The common error markers in `transforms/username_maigret.py` are taken from Maigret's `maigret/errors.py`.
