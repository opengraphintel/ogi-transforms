# Changelog

## 1.3.0

- Updated the vendored database to Maigret v0.6.6: 5,897 sites, up from 3,143, mostly forums, discussion boards and wikis, plus the new DiscourseJson, MediaWikiJson, Lemmy, Mastodon and Vanilla engines.
- Fixed engine templates never being applied. Sites that rely on an engine for their URL (about 45% of the old database and 57% of the new one) were silently skipped, and engine sites with their own URL lost their check type and strings, so sites such as GitHubGist reported every username as claimed.
- Fixed `presenseStrs`, the spelling Maigret's data uses, being ignored. Message checks on those sites lost their presence test.
- Fixed nested keys being rewritten to snake_case, which mangled per-site headers (`User-Agent` became `user-_agent`) and error markers.
- Added Maigret's `regexCheck`, `requestMethod`/`requestPayload` (POST), `ignore403`, response `encoding` and per-site `errors` handling.
- Block pages, CAPTCHAs and 401/403/429/999/5xx answers now count as unknown instead of found or not found, using Maigret's common error markers.
- A 404 or 410 answer on a message-check site now counts as not found, so a site that moved its profile URLs no longer reports every username as claimed. This is stricter than Maigret.
- Sites marked as bot-protected are skipped by default; added `include_protected_sites` to probe them anyway.
- Sites that need DNS, Tor or I2P gateways, and message checks with neither presence nor absence strings, are skipped.
- Added `site_tags` to scan forums, wikis, countries or one engine instead of only the most popular sites.
- The summary message now counts not found, unknown (with the main reasons) and skipped sites.
- The site database is parsed once per process instead of on every run.
- Added Maigret's licence as `resources/MAIGRET_LICENSE` and recorded the vendored release and checksum in the README.
- Added tests.

## 1.2.1

- Added long-form documentation (long_description, when_to_use, limitations, example_use_cases) for the transform info dialog.

## 1.2.0

- Parallel site scanning using asyncio.gather with configurable concurrency (default 20).
- Added `concurrency` setting (range 1-50) to control maximum concurrent site checks.
- Aligned httpx connection pool limits with the concurrency setting.

## 1.1.0

- Replaced direct Maigret package dependency with an adoption-style OGI-native checker.
- Vendored Maigret `data.json` into the plugin resources.
- Reduced runtime dependency surface to lightweight HTTP-based checking only.

## 1.0.0

- Initial community plugin scaffold for Maigret-backed username discovery.
