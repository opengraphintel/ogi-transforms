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
- Core site concepts such as:
  - `message`
  - `status_code`
  - `response_url`
  - headers, URL templates, rank, disabled flags, and username regex checks

## What Is Not Adopted

- Upstream Maigret Python package as a runtime dependency
- HTML/PDF/XMind reporting
- Web UI
- Recursive identifier extraction
- Activation hooks for complex site-specific auth refresh flows

## Settings

- `top_sites`: maximum number of ranked sites to query from the vendored database
- `include_disabled_sites`: include disabled site entries
- `timeout_seconds`: per-request timeout
- `max_results`: cap returned claimed accounts

## Notes

- This plugin only emits claimed accounts.
- It is intentionally more conservative than full upstream Maigret.
- Results are evidence-based account-presence findings, not identity proof.
- Some upstream site definitions may require future adaptation as websites change.
- The vendored Maigret data remains subject to upstream drift and should be refreshed periodically.

## Upstream Attribution

- Upstream project: Maigret
- Upstream repository: https://github.com/soxoj/maigret
- Upstream license: MIT
- Vendored asset: `maigret/resources/data.json`
