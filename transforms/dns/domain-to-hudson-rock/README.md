# Domain to Hudson Rock

Checks a domain against [Hudson Rock](https://www.hudsonrock.com/)'s free
infostealer intelligence (the Cavalier "OSINT tools" tier) and maps the domain's
employee/user compromise statistics and third-party exposure onto the graph.

## Input / Output

- **Input**: `Domain`
- **Output**: `Domain`, `URL`, `Document`

## What it produces

When the domain appears in Hudson Rock's infostealer database, the transform:

- Enriches the input `Domain` with summary properties (total infections,
  employees/users compromised, third-party count, exposed-URL count, Shopify
  flag, last employee/user compromise dates, stealer families).
- Emits a `Document` breach report summarizing the stats, stealer families,
  applications, third-party domains, and top exposed login URLs.
- Emits exposed third-party domains as `Domain` entities (`third-party exposure`).
- Emits top exposed employee/client login URLs as `URL` entities
  (`employee credentials exposed` / `client credentials exposed`).

If the domain has no data, the transform reports that and produces nothing.

## API keys

None required. Hudson Rock's OSINT-tools endpoints are free and unauthenticated
(rate limited). No key is configured for this transform.

## Settings

- **Timeout Seconds** — HTTP timeout (5–30, default 15).
- **Max Results** — caps third-party `Domain` entities (1–200, default 50).
- **Max URLs** — caps exposed login `URL` entities (0–200, default 25; 0 disables).

## Notes & limitations

- This is **breach data harvested from malware victims** (real personal data).
  Use it only for domains you own or are authorized to investigate, and be
  mindful of where the resulting graph/export is stored.
- The free tier returns aggregate/partially-redacted data and is rate limited.
- Data and attribution: Hudson Rock — https://www.hudsonrock.com/
