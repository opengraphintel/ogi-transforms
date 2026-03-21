# Domain to abuse.ch IOCs

Looks up a domain in abuse.ch ThreatFox and enriches the input domain with IOC context. It also creates a summary evidence document and maps related URL and IP IOC records returned by ThreatFox.

## Input / Output

- **Input**: `Domain`
- **Output**: `Domain` (enriched), `URL`, `IPAddress`, and `Document`

## API Keys Required

- **abuse.ch Auth-Key** (`ABUSECH_API_KEY`) — obtain one via the abuse.ch Authentication Portal

Configure via Settings > API Keys in the OGI UI.
