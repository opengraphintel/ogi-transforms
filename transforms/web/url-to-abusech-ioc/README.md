# URL to abuse.ch IOC

Looks up a URL in abuse.ch ThreatFox and enriches the URL entity with IOC intelligence such as threat type, malware family, confidence, reporter, tags, and observed dates. It also creates a summary evidence document.

## Input / Output

- **Input**: `URL`
- **Output**: `URL` (enriched) and `Document` (summary evidence)

## API Keys Required

- **abuse.ch Auth-Key** (`ABUSECH_API_KEY`) — obtain one via the abuse.ch Authentication Portal

Configure via Settings > API Keys in the OGI UI.
