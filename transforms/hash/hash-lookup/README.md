# Hash Lookup

Looks up a file hash (MD5, SHA-1, SHA-256) on VirusTotal for threat intelligence. Enriches the hash entity with detection ratio, file type, size, and submission dates.

## Input / Output

- **Input**: `Hash`
- **Output**: `Hash` (enriched with VirusTotal data)

## API Keys Required

- **VirusTotal API key** (`VIRUSTOTAL_API_KEY`) — get one at https://www.virustotal.com

Configure via Settings > API Keys in the OGI UI.

## Properties Added

- `detection_ratio` — e.g., "15/72"
- `file_type` — e.g., "PE32 executable"
- `file_size` — in bytes
- `first_seen` — first submission date
- `last_seen` — last analysis date
