# Content to IOCs

Extracts common IOCs from `Document` content and creates entity nodes for discovered indicators.

## Input / Output

- **Input**: `Document`
- **Output**: `URL`, `IPAddress`, `Domain`, `EmailAddress`, `Hash`

## Extraction Strategy

1. Uses `iocsearcher` if available.
2. Falls back to internal regex extraction when unavailable.

This keeps extraction working even when the optional dependency is missing.

## API Keys

None required.
