# URL to Outbound Links

Fetches an HTML page and extracts outbound links from anchor tags (`<a href=...>`), including relative URL normalization.

## Input / Output

- **Input**: `URL`
- **Output**: `URL` and `Domain` entities (up to 100 links)

## Behavior

- Resolves relative links against the final fetched page URL
- Skips unsupported links (`mailto:`, `tel:`, `javascript:`, fragment-only)
- Creates `links to` edges from source URL to discovered URLs

## API Keys

None required.
