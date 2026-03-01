# Certificate Transparency Lookup

Queries crt.sh to discover subdomains via Certificate Transparency logs. Filters out wildcards and deduplicates results, with a limit of 500 subdomains.

## Input / Output

- **Input**: `Domain`
- **Output**: `Subdomain` entities

## API Keys

None required. Uses the free crt.sh API.

## Limitations

- Results limited to 500 unique subdomains
- Wildcard entries are excluded
- Depends on crt.sh availability
