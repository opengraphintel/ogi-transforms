# Domain to Shodan Attack Surface

Uses Shodan's domain information API to map a domain's observed DNS attack surface and emit graph entities for subdomains, IPs, MX records, and nameserver-related records.

## Input / Output

- Input: `Domain`
- Output: `Domain`, `Subdomain`, `IPAddress`, `MXRecord`, `NSRecord`, `Nameserver`

The transform enriches the root domain and emits related DNS entities from Shodan's domain dataset.

## API Keys

This transform requires a Shodan API key.

Configure it in OGI under `API Keys` using the `shodan` service. Do not place API keys in transform settings.

## What It Adds

The input domain may be enriched with:

- `shodan_domain`
- `shodan_tags`
- `shodan_subdomains`
- `shodan_record_count`

The transform can emit:

- `Subdomain` entities from Shodan subdomain enumeration
- `IPAddress` entities from `A` and `AAAA` records
- `MXRecord` entities from `MX` records
- `NSRecord` entities from `NS` records
- `Nameserver` entities when nameserver-style targets are present
- `Domain` entities for CNAME-style targets

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request
- `max_results`: maximum number of DNS records to process
- `include_history`: include historical DNS records from Shodan

## Notes

- This transform uses Shodan's `dns/domain/{domain}` endpoint.
- It is intended for domain attack-surface mapping, not raw DNS resolution.
- Historical mode can produce noisier graphs because it includes stale observations.