# IP to Shodan Host Intelligence

Looks up a single IP address against Shodan's Host Information API and enriches the input `IPAddress` entity with host intelligence such as ports, ASN, organization, location, and associated hostnames/domains.

## Input / Output

- Input: `IPAddress`
- Output: `IPAddress`, `ASNumber`, `Organization`, `Domain`, `Subdomain`, `Location`

The transform enriches the existing IP entity and also emits related graph entities for high-value reusable facts.

## API Keys

This transform requires a Shodan API key.

Configure it in OGI under `API Keys` using the `shodan` service. Do not place API keys in transform settings.

## What It Adds

The input IP may be enriched with:

- `shodan_ip_str`
- `shodan_asn`
- `shodan_isp`
- `shodan_org`
- `shodan_os`
- `shodan_hostnames`
- `shodan_domains`
- `shodan_ports`
- `shodan_tags`
- `shodan_city`
- `shodan_region_code`
- `shodan_country_code`
- `shodan_country_name`
- `shodan_postal_code`
- `shodan_latitude`
- `shodan_longitude`
- `shodan_last_update`

The transform can also emit:

- `ASNumber` from the host ASN
- `Organization` from the host org
- `Domain` and `Subdomain` entities from Shodan domains/hostnames
- `Location` for map-friendly geographic context

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request

## Notes

- This transform uses Shodan's host lookup endpoint with `minify=true`.
- It is designed for host profiling and graph enrichment, not full service-banner extraction.
- If you want a later transform that emits separate ports, banners, or service entities, that should be a separate transform.