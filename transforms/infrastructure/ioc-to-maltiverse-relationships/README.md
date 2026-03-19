# IOC to Maltiverse Relationships

Queries Maltiverse for an IOC record and emits related graph entities such as resolved IPs, related domains, email contacts, hashes, and networks based on the IOC type.

## Input / Output

- Input: `IPAddress`, `Domain`, `URL`, `Hash`
- Output: `IPAddress`, `Domain`, `URL`, `Hash`, `EmailAddress`, `Organization`, `Location`, `Network`

The transform focuses on graph relationships rather than only attaching summary properties.

## API Keys

This transform requires a Maltiverse API key.

Configure it in OGI under `API Keys` using the `maltiverse` service. Do not place API keys in transform settings.

## Relationship Sources

Based on the input type, the transform uses Maltiverse's documented IOC retrieval endpoints and emits relationships from fields such as:

- IP: `email`, `cidr`, `location`, `registrant_name`
- Hostname/Domain: `resolved_ip`, `domain`
- URL: `domain`, `hostname`
- Sample/Hash: `process_list.sha256`

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request
- `max_relationships`: maximum number of related items to emit from list fields

## Notes

- This transform uses Maltiverse IOC GET endpoints.
- It is relationship-oriented and intentionally conservative about which fields become graph entities.
- For URLs, the transform queries the direct URL endpoint.
- For `Hash`, the transform uses the SHA256 sample endpoint.