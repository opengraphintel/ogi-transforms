# Domain to Shodan Hostnames

Uses Shodan's domain DNS endpoint to enumerate hostnames observed for a root domain.

## What it does

- Enriches the input `Domain` entity with Shodan hostname summary metadata
- Emits `Subdomain` entities for Shodan-observed hostnames under the domain
- Connects emitted hostname entities back to the root domain with `subdomain of` edges

## Requirements

- Shodan API key

## Notes

This is intentionally narrower than `domain_to_shodan_attack_surface`. It focuses on hostname enumeration and does not emit IP, MX, or NS infrastructure records.
