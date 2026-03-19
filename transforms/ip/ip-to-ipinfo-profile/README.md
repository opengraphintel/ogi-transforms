# IP to IPinfo Profile

Looks up a single IP address against the IPinfo Core API and enriches the input `IPAddress` entity with profile data such as hostname, geolocation, ASN context, and IP characteristics.

## Input / Output

- Input: `IPAddress`
- Output: `IPAddress`

The transform enriches the existing IP entity instead of creating separate location or ASN entities.

## API Keys

This transform requires an IPinfo API token.

Configure it in OGI under `API Keys` using the `ipinfo` service. Do not place API keys in transform settings.

## What It Adds

When available, the transform may add:

- `ipinfo_hostname`
- `ipinfo_city`
- `ipinfo_region`
- `ipinfo_region_code`
- `ipinfo_country`
- `ipinfo_country_code`
- `ipinfo_continent`
- `ipinfo_continent_code`
- `ipinfo_latitude`
- `ipinfo_longitude`
- `ipinfo_timezone`
- `ipinfo_postal_code`
- `ipinfo_asn`
- `ipinfo_as_name`
- `ipinfo_as_domain`
- `ipinfo_as_route`
- `ipinfo_as_type`
- `ipinfo_is_anonymous`
- `ipinfo_is_anycast`
- `ipinfo_is_hosting`
- `ipinfo_is_mobile`
- `ipinfo_is_satellite`

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request

## Notes

- This transform uses IPinfo's Core Lookup API.
- It enriches the existing IP rather than creating separate graph entities.
- If you want a later transform that emits separate `Location` or `ASNumber` entities, that should be a separate transform.