# Domain to crt.sh Certificates

Queries crt.sh Certificate Transparency data for certificate records associated with a domain and emits `SSLCertificate` entities with certificate metadata.

## Input / Output

- Input: `Domain`
- Output: `SSLCertificate`

This transform is different from `cert-transparency`, which is focused on subdomain discovery. This one returns certificate records.

## What It Adds

Each emitted certificate entity may include:

- `crtsh_id`
- `issuer_name`
- `common_name`
- `name_value`
- `serial_number`
- `not_before`
- `not_after`
- `entry_timestamp`
- `matching_domain`

## Settings

- `max_results`: maximum number of certificate records to return
- `timeout_seconds`: HTTP timeout for crt.sh requests

## Notes

- No API key is required.
- crt.sh can be slow or intermittently unavailable.
- The transform merges exact-domain and wildcard-domain searches, then deduplicates by crt.sh record ID.
- Results reflect certificate transparency log observations, not necessarily currently deployed certificates.