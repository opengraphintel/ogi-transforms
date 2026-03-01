# WHOIS Lookup

Retrieves WHOIS registration data for a domain, extracting registrar, registrant organization, contact person, and email addresses. Also enriches the input domain entity with WHOIS dates and status.

## Input / Output

- **Input**: `Domain`
- **Output**: `Organization` (registrar, registrant org), `Person` (registrant name), `EmailAddress` (contact emails)

## Properties Added

The input domain is enriched with: `whois_creation_date`, `whois_expiration_date`, `whois_updated_date`, `dnssec`, `whois_status`.

## API Keys

None required.
