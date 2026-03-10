# Social Profile to Entities

Fetches a public social profile page referenced by a `SocialMedia` entity and extracts observed identifiers.

The transform expects a profile URL in one of:

- `entity.properties.profile_url`
- `entity.properties.url`
- `entity.value` when the value itself is an `http(s)` URL

Observed outputs can include:

- `Person`
- `Username`
- `EmailAddress`
- `URL`
- `Domain`

This plugin is intended as a follow-on enricher for account-discovery transforms such as `username-maigret`.