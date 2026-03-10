# Profile URL to Identifiers

Fetches a public profile page and extracts observed identifiers from page content and metadata.

Observed outputs can include:

- `Person` from `<title>`, `og:title`, or `twitter:title`
- `EmailAddress` values seen in page text or mailto links
- `Username` values observed in profile-like URLs or `@handle` text
- `URL` bio links and canonical/profile links
- `Domain` values derived from extracted links

Safeguards:

- Emits only observed values, not inferred identities
- Keeps provenance in entity properties
- Supports caps via `timeout_seconds`, `max_results`, and `max_content_chars`

Recommended follow-on use:

- Run this on a URL returned by `username-maigret`
- Combine with `social-profile-to-entities` for SocialMedia inputs