# Person to Phone Numbers

Finds public phone numbers likely associated with a `Person` from attached text, documents, and profile URLs.

What it does:

- Reuses person context already present on the graph such as `profile_urls`, `websites`, `documents`, `bio`, and `notes`
- Extracts phone candidates from embedded text and fetched public pages
- Scores phone numbers higher when they appear near the person's name, organization, or role
- Normalizes accepted phone numbers to E.164 when possible

Expected person properties for better results:

- `profile_url` / `profile_urls`
- `website` / `websites`
- `links`
- `documents`
- `bio`, `description`, `notes`
- `organization`, `employer`, `title`, `role`

Safeguards:

- Limits inspection to URLs and document-like content already attached to the person entity
- Uses `possible phone` edges because association is inferred from context
- Stores source URL or document title plus a context snippet on each result
- Avoids claiming a number is valid or owned without corroboration
