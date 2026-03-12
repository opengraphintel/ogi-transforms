# Document to Phone Numbers

Extracts public phone numbers from a `Document`, normalizes them when possible, and preserves context for analyst review.

What it does:

- Reads `Document.properties.content` or falls back to the document value
- Extracts phone candidates from text with `phonenumbers` when available, plus a conservative regex fallback
- Normalizes accepted numbers to E.164 when possible
- Stores a short context snippet and source URL metadata on each output entity

Output properties include:

- `confidence`
- `raw_value`
- `normalized`
- `context_snippet`
- `observed_in`
- `observed_on_url`

Safeguards:

- Keeps context snippets so analysts can review the surrounding text
- Uses lower confidence when a number could not be fully normalized
- Does not claim the number is owned by a specific person
