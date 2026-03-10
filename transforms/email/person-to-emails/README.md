# Person to Emails

Generates likely email addresses for a `Person` using known domains already attached to the entity.

What it does:

- Emits observed emails already present in person properties with higher confidence
- Infers likely formats such as `first.last@domain`, `flast@domain`, and `firstlast@domain`
- Requires known domains from the person entity properties for inference
- Marks every result as either `observed` or `inferred`

Expected person properties for better results:

- `domains`
- `email_domains`
- `employer_domain`
- `employer_domains`
- `website` / `websites`
- `emails` / `observed_emails`

Safeguards:

- Does not claim inferred emails are valid
- Keeps confidence and rationale in entity properties
- Uses `possible email` edges for inferred candidates