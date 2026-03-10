# Email to Evidence

Collects evidence around an `EmailAddress` without claiming that the mailbox is valid.

What it does:

- Extracts the hosting domain
- Performs an MX lookup to see whether the domain appears able to receive email
- Preserves observed source URLs already attached to the email entity
- Optionally performs a best-effort Google search for the exact email and crawls result pages for corroboration
- Emits a `Document` entity summarizing evidence and caveats

Important limitation:

- MX presence does **not** prove that a mailbox exists
- Google search scraping is brittle and may fail or return incomplete results
- This transform is for corroboration and analyst review, not hard verification