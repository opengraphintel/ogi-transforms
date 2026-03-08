# Username OSINT (user-scanner)

Uses the `user-scanner` Python library in library mode to check username presence and email registration across many platforms.

This is an official registry plugin and is intentionally **not bundled** with OGI core. Install it from Transform Hub or the `ogi` CLI.

## Input / Output

- Input: `SocialMedia`, `Person`, `Username`, or `EmailAddress` (`entity.value` is used as the scan identifier)
- Output: `SocialMedia` and `URL`

Recommended flow:
- `Person -> person_to_usernames -> Username OSINT (user-scanner)`
- `Person` input also works directly as a best-effort shortcut when the person value already resembles a handle
- `EmailAddress` input uses the email registration path from `user-scanner`

## Settings

- `scan_scope`: `all`, `social`, `dev`, `creator`, `community`, `gaming`
- `only_found`: include only found or registered results in output entities (default `true`)
- `max_results`: cap returned found accounts

## Notes

- Username and email scans use different `user-scanner` execution paths.
- Email-based results may represent registration evidence rather than a verified public username.
- Some sites can return temporary `403` or timeout results depending on region or network.
- Errors are reported in transform messages and do not fail the whole transform run.
- This plugin performs public endpoint checks only.
