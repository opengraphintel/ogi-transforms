# Username Search

Checks a username across popular platforms (GitHub, Reddit, Keybase) by making HTTP HEAD requests. Creates SocialMedia and URL entities for confirmed accounts.

## Input / Output

- **Input**: `SocialMedia` or `Person` (uses the entity value as username)
- **Output**: `SocialMedia` (platform-specific accounts), `URL` (profile links)

## API Keys

None required. Uses public profile URLs.

## Platforms Checked

- GitHub
- Reddit
- Keybase

## Notes

- 0.5-second delay between requests to avoid rate limiting
- A 200 response indicates the profile exists (may produce false positives for some platforms)
