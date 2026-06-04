# Username & Phone to Hudson Rock

Checks a username, social handle, or phone number against
[Hudson Rock](https://www.hudsonrock.com/)'s free infostealer intelligence (the
Cavalier "OSINT tools" tier) and maps any compromise found in global
infostealer malware logs onto the graph.

Hudson Rock queries phone numbers through the same endpoint as usernames, so
this transform accepts `PhoneNumber` entities in addition to `Username` and
`SocialMedia`.

## Input / Output

- **Input**: `Username`, `SocialMedia`, `PhoneNumber`
- **Output**: `Username`, `EmailAddress`, `IPAddress`, `Document`

## What it produces

When the identifier appears in Hudson Rock's infostealer database, the transform:

- Enriches the input entity with summary properties (compromise flag, infection
  count, first/last compromise dates, stealer families, operating systems,
  corporate/user service counts).
- Emits a `Document` evidence report summarizing each infection (date, stealer
  family, OS, computer name, infected IP, malware path, antiviruses, leaked
  logins, and passwords).
- Emits each infected machine's IP as an `IPAddress` entity
  (`compromised on host`).
- Emits leaked logins found on the infected machines as `EmailAddress` /
  `Username` entities (`leaked credential`) so they can be pivoted on.

If the identifier is not found, the transform reports that and produces nothing.

## API keys

None required. Hudson Rock's OSINT-tools endpoints are free and unauthenticated
(rate limited). No key is configured for this transform.

## Settings

- **Timeout Seconds** — HTTP timeout (5–30, default 15).
- **Max Results** — caps infected-host IP and leaked-login entities (1–200, default 50).
- **Include Leaked Logins** — emit leaked logins as entities (default on).
- **Mask Passwords** — mask leaked passwords in the evidence document instead of
  storing them verbatim (default on).

## Notes & limitations

- This is **breach data harvested from malware victims** (real personal data).
  Use it only for assets you own or are authorized to investigate, and be
  mindful of where the resulting graph/export is stored.
- The free tier returns partially-redacted data and is rate limited; bulk
  fan-out may be throttled.
- Data and attribution: Hudson Rock — https://www.hudsonrock.com/
