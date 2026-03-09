# Username OSINT (Maigret)

Uses the `maigret` Python library in library mode to find claimed usernames across many supported services.

This is an official registry plugin and is intentionally **not bundled** with OGI core. Install it from Transform Hub or the `ogi` CLI.

## Input / Output

- Input: `SocialMedia`, `Person`, or `Username` (`entity.value` is normalized into a username candidate)
- Output: `SocialMedia` and `URL`

Recommended flow:
- `Person -> person_to_usernames -> Username OSINT (Maigret)`
- `Username -> Username OSINT (Maigret)`
- `SocialMedia` input works when `entity.value` already resembles a username/handle

## Settings

- `top_sites`: maximum number of ranked Maigret sites to query
- `include_disabled_sites`: include sites Maigret marks as disabled
- `parse_profile_data`: enable Maigret page parsing for additional identifiers when available
- `max_results`: cap returned claimed accounts

## Notes

- This plugin only emits claimed accounts that Maigret reports as found.
- Parsed profile metadata is preserved in entity properties when Maigret exposes it.
- Results are evidence-based account-presence findings, not identity proof.
- Some sites can rate limit, geo-block, or change detection behavior over time.
- Errors are reported in transform messages and do not fail the whole transform run.

## Known Limitations

- `maigret==0.5.0` currently pulls in heavier dependencies than most OGI community plugins.
- The plugin uses Maigret's bundled site database and ranking behavior.
- Username normalization is intentionally conservative to avoid turning arbitrary person names into overly broad scans.
