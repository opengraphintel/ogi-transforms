# Username OSINT (user-scanner)

Uses the `user-scanner` Python library in library mode to check whether a username exists on many platforms.

This is an official registry plugin and is intentionally **not bundled** with OGI core. Install it from Transform Hub or the `ogi` CLI.

## Input / Output

- Input: `SocialMedia` or `Person` (entity `value` is used as username candidate)
- Output: `SocialMedia` and `URL`

## Settings

- `scan_scope`: `all`, `social`, `dev`, `creator`, `community`, `gaming`
- `only_found`: include only found profiles in output entities (default `true`)
- `max_results`: cap returned found accounts

## Dependency

- `user-scanner>=1.3.3`

## Notes

- Some sites can return temporary `403` or timeout results depending on region/network.
- Errors are reported in transform messages and do not fail the whole transform run.
- This plugin performs public endpoint checks only.
