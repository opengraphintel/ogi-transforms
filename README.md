# OGI Transform Registry

Community transforms for [OGI](https://github.com/khashashin/ogi), an open source OSINT and link analysis tool.

## How it works

Each directory under `transforms/` is an independently installable transform. The OGI CLI and Transform Hub UI read `index.json` (auto-generated on each merge) to discover what's available.

## Install a transform

Use the CLI from the OGI backend project:

```bash
cd backend
uv sync
uv run ogi transform search shodan
uv run ogi transform install shodan-host-lookup
```

Or use the Transform Hub UI inside OGI.

## Runtime cap overrides

Community transforms in this registry inherit OGI's host-side transform cap overrides. Operators can centrally clamp or remove common max settings such as `max_results`, `max_urls`, `max_links`, `max_content_chars`, or `timeout_seconds` with the backend env var:

```env
OGI_TRANSFORM_SETTING_MAX_OVERRIDES=max_results=50,max_urls=25,max_links=40
```

To remove a cap in a local deployment:

```env
OGI_TRANSFORM_SETTING_MAX_OVERRIDES=max_results=none,max_content_chars=none
```

This is configured in the main OGI app, not in this registry repo.

## Built-in transforms (ship with OGI)

| Category | Transforms |
|----------|-----------|
| DNS | domain-to-ip, domain-to-mx, domain-to-ns, ip-to-domain, whois-lookup |
| Certificates | domain-to-certs, cert-transparency |
| Email | domain-to-emails, email-to-domain |
| IP | ip-to-asn, ip-to-geolocation |
| Social | username-search |
| Hash | hash-lookup |
| Web | domain-to-urls, url-to-headers, url-to-links, url-to-content, content-to-iocs |
| Infrastructure | organization-to-team-members |

## Contribute a transform

1. Fork this repo
2. Add your transform under `transforms/<category>/<slug>/`
3. Include `plugin.yaml`, `README.md`, and `transforms/*.py`
4. Declare required secrets in `api_keys_required`, not `transform_settings`
5. Describe the transform with `long_description`, `when_to_use`, `limitations`, and `example_use_cases`
6. Open a PR - CI validates automatically

## Documenting a transform

OGI shows an info icon beside every transform in its sidebar. Clicking it opens
a dialog built from four optional manifest fields, so analysts can tell whether
a transform fits their investigation before spending an API credit on it:

| Field | What belongs there |
|-------|--------------------|
| `long_description` | What the transform actually does and which entities it emits |
| `when_to_use` | The situation it is right for, and which transform to reach for instead when it is not |
| `limitations` | Rate limits, staleness, coverage gaps, false positives - whatever would otherwise surprise someone reading the results |
| `example_use_cases` | Up to eight short, concrete scenarios |

Your `README.md` is installed alongside the transform and offered in the same
dialog as the deeper reference, so the manifest fields should still stand on
their own.

When adding capped settings, prefer common names like `max_results`, `max_urls`, `max_links`, `max_content_chars`, or `timeout_seconds` unless the setting is genuinely transform-specific. That keeps operator-side overrides predictable across the ecosystem.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

AGPLv3
