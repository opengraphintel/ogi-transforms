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
5. Open a PR - CI validates automatically

When adding capped settings, prefer common names like `max_results`, `max_urls`, `max_links`, `max_content_chars`, or `timeout_seconds` unless the setting is genuinely transform-specific. That keeps operator-side overrides predictable across the ecosystem.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

AGPLv3
