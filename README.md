# OGI Transform Registry

Community transforms for [OGI](https://github.com/opengraphintel/ogi), an open source OSINT and link analysis tool.

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
4. Open a PR - CI validates automatically

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

AGPLv3
