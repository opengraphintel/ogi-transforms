# OGI Transform Registry

The canonical registry of transforms for [OGI (OpenGraph Intel)](https://github.com/opengraphintel/ogi) — an open source link analysis and OSINT framework.

## What is this?

This repository serves as a package registry for OGI transforms. Each transform is independently versioned, rated, and installable. Community members can contribute new transforms via pull requests.

A machine-readable `index.json` is auto-generated on every merge to `main`, which the OGI CLI and Transform Hub UI use to discover and install transforms.

## Installing Transforms

### Via CLI

```bash
ogi transform search shodan
ogi transform install shodan-host-lookup
ogi transform list
ogi transform update
```

### Via UI

Open the **Transform Hub** in OGI (Settings > Plugins) to browse, search, and install transforms with one click.

## Repository Structure

```
transforms/
  <category>/
    <slug>/
      plugin.yaml          # v2 manifest (required)
      README.md            # Documentation (required)
      CHANGELOG.md         # Version history
      transforms/
        __init__.py
        <transform>.py     # Transform implementation
      tests/               # Optional tests
        test_<transform>.py
```

## Categories

| Category | Description |
|----------|-------------|
| `dns` | DNS resolution, records, WHOIS |
| `email` | Email address analysis |
| `web` | HTTP, robots.txt, headers |
| `ip` | IP intelligence, geolocation, ASN |
| `cert` | SSL certificates, transparency |
| `social` | Social media, usernames |
| `hash` | File hashes, malware lookups |
| `infrastructure` | Shodan, Censys, network scanning |
| `forensics` | Digital forensics tools |

## Verification Tiers

| Tier | Badge | Description |
|------|-------|-------------|
| **Official** | Blue | Maintained by the OGI core team |
| **Verified** | Green | Reviewed and audited by maintainers |
| **Community** | Grey | Passes CI, has tests and documentation |
| **Experimental** | Yellow | New or untested submissions |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

**Quick start:**

1. Fork this repo
2. Create `transforms/<category>/<your-slug>/` with the required files
3. Open a PR using the template
4. CI will validate your submission automatically

## License

AGPLv3
