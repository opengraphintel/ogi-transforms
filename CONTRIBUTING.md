# Contributing to OGI Transforms

Thank you for contributing to the OGI transform ecosystem! This guide walks you through creating and submitting a new transform.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- A working OGI installation for testing

## Creating a New Transform

### 1. Choose a Category

Pick the most appropriate category for your transform:

`dns`, `email`, `web`, `ip`, `cert`, `social`, `hash`, `infrastructure`, `forensics`

If none fit, propose a new category in your PR description.

### 2. Create the Directory Structure

```
transforms/<category>/<your-slug>/
  plugin.yaml          # Required: manifest
  README.md            # Required: documentation
  CHANGELOG.md         # Recommended: version history
  transforms/
    __init__.py         # Required: empty or with imports
    <your_transform>.py # Required: transform implementation
  tests/               # Recommended
    test_<name>.py
```

### 3. Write `plugin.yaml`

```yaml
name: your-transform-slug        # lowercase, hyphens only
version: "1.0.0"                  # semver required
display_name: "Your Transform"
description: "What this transform does"
author: "Your Name"
license: "AGPL-3.0"
category: "dns"
input_types: ["Domain"]           # OGI entity types
output_types: ["IPAddress"]       # OGI entity types
min_ogi_version: "0.3.0"

# Optional
tags: ["dns", "resolution"]
author_github: "yourusername"
python_dependencies:
  - "some-package>=1.0.0"
api_keys_required:
  - service: "example"
    description: "API key from https://example.com"
    env_var: "EXAMPLE_API_KEY"
transform_settings:
  - name: "example_api_key"
    display_name: "Example API Key"
    description: "API key used by this transform"
    required: true
    field_type: "secret"
  - name: "model"
    display_name: "Model"
    default: "gpt-4.1-mini"
    field_type: "select"
    options: ["gpt-4.1-mini", "gpt-4.1"]
  - name: "max_results"
    display_name: "Max Results"
    default: "100"
    field_type: "integer"
    min_value: 1
    max_value: 500
permissions:
  network: true
  filesystem: false
  subprocess: false
```

### 4. Implement the Transform

Your transform must extend `BaseTransform` from OGI:

```python
from ogi.models import Entity, EntityType, EntityCreate, EdgeCreate, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig


class YourTransform(BaseTransform):
    name = "your_transform"
    display_name = "Your Transform"
    description = "What it does"
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.IP_ADDRESS]
    category = "DNS"

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        entities = []
        edges = []
        messages = []

        # Your logic here...

        return TransformResult(
            entities=entities,
            edges=edges,
            messages=messages,
        )
```

### 5. Write a README

Your README should include:

- What the transform does
- Input and output entity types
- Any API keys required and how to get them
- Example usage
- Known limitations

## Submitting Your Transform

1. **Fork** this repository
2. **Create a branch**: `git checkout -b add-your-transform`
3. **Add your transform** in `transforms/<category>/<slug>/`
4. **Open a Pull Request** using the provided template
5. **CI checks** will run automatically
6. **Maintainers** will review your code

## CI Validation

Every PR is validated:

| Check | Tool | What it does |
|-------|------|-------------|
| Schema validation | `jsonschema` | Validates `plugin.yaml` against the schema |
| Python linting | `ruff` | Code style and common errors |
| Security scan | `bandit` | Detects dangerous function calls |
| Pattern scan | `semgrep` | Blocks `subprocess`, `ctypes`, raw `socket`, `__import__` |
| Structure check | Custom | Verifies required files exist |
| Tests | `pytest` | Runs tests if `tests/` directory exists (30s timeout) |

## Security Guidelines

- **Never** use `eval()`, `exec()`, `os.system()`, or `subprocess`
- **Never** import `ctypes` or use raw sockets
- **Always** declare required permissions in `plugin.yaml`
- **Always** declare required API keys
- **Prefer** `transform_settings` for typed options (model selectors, limits, toggles) so OGI can validate and render a settings UI
- **Prefer** `httpx` for HTTP requests (it's already an OGI dependency)

## Entity Types

Available entity types in OGI:

`Person`, `Domain`, `IPAddress`, `EmailAddress`, `PhoneNumber`, `Organization`, `URL`, `SocialMedia`, `Hash`, `Document`, `Location`, `ASNumber`, `Network`, `MXRecord`, `NSRecord`, `Nameserver`, `SSLCertificate`, `Subdomain`, `HTTPHeader`

## License

All contributions must be licensed under AGPLv3 to be compatible with OGI.


