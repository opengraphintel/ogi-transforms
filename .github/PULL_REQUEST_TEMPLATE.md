## New Transform Submission

### Transform Info

- **Slug**: `<your-transform-slug>`
- **Category**: `<dns|email|web|ip|cert|social|hash|infrastructure|forensics>`
- **Input types**: `<Entity types this accepts>`
- **Output types**: `<Entity types this produces>`

### Description

<!-- What does this transform do? Why is it useful? -->

### API Keys Required

<!-- List any API keys needed, or "None" -->

### Checklist

- [ ] `plugin.yaml` uses schema_version 2 and passes schema validation
- [ ] `README.md` documents usage, input/output types, and any API keys
- [ ] `transforms/__init__.py` exists
- [ ] Transform extends `BaseTransform` from OGI
- [ ] No use of `subprocess`, `eval`, `exec`, `os.system`, `ctypes`
- [ ] `permissions` field in `plugin.yaml` accurately reflects what the transform needs
- [ ] Tests included in `tests/` directory (recommended)
- [ ] `CHANGELOG.md` included (recommended)

### Testing Evidence

<!-- How did you test this? Paste output or screenshots. -->

### Notes

<!-- Any additional context for reviewers -->
