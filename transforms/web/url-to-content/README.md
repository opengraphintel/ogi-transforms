# URL to Content

Fetches URL content through Playwright rendering and creates a `Document` entity with extracted readable text.

## Input / Output

- **Input**: `URL`
- **Output**: `Document`

## Features

- Playwright-based page rendering (JS enabled)
- HTML text extraction from rendered page source
- Security controls for local/private targets and non-text content
- Configurable content size limit

## Security Notes

By default, localhost/private IP targets are blocked and non-text payloads are rejected.
Use `allow_local_network=true` only in trusted/sandboxed environments.

## API Keys

None required.
