# Onion Address Validator

Finds `.onion` addresses in text and verifies their v3 checksums entirely offline.

## Input / Output

- Input: `Document`, `URL`, `Domain`
- Output: `URL`

For a `Document`, the `content` property is scanned; otherwise the entity value is used.

## API Keys

None. This transform performs no network requests at all.

## How Validation Works

A v3 onion address is base32 over 35 bytes:

```
pubkey (32 bytes) || checksum (2 bytes) || version (1 byte)
checksum = SHA3-256(".onion checksum" || pubkey || version)[:2]
```

The transform decodes the address, recomputes the checksum, and only emits a `URL`
entity when it matches. Each result carries:

- `onion_address`
- `onion_version` (3)
- `onion_public_key_hex`
- `checksum_valid` (true)

## Settings

- `max_results`: maximum number of valid onion services to emit
- `emit_invalid`: report addresses that failed validation as run messages

## Notes

Because the checksum is computed locally, this transform has no external dependency and
cannot break when a third-party service changes. It requires no Tor connectivity.

A valid checksum proves only that an address is a well-formed hidden service identity.
It says nothing about whether the service is reachable, who operates it, or what it
hosts.

v2 addresses (16 characters) carry no checksum and the scheme was shut down in October
2021. They are recognized and counted, but never emitted as results.

## Chaining

Pairs naturally with `URL to Content` upstream (to obtain page text) and with
`Domain to Ransomware Leak Posts`, whose leak site URLs are frequently hidden services.
