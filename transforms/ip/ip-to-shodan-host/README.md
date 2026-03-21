# IP to Shodan Host

Uses Shodan's host endpoint to produce a quick baseline host profile for an IP address.

## What it does

- Enriches the input `IPAddress` with basic Shodan host summary fields
- Emits a summary `Document` with key observations
- Emits `ASNumber`, `Organization`, `Location`, and `Network` context when available

## Requirements

- Shodan API key

## Notes

This is the baseline Shodan transform. For richer service-, HTTP-, URL-, and certificate-oriented output, use `ip_to_shodan_host_intelligence`.
