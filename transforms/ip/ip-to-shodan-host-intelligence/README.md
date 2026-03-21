# IP to Shodan Host Intelligence

Uses Shodan's full host endpoint to build a richer host investigation graph.

## What it does

- Enriches the input `IPAddress` with Shodan host context
- Emits `ASNumber`, `Organization`, `Domain`, `Subdomain`, and `Location` entities
- Creates a summary `Document` with service and vulnerability context
- Optionally emits `URL`, `HTTPHeader`, and `SSLCertificate` entities from observed services

## Requirements

- Shodan API key

## Settings

- `include_services`: emit URL and HTTP header entities from service observations
- `include_vulnerabilities`: include vulnerability identifiers in the evidence summary
- `include_ssl`: emit SSL certificate entities from service observations

## Notes

This is the deeper investigative Shodan transform. For a lighter profile-and-evidence pass, use `ip_to_shodan_host`.
