# IP to Geolocation

Looks up geographic location data for an IP address using the free ip-api.com service. Returns country, city, region, coordinates, ISP, and organization.

## Input / Output

- **Input**: `IPAddress`
- **Output**: `Location` (with country, city, region, lat/lon, ISP, org)

## API Keys

None required. Uses the free ip-api.com endpoint.

## Limitations

- Rate limited to 45 requests per minute on the free tier
- HTTP only (no HTTPS on free tier)
