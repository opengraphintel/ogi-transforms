# Domain to IP Address

Resolves A (IPv4) and AAAA (IPv6) DNS records for a domain, creating IP Address entities for each result.

## Input / Output

- **Input**: `Domain` (e.g., `example.com`)
- **Output**: `IPAddress` entities linked via "resolves to (A)" or "resolves to (AAAA)" edges

## How it works

Uses `dnspython` to query both A and AAAA record types. Each resolved IP address is created as an entity with the record type stored in properties.

## API Keys

None required.

## Example

```
Input:  Domain "example.com"
Output: IPAddress "93.184.216.34" (A record)
        IPAddress "2606:2800:220:1:248:1893:25c8:1946" (AAAA record)
```
