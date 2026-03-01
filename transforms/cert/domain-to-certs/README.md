# Domain to SSL Certificates

Connects to a domain on port 443 and retrieves the SSL/TLS certificate, extracting subject, issuer, serial number, validity dates, and Subject Alternative Names (SANs).

## Input / Output

- **Input**: `Domain`
- **Output**: `SSLCertificate`, `Organization` (certificate issuer)

## API Keys

None required. Uses stdlib `ssl` module for direct TLS connections.
