# Domain to URLs (robots.txt)

Fetches `robots.txt` from a domain and extracts URLs from `Sitemap:` and `Disallow:` directives. Useful for discovering hidden or protected paths.

## Input / Output

- **Input**: `Domain`
- **Output**: `URL` entities (up to 50)

## API Keys

None required.

## Limitations

- Results capped at 50 URLs
- Only extracts from robots.txt (does not crawl sitemaps)
