# URL to urlscan Lookup

Searches urlscan's historical scan index for the most recent matching result for a URL and enriches the input `URL` entity with urlscan metadata.

## Input / Output

- Input: `URL`
- Output: `URL`

The transform enriches the existing URL entity instead of creating separate result entities.

## API Keys

This transform requires a urlscan API key.

Configure it in OGI under `API Keys` using the `urlscan` service. Do not place API keys in transform settings.

## What It Adds

When a match is found, the transform may add:

- `urlscan_result_id`
- `urlscan_report_url`
- `urlscan_task_url`
- `urlscan_page_url`
- `urlscan_page_domain`
- `urlscan_page_ip`
- `urlscan_country`
- `urlscan_server`
- `urlscan_status`
- `urlscan_visibility`
- `urlscan_scan_date`

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request

## Notes

- This transform searches existing urlscan results; it does not submit a new scan.
- Matching depends on urlscan search indexing and exact URL lookup behavior.
- The transform returns only the most recent matching scan.