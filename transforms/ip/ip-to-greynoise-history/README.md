# IP to GreyNoise History

Looks up GreyNoise timeline data for a single IP address and enriches the input `IPAddress` entity with a summarized view of historical activity.

## Input / Output

- Input: `IPAddress`
- Output: `IPAddress`, `Organization`, `Location`

The transform keeps a summary on the IP and also emits deduplicated graph entities for historically observed organizations and countries.

## API Keys

This transform requires a GreyNoise API key with access to the timeline endpoint.

Configure it in OGI under `API Keys` using the `greynoise` service. Do not place API keys in transform settings.

## What It Adds

When available, the transform may add IP summary properties such as:

- `greynoise_history_window_start`
- `greynoise_history_window_end`
- `greynoise_history_ip`
- `greynoise_history_event_count`
- `greynoise_history_first_seen`
- `greynoise_history_last_seen`
- `greynoise_history_classifications`
- `greynoise_history_ports`
- `greynoise_history_tags`
- `greynoise_history_organizations`
- `greynoise_history_rdns`
- `greynoise_history_countries`
- `greynoise_history_http_paths`
- `greynoise_history_user_agents`

The transform can also emit:

- `Organization` entities for historically observed organizations
- `Location` entities for historically observed countries

## Settings

- `timeout_seconds`: HTTP timeout for the lookup request
- `max_activity_points`: maximum number of timeline points to summarize

## Notes

- This transform uses GreyNoise's timeline endpoint.
- GreyNoise documents this endpoint as requiring an additional subscription license.
- The transform summarizes returned history rather than emitting per-event graph entities.