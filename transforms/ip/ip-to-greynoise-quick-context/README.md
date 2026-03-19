# IP to GreyNoise Quick Context

Looks up a single IP address against the GreyNoise Community API and attaches lightweight internet-noise context directly to the input IP entity.

## Input / Output

- Input: `IPAddress`
- Output: `IPAddress`

The transform enriches the existing IP with GreyNoise-specific properties instead of creating separate entities.

## What It Adds

When GreyNoise returns data, the transform adds these properties to the IP entity when available:

- `greynoise_noise`
- `greynoise_riot`
- `greynoise_classification`
- `greynoise_name`
- `greynoise_link`
- `greynoise_last_seen`
- `greynoise_message`

## Settings

- `timeout_seconds`: HTTP timeout for the GreyNoise request

## Notes

- This transform uses the GreyNoise Community API for lightweight context.
- Community lookups are quota-limited by GreyNoise.
- This is intended as a quick triage enrichment, not a full paid-context investigation.
- A future advanced GreyNoise transform can add deeper API-key-backed context if needed.