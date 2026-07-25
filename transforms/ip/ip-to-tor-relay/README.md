# IP to Tor Relay

Checks an IP address against the Tor Project's [Onionoo](https://onionoo.torproject.org)
service and, when it matches, enriches the address with the relay's identity and role.

## Input / Output

- Input: `IPAddress`
- Output: `IPAddress`, `Organization`, `Location`, `ASNumber`

## API Keys

None. Onionoo is a public service operated by the Tor Project and needs no key.

## What It Adds

On a match, the input `IPAddress` gains:

- `tor_relay` (true)
- `tor_relay_nickname`, `tor_relay_fingerprint`
- `tor_relay_flags`, `tor_is_exit_node`, `tor_is_guard_node`
- `tor_relay_running`, `tor_relay_first_seen`, `tor_relay_last_seen`
- `tor_relay_country`, `tor_relay_country_name`
- `tor_relay_as`, `tor_relay_as_name`
- `tor_relay_platform`, `tor_relay_version`, `tor_relay_contact`
- `tor_relay_observed_bandwidth`, `tor_relay_consensus_weight`, `tor_relay_exit_probability`
- `tor_relay_exit_addresses`

It also emits an `ASNumber` for the announcing network, an `Organization` for the
hosting provider, and a `Location` for the relay's country.

When the address is not a relay, the entity is marked `tor_relay: false` rather than
left unchanged, so a negative result is visible in the graph.

## Settings

- `timeout_seconds`: HTTP timeout for the Onionoo lookup

## Notes

Onionoo's `search` parameter is a prefix match, so this transform verifies that the
queried address actually appears in the relay's published `or_addresses` or
`exit_addresses` before reporting a match. Bridges are deliberately not published by
the Tor Project, so traffic entering the network via a bridge will not appear here.

Being a guard or middle relay is not the same as being an exit: only exit nodes
originate onward connections, so check `tor_is_exit_node` before concluding that
traffic to your estate came through the address.
