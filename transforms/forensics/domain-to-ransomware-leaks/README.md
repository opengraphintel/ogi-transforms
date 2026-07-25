# Domain to Ransomware Leak Posts

Searches [ransomware.live](https://www.ransomware.live) for leak site posts naming a
domain or organization, and pulls the surrounding context into the graph.

## Input / Output

- Input: `Domain`, `Organization`
- Output: `Document`, `Organization`, `Location`, `URL`, `Vulnerability`

## API Keys

Requires a ransomware.live **API PRO** key. It is free and perpetual, with a quota of
500,000 requests per month. Get one at <https://www.ransomware.live/my>.

Configure it in OGI under `API Keys` using the `ransomwarelive` service. Do not place
API keys in transform settings.

The free v2 API is deliberately not used here: it is rate limited to one request per
minute and its terms restrict it to personal use, which does not cover most OGI
deployments. API PRO is the licensed path for corporate and business use.

## What It Emits

For each matching leak post:

- a `Document` holding the post summary, with `victim`, `ransomware_group`,
  `victim_website`, `country`, `sector`, `attack_date`, `discovered`, and `permalink`
- an `Organization` for the ransomware group, linked with `published leak post`
- a `Location` for the victim's country

With `include_group_intel` enabled (the default), each distinct group is looked up once
more to add:

- `URL` entities for its known leak sites, usually Tor hidden services
- `Vulnerability` entities for the CVEs the group is known to exploit

## Settings

- `timeout_seconds`: HTTP timeout for requests
- `max_results`: maximum number of leak posts to emit
- `include_group_intel`: fetch leak site URLs and exploited CVEs per group

## Notes

The keyword search is a case-insensitive substring match against victim name and
website, so short or generic inputs produce false matches, and an organization listed
under a trading name may be missed. Verify matches against the permalink before acting.

Absence of results is not evidence that an organization was never attacked. Only victims
the gangs chose to publish appear at all, and those who paid before publication
typically never do.

Attack dates come from the gangs' own listings and are estimates.

## Chaining

The leak site `URL` entities are usually `.onion` addresses; run
`Onion Address Validator` on them to confirm they are well-formed hidden service
identities.
