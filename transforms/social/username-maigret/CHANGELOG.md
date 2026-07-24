# Changelog

## 1.2.1

- Added long-form documentation (long_description, when_to_use, limitations, example_use_cases) for the transform info dialog.

## 1.2.0

- Parallel site scanning using asyncio.gather with configurable concurrency (default 20).
- Added `concurrency` setting (range 1-50) to control maximum concurrent site checks.
- Aligned httpx connection pool limits with the concurrency setting.

## 1.1.0

- Replaced direct Maigret package dependency with an adoption-style OGI-native checker.
- Vendored Maigret `data.json` into the plugin resources.
- Reduced runtime dependency surface to lightweight HTTP-based checking only.

## 1.0.0

- Initial community plugin scaffold for Maigret-backed username discovery.
