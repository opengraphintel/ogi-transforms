import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class DomainToShodanHostnames(BaseTransform):
    name = "domain_to_shodan_hostnames"
    display_name = "Domain to Shodan Hostnames"
    description = "Enumerates Shodan-observed hostnames for a domain"
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    category = "DNS"
    settings = [
        TransformSetting(
            name="shodan_api_key",
            display_name="Shodan API Key",
            description="API key for Shodan hostname lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Shodan domain request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of hostnames to emit",
            default="100",
            field_type="integer",
            min_value=10,
            max_value=1000,
        ),
        TransformSetting(
            name="include_history",
            display_name="Include History",
            description="Include historical DNS records from Shodan",
            default="false",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        domain = entity.value.strip().lower().rstrip(".")
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("shodan_api_key") or "").strip()
        if not api_key:
            messages.append("Shodan API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not domain:
            messages.append("Domain value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)
        max_results = self._get_max_results(config)
        include_history = self._get_bool(config.settings.get("include_history", "false"))

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    f"https://api.shodan.io/dns/domain/{domain}",
                    params={
                        "key": api_key,
                        "history": str(include_history).lower(),
                        "page": 1,
                    },
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("Shodan returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            subdomains = self._iter_clean_list(data.get("subdomains"))
            tags = self._iter_clean_list(data.get("tags"))
            hostname_values = [
                domain if subdomain in {"", "@"} else f"{subdomain}.{domain}"
                for subdomain in subdomains
            ]
            hostname_values = self._unique_preserve_order(hostname_values)

            entities.append(
                entity.model_copy(
                    update={
                        "properties": {
                            **entity.properties,
                            "shodan_domain": self._clean(data.get("domain")) or domain,
                            "shodan_tags": ", ".join(tags),
                            "shodan_hostname_count": len(hostname_values),
                            "shodan_hostnames": ", ".join(hostname_values[:max_results]),
                        }
                    }
                )
            )

            emitted = 0
            seen: set[str] = set()
            for hostname in hostname_values:
                if hostname == domain:
                    continue
                normalized = hostname.lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                if emitted >= max_results:
                    break
                subdomain_entity = Entity(
                    type=EntityType.SUBDOMAIN,
                    value=hostname,
                    properties={"parent_domain": domain, "source": "shodan"},
                    source=self.name,
                )
                entities.append(subdomain_entity)
                edges.append(
                    Edge(
                        source_id=subdomain_entity.id,
                        target_id=entity.id,
                        label="subdomain of",
                        source_transform=self.name,
                    )
                )
                emitted += 1

            messages.append(f"Hostnames discovered: {len(hostname_values)}")
            messages.append(f"Hostnames emitted: {emitted}")
            if tags:
                messages.append(f"Tags: {', '.join(tags)}")
            if len(hostname_values) > max_results:
                messages.append(f"Results truncated to {max_results} hostnames")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid Shodan API key")
            elif e.response.status_code == 404:
                messages.append(f"Shodan has no hostname data for {domain}")
            elif e.response.status_code == 429:
                messages.append("Shodan rate limit exceeded")
            else:
                messages.append(f"Shodan HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Shodan: {e}")
        except Exception as e:
            messages.append(f"Error during Shodan hostname lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _iter_clean_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        cleaned_values: list[str] = []
        for item in value:
            cleaned = self._clean(item)
            if cleaned:
                cleaned_values.append(cleaned)
        return self._unique_preserve_order(cleaned_values)

    def _unique_preserve_order(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []
        for value in values:
            normalized = value.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(value)
        return results

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip().rstrip(".")

    def _get_bool(self, raw: object) -> bool:
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))

    def _get_max_results(self, config: TransformConfig) -> int:
        raw_value = config.settings.get("max_results", 100)
        try:
            max_results = int(raw_value)
        except (TypeError, ValueError):
            return 100
        return max(10, min(max_results, 1000))
