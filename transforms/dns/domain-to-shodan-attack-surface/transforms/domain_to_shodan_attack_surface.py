import ipaddress

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class DomainToShodanAttackSurface(BaseTransform):
    name = "domain_to_shodan_attack_surface"
    display_name = "Domain to Shodan Attack Surface"
    description = "Maps a domain's Shodan-observed DNS attack surface"
    input_types = [EntityType.DOMAIN]
    output_types = [
        EntityType.DOMAIN,
        EntityType.SUBDOMAIN,
        EntityType.IP_ADDRESS,
        EntityType.MX_RECORD,
        EntityType.NS_RECORD,
        EntityType.NAMESERVER,
    ]
    category = "DNS"
    settings = [
        TransformSetting(
            name="shodan_api_key",
            display_name="Shodan API Key",
            description="API key for Shodan domain lookups",
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
            description="Maximum number of DNS records to process",
            default="200",
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
        domain = entity.value.strip().lower()
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
            records = data.get("data") if isinstance(data.get("data"), list) else []

            enriched = entity.model_copy(update={
                "properties": {
                    **entity.properties,
                    "shodan_domain": self._clean(data.get("domain")) or domain,
                    "shodan_tags": ", ".join(tags),
                    "shodan_subdomains": ", ".join(subdomains),
                    "shodan_record_count": len(records),
                }
            })
            entities.append(enriched)

            if tags:
                messages.append(f"Tags: {', '.join(tags)}")
            if subdomains:
                messages.append(f"Subdomains: {len(subdomains)}")
            messages.append(f"Records processed: {min(len(records), max_results)}")

            seen: set[tuple[str, str]] = set()

            for subdomain in subdomains:
                fqdn = domain if subdomain in {"", "@"} else f"{subdomain}.{domain}"
                if fqdn == domain:
                    continue
                key = (EntityType.SUBDOMAIN.value, fqdn)
                if key in seen:
                    continue
                seen.add(key)
                sub_entity = Entity(
                    type=EntityType.SUBDOMAIN,
                    value=fqdn,
                    properties={"parent_domain": domain, "source": "shodan"},
                    source=self.name,
                )
                entities.append(sub_entity)
                edges.append(Edge(
                    source_id=sub_entity.id,
                    target_id=entity.id,
                    label="subdomain of",
                    source_transform=self.name,
                ))

            truncated = False
            for record in records[:max_results]:
                if not isinstance(record, dict):
                    continue
                record_type = self._clean(record.get("type")).upper()
                subdomain = self._clean(record.get("subdomain"))
                value = self._clean(record.get("value"))
                last_seen = self._clean(record.get("last_seen"))
                fqdn = domain if subdomain in {"", "@"} else f"{subdomain}.{domain}"

                if not value:
                    continue

                if record_type in {"A", "AAAA"} and self._is_ip(value):
                    self._append_entity(
                        entities,
                        edges,
                        seen,
                        entity,
                        EntityType.IP_ADDRESS,
                        value,
                        "resolves to",
                        {"record_type": record_type, "fqdn": fqdn, "last_seen": last_seen, "source": "shodan"},
                    )
                elif record_type == "MX":
                    self._append_entity(
                        entities,
                        edges,
                        seen,
                        entity,
                        EntityType.MX_RECORD,
                        value,
                        "mx record",
                        {"fqdn": fqdn, "last_seen": last_seen, "source": "shodan"},
                    )
                elif record_type == "NS":
                    self._append_entity(
                        entities,
                        edges,
                        seen,
                        entity,
                        EntityType.NS_RECORD,
                        value,
                        "ns record",
                        {"fqdn": fqdn, "last_seen": last_seen, "source": "shodan"},
                    )
                    self._append_entity(
                        entities,
                        edges,
                        seen,
                        entity,
                        EntityType.NAMESERVER,
                        value,
                        "served by",
                        {"fqdn": fqdn, "last_seen": last_seen, "source": "shodan"},
                    )
                elif record_type == "CNAME" and value:
                    cname_type = EntityType.SUBDOMAIN if value.endswith(f".{domain}") and value != domain else EntityType.DOMAIN
                    self._append_entity(
                        entities,
                        edges,
                        seen,
                        entity,
                        cname_type,
                        value,
                        "alias of",
                        {"fqdn": fqdn, "last_seen": last_seen, "record_type": record_type, "source": "shodan"},
                    )

            if len(records) > max_results:
                truncated = True
            if truncated:
                messages.append(f"Results truncated to {max_results} records")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid Shodan API key")
            elif e.response.status_code == 404:
                messages.append(f"Shodan has no domain data for {domain}")
            elif e.response.status_code == 429:
                messages.append("Shodan rate limit exceeded")
            else:
                messages.append(f"Shodan HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Shodan: {e}")
        except Exception as e:
            messages.append(f"Error during Shodan domain lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _append_entity(
        self,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        source_entity: Entity,
        entity_type: EntityType,
        value: str,
        edge_label: str,
        properties: dict[str, str],
    ) -> None:
        key = (entity_type.value, value.lower())
        if key in seen:
            return
        seen.add(key)
        target = Entity(
            type=entity_type,
            value=value,
            properties=properties,
            source=self.name,
        )
        entities.append(target)
        edges.append(Edge(
            source_id=source_entity.id,
            target_id=target.id,
            label=edge_label,
            source_transform=self.name,
        ))

    def _iter_clean_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        seen: set[str] = set()
        results: list[str] = []
        for item in value:
            cleaned = self._clean(item)
            if not cleaned:
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(cleaned)
        return results

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip().rstrip('.')

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
        raw_value = config.settings.get("max_results", 200)
        try:
            max_results = int(raw_value)
        except (TypeError, ValueError):
            return 200
        return max(10, min(max_results, 1000))