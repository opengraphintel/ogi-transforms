import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IPToShodanHostIntelligence(BaseTransform):
    name = "ip_to_shodan_host_intelligence"
    display_name = "IP to Shodan Host Intelligence"
    description = "Enriches an IP address with Shodan host intelligence"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [
        EntityType.IP_ADDRESS,
        EntityType.AS_NUMBER,
        EntityType.ORGANIZATION,
        EntityType.DOMAIN,
        EntityType.SUBDOMAIN,
        EntityType.LOCATION,
    ]
    category = "IP Intelligence"
    settings = [
        TransformSetting(
            name="shodan_api_key",
            display_name="Shodan API Key",
            description="API key for Shodan host lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Shodan host request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("shodan_api_key") or "").strip()
        if not api_key:
            messages.append("Shodan API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not ip:
            messages.append("IP value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": api_key, "minify": "true"},
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("Shodan returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            enriched_properties: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "shodan_ip_str": self._clean(data.get("ip_str")),
                "shodan_asn": self._clean(data.get("asn")),
                "shodan_isp": self._clean(data.get("isp")),
                "shodan_org": self._clean(data.get("org")),
                "shodan_os": self._clean(data.get("os")),
                "shodan_hostnames": self._join_list(data.get("hostnames")),
                "shodan_domains": self._join_list(data.get("domains")),
                "shodan_ports": self._join_list(data.get("ports")),
                "shodan_tags": self._join_list(data.get("tags")),
                "shodan_city": self._clean(data.get("city")),
                "shodan_region_code": self._clean(data.get("region_code")),
                "shodan_country_code": self._clean(data.get("country_code")),
                "shodan_country_name": self._clean(data.get("country_name")),
                "shodan_postal_code": self._clean(data.get("postal_code")),
                "shodan_last_update": self._clean(data.get("last_update")),
            }

            latitude = data.get("latitude")
            longitude = data.get("longitude")
            if isinstance(latitude, (int, float)):
                enriched_properties["shodan_latitude"] = float(latitude)
            if isinstance(longitude, (int, float)):
                enriched_properties["shodan_longitude"] = float(longitude)

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            asn_value = self._clean(data.get("asn"))
            if asn_value:
                as_entity = Entity(
                    type=EntityType.AS_NUMBER,
                    value=asn_value,
                    properties={
                        "org": self._clean(data.get("org")),
                        "isp": self._clean(data.get("isp")),
                        "source": "shodan",
                    },
                    source=self.name,
                )
                entities.append(as_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=as_entity.id,
                    label="belongs to ASN",
                    source_transform=self.name,
                ))
                messages.append(f"ASN: {asn_value}")

            org_value = self._clean(data.get("org"))
            if org_value:
                org_entity = Entity(
                    type=EntityType.ORGANIZATION,
                    value=org_value,
                    properties={
                        "asn": asn_value,
                        "isp": self._clean(data.get("isp")),
                        "source": "shodan",
                    },
                    source=self.name,
                )
                entities.append(org_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=org_entity.id,
                    label="operated by",
                    source_transform=self.name,
                ))
                messages.append(f"Organization: {org_value}")

            location_entity = self._build_location_entity(data)
            if location_entity is not None:
                entities.append(location_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=location_entity.id,
                    label="located in",
                    source_transform=self.name,
                ))
                messages.append(f"Location: {location_entity.value}")

            seen_names: set[tuple[EntityType, str]] = set()
            for hostname in self._iter_clean_list(data.get("hostnames")):
                entity_type = EntityType.SUBDOMAIN if "." in hostname else EntityType.DOMAIN
                key = (entity_type, hostname.lower())
                if key in seen_names:
                    continue
                seen_names.add(key)
                host_entity = Entity(
                    type=entity_type,
                    value=hostname,
                    properties={"source": "shodan", "kind": "hostname"},
                    source=self.name,
                )
                entities.append(host_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=host_entity.id,
                    label="resolves to",
                    source_transform=self.name,
                ))

            for domain_value in self._iter_clean_list(data.get("domains")):
                key = (EntityType.DOMAIN, domain_value.lower())
                if key in seen_names:
                    continue
                seen_names.add(key)
                domain_entity = Entity(
                    type=EntityType.DOMAIN,
                    value=domain_value,
                    properties={"source": "shodan", "kind": "domain"},
                    source=self.name,
                )
                entities.append(domain_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=domain_entity.id,
                    label="associated with domain",
                    source_transform=self.name,
                ))

            if enriched_properties.get("shodan_ports"):
                messages.append(f"Ports: {enriched_properties['shodan_ports']}")
            if enriched_properties.get("shodan_hostnames"):
                messages.append(f"Hostnames: {enriched_properties['shodan_hostnames']}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid Shodan API key")
            elif e.response.status_code == 404:
                messages.append(f"Shodan has no host data for {ip}")
            elif e.response.status_code == 429:
                messages.append("Shodan rate limit exceeded")
            else:
                messages.append(f"Shodan HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Shodan: {e}")
        except Exception as e:
            messages.append(f"Error during Shodan host lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _build_location_entity(self, data: dict) -> Entity | None:
        city = self._clean(data.get("city"))
        region_code = self._clean(data.get("region_code"))
        country_name = self._clean(data.get("country_name"))
        latitude = data.get("latitude")
        longitude = data.get("longitude")

        parts = [part for part in (city, region_code, country_name) if part]
        if not parts and not isinstance(latitude, (int, float)) and not isinstance(longitude, (int, float)):
            return None

        location_value = ", ".join(parts) if parts else self._clean(data.get("ip_str")) or "Unknown location"
        properties: dict[str, str | float] = {
            "city": city,
            "region_code": region_code,
            "country": country_name,
            "country_code": self._clean(data.get("country_code")),
            "postal_code": self._clean(data.get("postal_code")),
            "source": "shodan",
        }
        if isinstance(latitude, (int, float)):
            properties["lat"] = float(latitude)
        if isinstance(longitude, (int, float)):
            properties["lon"] = float(longitude)

        return Entity(
            type=EntityType.LOCATION,
            value=location_value,
            properties=properties,
            source=self.name,
        )

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _join_list(self, value: object) -> str:
        return ", ".join(self._iter_clean_list(value))

    def _iter_clean_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        seen: set[str] = set()
        results: list[str] = []
        for item in value:
            cleaned = str(item).strip()
            if not cleaned:
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(cleaned)
        return results

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))