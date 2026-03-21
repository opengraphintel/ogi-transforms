import ipaddress

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IPToShodanHost(BaseTransform):
    name = "ip_to_shodan_host"
    display_name = "IP to Shodan Host"
    description = "Creates a baseline Shodan host summary for an IP address"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [
        EntityType.IP_ADDRESS,
        EntityType.DOCUMENT,
        EntityType.ORGANIZATION,
        EntityType.AS_NUMBER,
        EntityType.LOCATION,
        EntityType.NETWORK,
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
            return TransformResult(messages=["Shodan API key required. Configure it under API Keys."])
        if not ip:
            return TransformResult(messages=["IP value is empty"])

        try:
            async with httpx.AsyncClient(timeout=self._get_timeout_seconds(config)) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": api_key, "minify": "true"},
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                return TransformResult(messages=["Shodan returned an unexpected response payload"])

            enriched = entity.model_copy(
                update={
                    "properties": {
                        **entity.properties,
                        "shodan_ip_str": self._clean(data.get("ip_str")),
                        "shodan_asn": self._clean(data.get("asn")),
                        "shodan_isp": self._clean(data.get("isp")),
                        "shodan_org": self._clean(data.get("org")),
                        "shodan_os": self._clean(data.get("os")),
                        "shodan_ports": self._join_list(data.get("ports")),
                        "shodan_tags": self._join_list(data.get("tags")),
                        "shodan_country_name": self._clean(data.get("country_name")),
                        "shodan_last_update": self._clean(data.get("last_update")),
                        "shodan_link": f"https://www.shodan.io/host/{ip}",
                    }
                }
            )
            entities.append(enriched)

            summary_document = Entity(
                type=EntityType.DOCUMENT,
                value=f"Shodan host summary for {ip}",
                properties={
                    "provider": "shodan",
                    "report_url": f"https://www.shodan.io/host/{ip}",
                    "content": self._build_summary(ip, data),
                },
                source=self.name,
            )
            entities.append(summary_document)
            edges.append(Edge(source_id=entity.id, target_id=summary_document.id, label="has evidence", source_transform=self.name))

            asn_value = self._clean(data.get("asn"))
            if asn_value:
                as_entity = Entity(
                    type=EntityType.AS_NUMBER,
                    value=asn_value,
                    properties={"org": self._clean(data.get("org")), "isp": self._clean(data.get("isp")), "source": "shodan"},
                    source=self.name,
                )
                entities.append(as_entity)
                edges.append(Edge(source_id=entity.id, target_id=as_entity.id, label="belongs to ASN", source_transform=self.name))

            org_value = self._clean(data.get("org"))
            if org_value:
                org_entity = Entity(
                    type=EntityType.ORGANIZATION,
                    value=org_value,
                    properties={"asn": asn_value, "isp": self._clean(data.get("isp")), "source": "shodan"},
                    source=self.name,
                )
                entities.append(org_entity)
                edges.append(Edge(source_id=entity.id, target_id=org_entity.id, label="operated by", source_transform=self.name))

            location_entity = self._build_location_entity(data)
            if location_entity is not None:
                entities.append(location_entity)
                edges.append(Edge(source_id=entity.id, target_id=location_entity.id, label="located in", source_transform=self.name))

            network_entity = self._build_network_entity(ip)
            if network_entity is not None:
                entities.append(network_entity)
                edges.append(Edge(source_id=entity.id, target_id=network_entity.id, label="within network", source_transform=self.name))

            messages.append("Baseline Shodan host profile created")
            if asn_value:
                messages.append(f"ASN: {asn_value}")
            if org_value:
                messages.append(f"Organization: {org_value}")

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

    def _build_summary(self, ip: str, data: dict) -> str:
        lines = [
            f"IP: {self._clean(data.get('ip_str')) or ip}",
            f"ASN: {self._clean(data.get('asn')) or 'unknown'}",
            f"Organization: {self._clean(data.get('org')) or 'unknown'}",
            f"ISP: {self._clean(data.get('isp')) or 'unknown'}",
            f"OS: {self._clean(data.get('os')) or 'unknown'}",
            f"Country: {self._clean(data.get('country_name')) or 'unknown'}",
            f"Ports: {self._join_list(data.get('ports')) or 'none'}",
            f"Tags: {self._join_list(data.get('tags')) or 'none'}",
            f"Hostnames: {self._join_list(data.get('hostnames')) or 'none'}",
            f"Domains: {self._join_list(data.get('domains')) or 'none'}",
            f"Last update: {self._clean(data.get('last_update')) or 'unknown'}",
            f"Shodan URL: https://www.shodan.io/host/{ip}",
        ]
        return "\n".join(lines)

    def _build_location_entity(self, data: dict) -> Entity | None:
        city = self._clean(data.get("city"))
        region_code = self._clean(data.get("region_code"))
        country_name = self._clean(data.get("country_name"))
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        parts = [part for part in (city, region_code, country_name) if part]
        if not parts and not isinstance(latitude, (int, float)) and not isinstance(longitude, (int, float)):
            return None
        properties: dict[str, str | float] = {
            "city": city,
            "region_code": region_code,
            "country": country_name,
            "country_code": self._clean(data.get("country_code")),
            "source": "shodan",
        }
        if isinstance(latitude, (int, float)):
            properties["lat"] = float(latitude)
        if isinstance(longitude, (int, float)):
            properties["lon"] = float(longitude)
        return Entity(type=EntityType.LOCATION, value=", ".join(parts) if parts else "Observed location", properties=properties, source=self.name)

    def _build_network_entity(self, ip: str) -> Entity | None:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None
        prefix = 24 if ip_obj.version == 4 else 64
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return Entity(
            type=EntityType.NETWORK,
            value=str(network),
            properties={"derived_from_ip": ip, "prefix_length": prefix, "source": "shodan"},
            source=self.name,
        )

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _join_list(self, value: object) -> str:
        if not isinstance(value, list):
            return ""
        return ", ".join(str(item).strip() for item in value if str(item).strip())

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))
