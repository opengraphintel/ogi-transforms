import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IPToGreyNoiseHistory(BaseTransform):
    name = "ip_to_greynoise_history"
    display_name = "IP to GreyNoise History"
    description = "Enriches an IP address with GreyNoise historical activity summary"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [EntityType.IP_ADDRESS, EntityType.ORGANIZATION, EntityType.LOCATION]
    category = "IP Intelligence"
    settings = [
        TransformSetting(
            name="greynoise_api_key",
            display_name="GreyNoise API Key",
            description="API key for GreyNoise timeline lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the GreyNoise history request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="max_activity_points",
            display_name="Max Activity Points",
            description="Maximum number of timeline activity points to summarize",
            default="200",
            field_type="integer",
            min_value=10,
            max_value=500,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("greynoise_api_key") or "").strip()
        if not api_key:
            messages.append("GreyNoise API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not ip:
            messages.append("IP value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)
        max_activity_points = self._get_max_activity_points(config)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    f"https://api.greynoise.io/v3/noise/ips/{ip}/timeline",
                    headers={
                        "accept": "application/json",
                        "key": api_key,
                    },
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("GreyNoise returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            activity = data.get("activity") if isinstance(data.get("activity"), list) else []
            activity = [item for item in activity if isinstance(item, dict)][:max_activity_points]

            classifications = self._collect_unique(item.get("classification") for item in activity)
            organizations = self._collect_unique(item.get("organization") for item in activity)
            rdns_values = self._collect_unique(item.get("rdns") for item in activity)
            countries = self._collect_unique(item.get("country") for item in activity)
            ports = self._collect_ports(activity)
            tags = self._collect_tag_slugs(activity)
            http_paths = self._collect_nested_strings(activity, "http_paths")
            user_agents = self._collect_nested_strings(activity, "http_user_agents")
            timestamps = [str(item.get("timestamp")).strip() for item in activity if str(item.get("timestamp") or "").strip()]

            enriched_properties: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "greynoise_history_window_start": self._clean(metadata.get("start_time")),
                "greynoise_history_window_end": self._clean(metadata.get("end_time")),
                "greynoise_history_ip": self._clean(metadata.get("ip")) or ip,
                "greynoise_history_event_count": len(activity),
                "greynoise_history_first_seen": timestamps[0] if timestamps else "",
                "greynoise_history_last_seen": timestamps[-1] if timestamps else "",
                "greynoise_history_classifications": ", ".join(classifications),
                "greynoise_history_ports": ", ".join(ports),
                "greynoise_history_tags": ", ".join(tags),
                "greynoise_history_organizations": ", ".join(organizations),
                "greynoise_history_rdns": ", ".join(rdns_values),
                "greynoise_history_countries": ", ".join(countries),
                "greynoise_history_http_paths": ", ".join(http_paths),
                "greynoise_history_user_agents": ", ".join(user_agents),
            }

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            seen: set[tuple[str, str]] = set()
            for org_name in organizations:
                key = (EntityType.ORGANIZATION.value, org_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                org_entity = Entity(
                    type=EntityType.ORGANIZATION,
                    value=org_name,
                    properties={"source": "greynoise", "kind": "historical_observation"},
                    source=self.name,
                )
                entities.append(org_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=org_entity.id,
                    label="observed from organization",
                    source_transform=self.name,
                ))

            for country_name in countries:
                key = (EntityType.LOCATION.value, country_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                location_entity = Entity(
                    type=EntityType.LOCATION,
                    value=country_name,
                    properties={"country": country_name, "source": "greynoise", "kind": "historical_country"},
                    source=self.name,
                )
                entities.append(location_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=location_entity.id,
                    label="observed in country",
                    source_transform=self.name,
                ))

            messages.append(f"GreyNoise history events summarized: {len(activity)}")
            if classifications:
                messages.append(f"Classifications: {', '.join(classifications)}")
            if ports:
                messages.append(f"Ports: {', '.join(ports)}")
            if tags:
                messages.append(f"Tags: {', '.join(tags[:10])}")
            if organizations:
                messages.append(f"Organizations: {', '.join(organizations[:5])}")
            if countries:
                messages.append(f"Countries: {', '.join(countries[:5])}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid GreyNoise API key")
            elif e.response.status_code == 402:
                messages.append("GreyNoise timeline access requires an additional subscription license")
            elif e.response.status_code == 404:
                messages.append(f"GreyNoise has no historical timeline data for {ip}")
            elif e.response.status_code == 429:
                messages.append("GreyNoise rate limit exceeded")
            else:
                messages.append(f"GreyNoise HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting GreyNoise: {e}")
        except Exception as e:
            messages.append(f"Error during GreyNoise history lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _collect_ports(self, activity: list[dict]) -> list[str]:
        seen: set[str] = set()
        ports: list[str] = []
        for item in activity:
            protocols = item.get("protocols")
            if not isinstance(protocols, list):
                continue
            for protocol in protocols:
                if not isinstance(protocol, dict):
                    continue
                port = protocol.get("port")
                if port is None:
                    continue
                value = str(port).strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                ports.append(value)
        return ports

    def _collect_tag_slugs(self, activity: list[dict]) -> list[str]:
        seen: set[str] = set()
        tags: list[str] = []
        for item in activity:
            raw_tags = item.get("tags")
            if not isinstance(raw_tags, list):
                continue
            for tag in raw_tags:
                if not isinstance(tag, dict):
                    continue
                value = self._clean(tag.get("slug")) or self._clean(tag.get("name"))
                if not value:
                    continue
                normalized = value.lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                tags.append(value)
        return tags

    def _collect_nested_strings(self, activity: list[dict], field_name: str) -> list[str]:
        seen: set[str] = set()
        values: list[str] = []
        for item in activity:
            raw = item.get(field_name)
            if not isinstance(raw, list):
                continue
            for entry in raw:
                value = self._clean(entry)
                if not value:
                    continue
                normalized = value.lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                values.append(value)
        return values

    def _collect_unique(self, values) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []
        for raw in values:
            value = self._clean(raw)
            if not value:
                continue
            normalized = value.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(value)
        return results

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))

    def _get_max_activity_points(self, config: TransformConfig) -> int:
        raw_value = config.settings.get("max_activity_points", 200)
        try:
            max_points = int(raw_value)
        except (TypeError, ValueError):
            return 200
        return max(10, min(max_points, 500))