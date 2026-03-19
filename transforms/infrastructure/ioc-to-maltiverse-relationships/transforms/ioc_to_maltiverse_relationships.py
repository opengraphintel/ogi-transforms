import hashlib

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IOCToMaltiverseRelationships(BaseTransform):
    name = "ioc_to_maltiverse_relationships"
    display_name = "IOC to Maltiverse Relationships"
    description = "Maps related entities from Maltiverse IOC records"
    input_types = [EntityType.IP_ADDRESS, EntityType.DOMAIN, EntityType.URL, EntityType.HASH]
    output_types = [
        EntityType.IP_ADDRESS,
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.HASH,
        EntityType.EMAIL_ADDRESS,
        EntityType.ORGANIZATION,
        EntityType.LOCATION,
        EntityType.NETWORK,
    ]
    category = "Infrastructure"
    settings = [
        TransformSetting(
            name="maltiverse_api_key",
            display_name="Maltiverse API Key",
            description="API key for Maltiverse lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Maltiverse request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="max_relationships",
            display_name="Max Relationships",
            description="Maximum number of related entities to emit from list fields",
            default="100",
            field_type="integer",
            min_value=10,
            max_value=500,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        value = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("maltiverse_api_key") or "").strip()
        if not api_key:
            messages.append("Maltiverse API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not value:
            messages.append("IOC value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)
        max_relationships = self._get_max_relationships(config)

        try:
            endpoint = self._endpoint_for_entity(entity)
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    endpoint,
                    headers={
                        "accept": "application/json",
                        "authorization": f"Bearer {api_key}",
                    },
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("Maltiverse returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            seen: set[tuple[str, str]] = set()
            emitted = 0

            if entity.type == EntityType.IP_ADDRESS:
                emitted += self._emit_ip_relationships(entity, data, entities, edges, seen, max_relationships)
            elif entity.type == EntityType.DOMAIN:
                emitted += self._emit_domain_relationships(entity, data, entities, edges, seen, max_relationships)
            elif entity.type == EntityType.URL:
                emitted += self._emit_url_relationships(entity, data, entities, edges, seen, max_relationships)
            elif entity.type == EntityType.HASH:
                emitted += self._emit_hash_relationships(entity, data, entities, edges, seen, max_relationships)

            messages.append(f"Maltiverse relationships emitted: {emitted}")
            classification = self._clean(data.get("classification"))
            if classification:
                messages.append(f"Classification: {classification}")
            tags = self._iter_clean_list(data.get("tag"))
            if tags:
                messages.append(f"Tags: {', '.join(tags[:10])}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid Maltiverse API key")
            elif e.response.status_code == 404:
                messages.append(f"Maltiverse has no record for {value}")
            elif e.response.status_code == 429:
                messages.append("Maltiverse rate limit exceeded")
            else:
                messages.append(f"Maltiverse HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Maltiverse: {e}")
        except Exception as e:
            messages.append(f"Error during Maltiverse relationship lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _endpoint_for_entity(self, entity: Entity) -> str:
        value = entity.value.strip()
        if entity.type == EntityType.IP_ADDRESS:
            return f"https://api.maltiverse.com/ip/{value}"
        if entity.type == EntityType.DOMAIN:
            return f"https://api.maltiverse.com/hostname/{value}"
        if entity.type == EntityType.URL:
            checksum = hashlib.sha256(value.encode()).hexdigest()
            return f"https://api.maltiverse.com/url/{checksum}"
        if entity.type == EntityType.HASH:
            return f"https://api.maltiverse.com/sample/{value}"
        raise ValueError(f"Unsupported entity type: {entity.type}")

    def _emit_ip_relationships(
        self,
        source: Entity,
        data: dict,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        max_relationships: int,
    ) -> int:
        emitted = 0
        for email in self._iter_clean_list(data.get("email"))[:max_relationships]:
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.EMAIL_ADDRESS,
                email,
                "contact email",
                {"source": "maltiverse"},
            )
        for cidr in self._iter_clean_list(data.get("cidr"))[:max_relationships]:
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.NETWORK,
                cidr,
                "belongs to network",
                {"source": "maltiverse"},
            )
        registrant_name = self._clean(data.get("registrant_name"))
        if registrant_name and emitted < max_relationships:
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.ORGANIZATION,
                registrant_name,
                "registered to",
                {"source": "maltiverse"},
            )
        location = data.get("location") if isinstance(data.get("location"), dict) else {}
        if location and emitted < max_relationships:
            lat = location.get("lat")
            lon = location.get("lon")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                label = self._clean(data.get("country_code")) or source.value
                emitted += self._append_entity(
                    source,
                    entities,
                    edges,
                    seen,
                    EntityType.LOCATION,
                    label,
                    "located in",
                    {"lat": str(float(lat)), "lon": str(float(lon)), "source": "maltiverse"},
                )
        return emitted

    def _emit_domain_relationships(
        self,
        source: Entity,
        data: dict,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        max_relationships: int,
    ) -> int:
        emitted = 0
        domain_value = self._clean(data.get("domain"))
        if domain_value and domain_value.lower() != source.value.strip().lower():
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.DOMAIN,
                domain_value,
                "registered under",
                {"source": "maltiverse"},
            )
        for item in data.get("resolved_ip", []) if isinstance(data.get("resolved_ip"), list) else []:
            if emitted >= max_relationships:
                break
            if not isinstance(item, dict):
                continue
            ip_value = self._clean(item.get("ip_addr"))
            if not ip_value:
                continue
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.IP_ADDRESS,
                ip_value,
                "resolves to",
                {"timestamp": self._clean(item.get("timestamp")), "source": "maltiverse"},
            )
        return emitted

    def _emit_url_relationships(
        self,
        source: Entity,
        data: dict,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        max_relationships: int,
    ) -> int:
        emitted = 0
        domain_value = self._clean(data.get("domain"))
        if domain_value:
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.DOMAIN,
                domain_value,
                "hosted on domain",
                {"source": "maltiverse"},
            )
        hostname = self._clean(data.get("hostname"))
        if hostname and hostname.lower() != domain_value.lower() and emitted < max_relationships:
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.DOMAIN,
                hostname,
                "hosted on hostname",
                {"source": "maltiverse"},
            )
        return emitted

    def _emit_hash_relationships(
        self,
        source: Entity,
        data: dict,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        max_relationships: int,
    ) -> int:
        emitted = 0
        process_list = data.get("process_list") if isinstance(data.get("process_list"), list) else []
        for item in process_list:
            if emitted >= max_relationships:
                break
            if not isinstance(item, dict):
                continue
            sha256_value = self._clean(item.get("sha256"))
            if not sha256_value or sha256_value.lower() == source.value.strip().lower():
                continue
            emitted += self._append_entity(
                source,
                entities,
                edges,
                seen,
                EntityType.HASH,
                sha256_value,
                "related sample",
                {"process_name": self._clean(item.get("name")), "source": "maltiverse"},
            )
        return emitted

    def _append_entity(
        self,
        source_entity: Entity,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        entity_type: EntityType,
        value: str,
        edge_label: str,
        properties: dict[str, str],
    ) -> int:
        key = (entity_type.value, value.lower())
        if key in seen:
            return 0
        seen.add(key)
        target = Entity(type=entity_type, value=value, properties=properties, source=self.name)
        entities.append(target)
        edges.append(Edge(
            source_id=source_entity.id,
            target_id=target.id,
            label=edge_label,
            source_transform=self.name,
        ))
        return 1

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

    def _get_max_relationships(self, config: TransformConfig) -> int:
        raw_value = config.settings.get("max_relationships", 100)
        try:
            max_relationships = int(raw_value)
        except (TypeError, ValueError):
            return 100
        return max(10, min(max_relationships, 500))