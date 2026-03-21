import ipaddress
from urllib.parse import urlparse

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class URLToAbuseCHIOC(BaseTransform):
    name = "url_to_abusech_ioc"
    display_name = "URL to abuse.ch IOC"
    description = "Looks up a URL in abuse.ch ThreatFox"
    input_types = [EntityType.URL]
    output_types = [EntityType.URL, EntityType.DOCUMENT, EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.HASH]
    category = "Web Intelligence"
    settings = [
        TransformSetting(
            name="abusech_api_key",
            display_name="abuse.ch API Key",
            description="Auth-Key for abuse.ch ThreatFox IOC lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the ThreatFox request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        url_value = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("abusech_api_key") or "").strip()
        if not api_key:
            return TransformResult(messages=["abuse.ch API key required. Configure it under API Keys."])
        if not url_value:
            return TransformResult(messages=["URL value is empty"])

        try:
            records = await self._search_ioc(url_value, api_key, self._get_timeout_seconds(config))
            url_records = [record for record in records if self._clean(record.get("ioc_type")) == "url"]
            if not url_records:
                return TransformResult(messages=[f"abuse.ch has no ThreatFox IOC record for {url_value}"])

            best_record = url_records[0]
            enriched = entity.model_copy(
                update={
                    "properties": {
                        **entity.properties,
                        "abusech_threatfox_id": self._clean(best_record.get("id")),
                        "abusech_ioc": self._clean(best_record.get("ioc")),
                        "abusech_ioc_type": self._clean(best_record.get("ioc_type")),
                        "abusech_threat_type": self._clean(best_record.get("threat_type")),
                        "abusech_threat_type_desc": self._clean(best_record.get("threat_type_desc")),
                        "abusech_malware": self._clean(best_record.get("malware")),
                        "abusech_malware_printable": self._clean(best_record.get("malware_printable")),
                        "abusech_confidence_level": self._clean(best_record.get("confidence_level")),
                        "abusech_reporter": self._clean(best_record.get("reporter")),
                        "abusech_first_seen": self._clean(best_record.get("first_seen")),
                        "abusech_last_seen": self._clean(best_record.get("last_seen")),
                        "abusech_reference": self._clean(best_record.get("reference")),
                        "abusech_tags": self._join_tags(best_record.get("tags")),
                        "abusech_link": self._build_ioc_link(best_record),
                    }
                }
            )
            entities.append(enriched)

            summary_document = Entity(
                type=EntityType.DOCUMENT,
                value=f"abuse.ch ThreatFox IOC summary for {url_value}",
                properties={
                    "provider": "abuse.ch",
                    "report_url": self._build_ioc_link(best_record),
                    "content": self._build_summary(best_record),
                },
                source=self.name,
            )
            entities.append(summary_document)
            edges.append(Edge(source_id=entity.id, target_id=summary_document.id, label="has evidence", source_transform=self.name))

            emitted = self._emit_related_entities(entity, best_record, entities, edges)
            messages.append("abuse.ch ThreatFox IOC found")
            if emitted:
                messages.append(f"Related entities emitted: {emitted}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code in {401, 403}:
                messages.append("Invalid abuse.ch API key")
            elif e.response.status_code == 429:
                messages.append("abuse.ch rate limit exceeded")
            else:
                messages.append(f"abuse.ch HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting abuse.ch: {e}")
        except Exception as e:
            messages.append(f"Error during abuse.ch IOC lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _search_ioc(self, value: str, api_key: str, timeout_seconds: float) -> list[dict]:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": value, "exact_match": True},
                headers={"Auth-Key": api_key, "accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            return []
        status = self._clean(payload.get("query_status"))
        if status in {"no_result", "no_results", "ioc_not_found"}:
            return []
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def _emit_related_entities(self, source_entity: Entity, record: dict, entities: list[Entity], edges: list[Edge]) -> int:
        emitted = 0
        seen: set[tuple[str, str]] = set()
        parsed = urlparse(self._clean(record.get("ioc")))
        hostname = (parsed.hostname or "").strip().lower()
        if hostname:
            if self._is_valid_ip(hostname):
                emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.IP_ADDRESS, hostname, "hosted on")
            else:
                emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.DOMAIN, hostname, "hosted on")

        for hash_value in self._candidate_hashes(record):
            emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.HASH, hash_value, "associated sample")

        return emitted

    def _candidate_hashes(self, record: dict) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()
        for key in ("md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"):
            value = self._clean(record.get(key))
            if value and value.lower() not in seen:
                seen.add(value.lower())
                results.append(value)
        malware_samples = record.get("malware_samples")
        if isinstance(malware_samples, list):
            for item in malware_samples:
                if not isinstance(item, dict):
                    continue
                for key in ("sha256_hash", "sha1_hash", "md5_hash"):
                    value = self._clean(item.get(key))
                    if value and value.lower() not in seen:
                        seen.add(value.lower())
                        results.append(value)
        return results

    def _append_entity(
        self,
        source_entity: Entity,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
        entity_type: EntityType,
        value: str,
        label: str,
    ) -> int:
        key = (entity_type.value, value.lower())
        if key in seen:
            return 0
        seen.add(key)
        target = Entity(type=entity_type, value=value, properties={"source": "abuse.ch"}, source=self.name)
        entities.append(target)
        edges.append(Edge(source_id=source_entity.id, target_id=target.id, label=label, source_transform=self.name))
        return 1

    def _build_summary(self, record: dict) -> str:
        lines = [
            f"IOC: {self._clean(record.get('ioc')) or 'unknown'}",
            f"IOC type: {self._clean(record.get('ioc_type')) or 'unknown'}",
            f"Threat type: {self._clean(record.get('threat_type_desc')) or self._clean(record.get('threat_type')) or 'unknown'}",
            f"Malware: {self._clean(record.get('malware_printable')) or self._clean(record.get('malware')) or 'unknown'}",
            f"Confidence level: {self._clean(record.get('confidence_level')) or 'unknown'}",
            f"Reporter: {self._clean(record.get('reporter')) or 'unknown'}",
            f"First seen: {self._clean(record.get('first_seen')) or 'unknown'}",
            f"Last seen: {self._clean(record.get('last_seen')) or 'unknown'}",
            f"Reference: {self._clean(record.get('reference')) or 'unknown'}",
            f"Tags: {self._join_tags(record.get('tags')) or 'none'}",
            f"ThreatFox URL: {self._build_ioc_link(record)}",
        ]
        return "`n".join(lines)

    def _build_ioc_link(self, record: dict) -> str:
        record_id = self._clean(record.get("id"))
        if record_id:
            return f"https://threatfox.abuse.ch/ioc/{record_id}/"
        return "https://threatfox.abuse.ch/"

    def _join_tags(self, value: object) -> str:
        if not isinstance(value, list):
            return ""
        seen: set[str] = set()
        items: list[str] = []
        for item in value:
            cleaned = self._clean(item)
            if not cleaned:
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            items.append(cleaned)
        return ", ".join(items)

    def _is_valid_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

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
