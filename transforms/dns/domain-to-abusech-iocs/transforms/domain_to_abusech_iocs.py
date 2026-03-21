import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class DomainToAbuseCHIOCs(BaseTransform):
    name = "domain_to_abusech_iocs"
    display_name = "Domain to abuse.ch IOCs"
    description = "Looks up a domain in abuse.ch ThreatFox and maps related IOC records"
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.DOMAIN, EntityType.URL, EntityType.IP_ADDRESS, EntityType.HASH, EntityType.DOCUMENT]
    category = "DNS Intelligence"
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
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of ThreatFox IOC records to map",
            default="25",
            field_type="integer",
            min_value=5,
            max_value=100,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        domain_value = entity.value.strip().lower()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("abusech_api_key") or "").strip()
        if not api_key:
            return TransformResult(messages=["abuse.ch API key required. Configure it under API Keys."])
        if not domain_value:
            return TransformResult(messages=["Domain value is empty"])

        try:
            records = await self._search_ioc(domain_value, api_key, self._get_timeout_seconds(config))
            if not records:
                return TransformResult(messages=[f"abuse.ch has no ThreatFox IOC records for {domain_value}"])

            domain_records = [record for record in records if self._clean(record.get("ioc_type")) == "domain"]
            best_record = domain_records[0] if domain_records else records[0]

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
                        "abusech_tags": self._join_tags(best_record.get("tags")),
                        "abusech_link": self._build_ioc_link(best_record),
                        "abusech_result_count": len(records),
                    }
                }
            )
            entities.append(enriched)

            summary_document = Entity(
                type=EntityType.DOCUMENT,
                value=f"abuse.ch ThreatFox IOC summary for {domain_value}",
                properties={
                    "provider": "abuse.ch",
                    "report_url": self._build_ioc_link(best_record),
                    "content": self._build_summary(domain_value, records),
                },
                source=self.name,
            )
            entities.append(summary_document)
            edges.append(Edge(source_id=entity.id, target_id=summary_document.id, label="has evidence", source_transform=self.name))

            seen: set[tuple[str, str]] = set()
            max_results = self._get_max_results(config)
            emitted = 0
            for record in records:
                if emitted >= max_results:
                    break
                emitted += self._emit_record_entities(entity, record, entities, edges, seen)

            messages.append(f"abuse.ch ThreatFox IOC records found: {len(records)}")
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

    def _emit_record_entities(
        self,
        source_entity: Entity,
        record: dict,
        entities: list[Entity],
        edges: list[Edge],
        seen: set[tuple[str, str]],
    ) -> int:
        emitted = 0
        ioc_value = self._clean(record.get("ioc"))
        ioc_type = self._clean(record.get("ioc_type"))
        if ioc_value:
            if ioc_type == "url":
                emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.URL, ioc_value, "related IOC", record)
            elif ioc_type in {"ip:port", "ip"}:
                ip_value = ioc_value.split(":", 1)[0].strip()
                if ip_value:
                    emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.IP_ADDRESS, ip_value, "related IOC", record)

        for hash_value in self._candidate_hashes(record):
            emitted += self._append_entity(source_entity, entities, edges, seen, EntityType.HASH, hash_value, "associated sample", record)
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
        record: dict,
    ) -> int:
        key = (entity_type.value, value.lower())
        if key in seen:
            return 0
        seen.add(key)
        target = Entity(
            type=entity_type,
            value=value,
            properties={
                "abusech_threat_type": self._clean(record.get("threat_type")),
                "abusech_malware": self._clean(record.get("malware_printable")) or self._clean(record.get("malware")),
                "abusech_first_seen": self._clean(record.get("first_seen")),
                "abusech_last_seen": self._clean(record.get("last_seen")),
                "abusech_reporter": self._clean(record.get("reporter")),
                "abusech_link": self._build_ioc_link(record),
            },
            source=self.name,
        )
        entities.append(target)
        edges.append(Edge(source_id=source_entity.id, target_id=target.id, label=label, source_transform=self.name))
        return 1

    def _build_summary(self, domain_value: str, records: list[dict]) -> str:
        lines = [f"Domain queried: {domain_value}", f"IOC records: {len(records)}"]
        for record in records[:10]:
            lines.append(
                " | ".join(
                    part
                    for part in [
                        self._clean(record.get("ioc_type")) or "unknown",
                        self._clean(record.get("ioc")) or "unknown",
                        self._clean(record.get("threat_type_desc")) or self._clean(record.get("threat_type")) or "unknown",
                        self._clean(record.get("malware_printable")) or self._clean(record.get("malware")) or "unknown",
                        self._clean(record.get("first_seen")) or "unknown",
                    ]
                )
            )
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

    def _get_max_results(self, config: TransformConfig) -> int:
        raw_value = config.settings.get("max_results", 25)
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return 25
        return max(5, min(value, 100))
