import ipaddress
from urllib.parse import urlparse

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IOCToAbuseCHCampaignContext(BaseTransform):
    name = "ioc_to_abusech_campaign_context"
    display_name = "IOC to abuse.ch Campaign Context"
    description = "Aggregates abuse.ch campaign and family context for an IOC"
    input_types = [EntityType.DOMAIN, EntityType.URL, EntityType.IP_ADDRESS, EntityType.HASH]
    output_types = [EntityType.DOCUMENT, EntityType.DOMAIN, EntityType.URL, EntityType.IP_ADDRESS, EntityType.HASH]
    category = "Infrastructure Intelligence"
    settings = [
        TransformSetting(name="abusech_api_key", display_name="abuse.ch API Key", description="Auth-Key for abuse.ch ThreatFox and MalwareBazaar lookups", required=True, field_type="secret"),
        TransformSetting(name="max_related", display_name="Max Related", description="Maximum number of related IOC entities to emit", default="25", field_type="integer", min_value=5, max_value=100),
        TransformSetting(name="timeout_seconds", display_name="Timeout Seconds", description="HTTP timeout for the abuse.ch requests", default="20", field_type="integer", min_value=5, max_value=30),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        api_key = str(config.settings.get("abusech_api_key") or "").strip()
        if not api_key:
            return TransformResult(messages=["abuse.ch API key required. Configure it under API Keys."])
        value = entity.value.strip()
        if not value:
            return TransformResult(messages=["IOC value is empty"])

        timeout_seconds = self._get_timeout_seconds(config)
        if entity.type == EntityType.HASH:
            records = await self._search_malware_sample(value, api_key, timeout_seconds)
            if not records:
                return TransformResult(messages=[f"abuse.ch has no campaign context for {value}"])
            return self._from_malware_sample(entity, records[0], config)

        records = await self._search_threatfox(value, api_key, timeout_seconds)
        if not records:
            return TransformResult(messages=[f"abuse.ch has no campaign context for {value}"])
        return self._from_threatfox_records(entity, records, config)

    async def _search_threatfox(self, value: str, api_key: str, timeout_seconds: float) -> list[dict]:
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
        if str(payload.get("query_status") or "").strip().lower() in {"no_result", "no_results", "ioc_not_found"}:
            return []
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    async def _search_malware_sample(self, hash_value: str, api_key: str, timeout_seconds: float) -> list[dict]:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_value},
                headers={"Auth-Key": api_key, "accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict) or str(payload.get("query_status") or "").strip().lower() not in {"ok", ""}:
            return []
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    def _from_threatfox_records(self, entity: Entity, records: list[dict], config: TransformConfig) -> TransformResult:
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages = [f"abuse.ch campaign context records: {len(records)}"]
        best = records[0]
        doc = Entity(
            type=EntityType.DOCUMENT,
            value=f"abuse.ch campaign context for {entity.value}",
            properties={
                "provider": "abuse.ch",
                "report_url": self._record_link(best),
                "content": self._threatfox_summary(entity.value, records),
            },
            source=self.name,
        )
        entities.append(doc)
        edges.append(Edge(source_id=entity.id, target_id=doc.id, label="has evidence", source_transform=self.name))

        seen: set[tuple[str, str]] = set()
        emitted = 0
        limit = self._get_max_related(config)
        for record in records:
            if emitted >= limit:
                break
            ioc_value = self._clean(record.get("ioc"))
            ioc_type = self._clean(record.get("ioc_type"))
            if ioc_value:
                if ioc_type == "url":
                    emitted += self._append_entity(entity, entities, edges, seen, EntityType.URL, ioc_value, "related IOC")
                    host = (urlparse(ioc_value).hostname or "").strip().lower()
                    if host:
                        emitted += self._append_host(entity, entities, edges, seen, host)
                elif ioc_type in {"ip", "ip:port"}:
                    emitted += self._append_entity(entity, entities, edges, seen, EntityType.IP_ADDRESS, ioc_value.split(":", 1)[0].strip(), "related IOC")
                elif ioc_type == "domain":
                    emitted += self._append_entity(entity, entities, edges, seen, EntityType.DOMAIN, ioc_value.lower(), "related IOC")
            for hash_key in ("md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"):
                hash_value = self._clean(record.get(hash_key))
                if hash_value:
                    emitted += self._append_entity(entity, entities, edges, seen, EntityType.HASH, hash_value, "associated sample")
        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _from_malware_sample(self, entity: Entity, sample: dict, config: TransformConfig) -> TransformResult:
        entities: list[Entity] = []
        edges: list[Edge] = []
        sample_sha256 = self._clean(sample.get("sha256_hash")) or entity.value
        doc = Entity(
            type=EntityType.DOCUMENT,
            value=f"abuse.ch campaign context for {sample_sha256}",
            properties={
                "provider": "abuse.ch",
                "report_url": f"https://bazaar.abuse.ch/sample/{sample_sha256}/",
                "content": self._malware_summary(sample_sha256, sample),
            },
            source=self.name,
        )
        entities.append(doc)
        edges.append(Edge(source_id=entity.id, target_id=doc.id, label="has evidence", source_transform=self.name))

        seen: set[tuple[str, str]] = set()
        emitted = 0
        limit = self._get_max_related(config)
        urls, domains, ips = self._extract_related_context(sample)
        for value in urls:
            if emitted >= limit:
                break
            emitted += self._append_entity(entity, entities, edges, seen, EntityType.URL, value, "related IOC")
        for value in domains:
            if emitted >= limit:
                break
            emitted += self._append_entity(entity, entities, edges, seen, EntityType.DOMAIN, value, "related IOC")
        for value in ips:
            if emitted >= limit:
                break
            emitted += self._append_entity(entity, entities, edges, seen, EntityType.IP_ADDRESS, value, "related IOC")
        for key in ("md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"):
            hash_value = self._clean(sample.get(key))
            if emitted >= limit:
                break
            if hash_value and hash_value.lower() != entity.value.strip().lower():
                emitted += self._append_entity(entity, entities, edges, seen, EntityType.HASH, hash_value, "related hash")
        return TransformResult(entities=entities, edges=edges, messages=[f"abuse.ch campaign context built for {entity.value}", f"Related entities emitted: {emitted}"])

    def _threatfox_summary(self, input_value: str, records: list[dict]) -> str:
        families = sorted({self._clean(record.get("malware_printable")) or self._clean(record.get("malware")) for record in records if self._clean(record.get("malware_printable")) or self._clean(record.get("malware"))})
        threat_types = sorted({self._clean(record.get("threat_type_desc")) or self._clean(record.get("threat_type")) for record in records if self._clean(record.get("threat_type_desc")) or self._clean(record.get("threat_type"))})
        lines = [
            f"Input IOC: {input_value}",
            f"ThreatFox records: {len(records)}",
            f"Families: {', '.join(families) if families else 'unknown'}",
            f"Threat types: {', '.join(threat_types) if threat_types else 'unknown'}",
        ]
        for record in records[:10]:
            lines.append(
                " | ".join([
                    self._clean(record.get("ioc_type")) or "unknown",
                    self._clean(record.get("ioc")) or "unknown",
                    self._clean(record.get("malware_printable")) or self._clean(record.get("malware")) or "unknown",
                    self._clean(record.get("threat_type_desc")) or self._clean(record.get("threat_type")) or "unknown",
                    self._clean(record.get("first_seen")) or "unknown",
                ])
            )
        return "\n".join(lines)

    def _malware_summary(self, sha256_hash: str, sample: dict) -> str:
        return "\n".join([
            f"Sample: {sha256_hash}",
            f"Signature: {self._clean(sample.get('signature')) or 'unknown'}",
            f"Reporter: {self._clean(sample.get('reporter')) or 'unknown'}",
            f"Delivery method: {self._clean(sample.get('delivery_method')) or 'unknown'}",
            f"First seen: {self._clean(sample.get('first_seen')) or 'unknown'}",
            f"Last seen: {self._clean(sample.get('last_seen')) or 'unknown'}",
            f"Tags: {self._join_list(sample.get('tags')) or 'none'}",
            f"MalwareBazaar URL: https://bazaar.abuse.ch/sample/{sha256_hash}/",
        ])

    def _extract_related_context(self, sample: dict) -> tuple[list[str], list[str], list[str]]:
        urls: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()
        self._walk_context(sample, urls, domains, ips)
        return sorted(urls), sorted(domains), sorted(ips)

    def _walk_context(self, value: object, urls: set[str], domains: set[str], ips: set[str]) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                self._walk_context(nested, urls, domains, ips)
            return
        if isinstance(value, list):
            for item in value:
                self._walk_context(item, urls, domains, ips)
            return
        if not isinstance(value, str):
            return
        text = value.strip()
        if not text:
            return
        for token in text.split():
            if token.startswith("http://") or token.startswith("https://"):
                parsed = urlparse(token.rstrip('.,);]'))
                if parsed.scheme and parsed.netloc:
                    cleaned = parsed.geturl()
                    urls.add(cleaned)
                    host = (parsed.hostname or "").strip().lower()
                    if host:
                        self._append_host_value(host, domains, ips)
        if "." in text and not text.startswith("http"):
            self._append_host_value(text.strip().lower().rstrip('.'), domains, ips)

    def _append_host_value(self, host: str, domains: set[str], ips: set[str]) -> None:
        try:
            ipaddress.ip_address(host)
            ips.add(host)
            return
        except ValueError:
            pass
        if "." in host and " " not in host:
            domains.add(host)

    def _append_host(self, source_entity: Entity, entities: list[Entity], edges: list[Edge], seen: set[tuple[str, str]], host: str) -> int:
        try:
            ipaddress.ip_address(host)
            return self._append_entity(source_entity, entities, edges, seen, EntityType.IP_ADDRESS, host, "hosted on")
        except ValueError:
            return self._append_entity(source_entity, entities, edges, seen, EntityType.DOMAIN, host, "hosted on")

    def _append_entity(self, source_entity: Entity, entities: list[Entity], edges: list[Edge], seen: set[tuple[str, str]], entity_type: EntityType, value: str, label: str) -> int:
        key = (entity_type.value, value.lower())
        if key in seen:
            return 0
        seen.add(key)
        target = Entity(type=entity_type, value=value, properties={"source": "abuse.ch"}, source=self.name)
        entities.append(target)
        edges.append(Edge(source_id=source_entity.id, target_id=target.id, label=label, source_transform=self.name))
        return 1

    def _record_link(self, record: dict) -> str:
        record_id = self._clean(record.get("id"))
        if record_id:
            return f"https://threatfox.abuse.ch/ioc/{record_id}/"
        return "https://threatfox.abuse.ch/"

    def _join_list(self, value: object) -> str:
        if not isinstance(value, list):
            return ""
        return ", ".join(self._clean(item) for item in value if self._clean(item))

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _get_max_related(self, config: TransformConfig) -> int:
        try:
            value = int(config.settings.get("max_related", 25))
        except (TypeError, ValueError):
            return 25
        return max(5, min(value, 100))

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        try:
            value = float(config.settings.get("timeout_seconds", 20))
        except (TypeError, ValueError):
            return 20.0
        return max(5.0, min(value, 30.0))
