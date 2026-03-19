import json
import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig


class DomainToCrtshCertificates(BaseTransform):
    name = "domain_to_crtsh_certificates"
    display_name = "Domain to crt.sh Certificates"
    description = "Queries crt.sh for certificate records associated with a domain"
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.SSL_CERTIFICATE]
    category = "Certificate"

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        domain = entity.value.strip().lower()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        if not domain:
            messages.append("Domain value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        max_results = self._get_max_results(config)
        timeout_seconds = self._get_timeout_seconds(config)

        try:
            records = await self._fetch_records(domain, timeout_seconds)
        except httpx.TimeoutException:
            messages.append(f"Request to crt.sh timed out for {domain}")
            return TransformResult(entities=entities, edges=edges, messages=messages)
        except httpx.HTTPStatusError as e:
            messages.append(f"crt.sh returned HTTP {e.response.status_code} for {domain}")
            return TransformResult(entities=entities, edges=edges, messages=messages)
        except httpx.RequestError as e:
            messages.append(f"Request error contacting crt.sh for {domain}: {e}")
            return TransformResult(entities=entities, edges=edges, messages=messages)
        except Exception as e:
            messages.append(f"Error querying crt.sh for {domain}: {e}")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not records:
            messages.append(f"No crt.sh certificates found for {domain}")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if len(records) > max_results:
            messages.append(
                f"Found {len(records)} certificate records, limiting to {max_results}"
            )

        for record in records[:max_results]:
            common_name = str(record.get("common_name") or "").strip()
            issuer_name = str(record.get("issuer_name") or "").strip()
            serial_number = str(record.get("serial_number") or "").strip()
            name_value = str(record.get("name_value") or "").strip()
            crtsh_id = str(record.get("id") or "").strip()
            not_before = str(record.get("not_before") or "").strip()
            not_after = str(record.get("not_after") or "").strip()
            entry_timestamp = str(record.get("entry_timestamp") or "").strip()
            matching_domain = self._pick_matching_name(name_value, common_name, domain)

            cert_value = common_name or matching_domain or f"crt.sh:{crtsh_id}" or domain
            cert_entity = Entity(
                type=EntityType.SSL_CERTIFICATE,
                value=cert_value,
                properties={
                    "crtsh_id": crtsh_id,
                    "issuer_name": issuer_name,
                    "common_name": common_name,
                    "name_value": name_value,
                    "serial_number": serial_number,
                    "not_before": not_before,
                    "not_after": not_after,
                    "entry_timestamp": entry_timestamp,
                    "matching_domain": matching_domain,
                    "source": "crt.sh",
                    "query_domain": domain,
                },
                source=self.name,
            )
            entities.append(cert_entity)
            edges.append(Edge(
                source_id=entity.id,
                target_id=cert_entity.id,
                label="observed in CT logs",
                source_transform=self.name,
            ))

        messages.append(f"Found {len(entities)} certificate records via crt.sh")
        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _fetch_records(self, domain: str, timeout_seconds: float) -> list[dict[str, object]]:
        queries = [domain, f"%.{domain}"]
        merged: dict[str, dict[str, object]] = {}

        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            for query in queries:
                response = await client.get(
                    "https://crt.sh/",
                    params={"q": query, "output": "json"},
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                payload = self._parse_payload(response.text)
                for record in payload:
                    record_id = str(record.get("id") or "").strip()
                    if not record_id:
                        continue
                    merged[record_id] = record

        return sorted(
            merged.values(),
            key=lambda record: (
                str(record.get("entry_timestamp") or ""),
                str(record.get("id") or ""),
            ),
            reverse=True,
        )

    def _parse_payload(self, payload: str) -> list[dict[str, object]]:
        if not payload.strip():
            return []

        data = json.loads(payload)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    def _pick_matching_name(self, name_value: str, common_name: str, domain: str) -> str:
        candidates: list[str] = []
        if name_value:
            candidates.extend(part.strip() for part in name_value.splitlines())
        if common_name:
            candidates.append(common_name.strip())

        for candidate in candidates:
            lowered = candidate.lower().lstrip("*.")
            if lowered == domain or lowered.endswith(f".{domain}"):
                return candidate
        return common_name or domain

    def _get_max_results(self, config: TransformConfig) -> int:
        raw_value = config.settings.get("max_results", 100)
        try:
            max_results = int(raw_value)
        except (TypeError, ValueError):
            return 100
        return max(1, min(max_results, 500))

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 20)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 20.0
        return max(5.0, min(timeout, 60.0))