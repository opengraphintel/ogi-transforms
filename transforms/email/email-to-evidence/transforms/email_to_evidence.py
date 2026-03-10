from __future__ import annotations

import re
from urllib.parse import parse_qs, quote, urlparse

import dns.resolver
import httpx
from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
GOOGLE_RESULT_RE = re.compile(r'''href\s*=\s*(?:"([^"]+)"|'([^']+)')''', re.IGNORECASE)
ROLE_LOCAL_PARTS = {"admin", "info", "contact", "hello", "support", "sales", "security", "abuse", "webmaster", "postmaster", "hostmaster"}
USER_AGENT = "Mozilla/5.0 (compatible; OGI Email Evidence/1.1; +https://github.com/opengraphintel/ogi)"


class EmailToEvidence(BaseTransform):
    name = "email_to_evidence"
    display_name = "Email to Evidence"
    description = "Collects evidence signals around an email address without claiming mailbox validity"
    input_types = [EntityType.EMAIL_ADDRESS]
    output_types = [EntityType.DOMAIN, EntityType.URL, EntityType.DOCUMENT]
    category = "Email"
    settings = [
        TransformSetting(name="timeout_seconds", display_name="Timeout Seconds", description="DNS and HTTP timeout used for evidence collection", default="10", field_type="integer", min_value=1, max_value=30),
        TransformSetting(name="include_domain_entity", display_name="Include Domain Entity", description="Emit the email domain as a Domain entity", default="true", field_type="boolean"),
        TransformSetting(name="include_source_urls", display_name="Include Source URLs", description="Emit observed source URLs already present in email properties", default="true", field_type="boolean"),
        TransformSetting(name="google_search_enabled", display_name="Enable Google Search", description="Perform a best-effort Google search for the exact email and crawl result pages for corroboration", default="false", field_type="boolean"),
        TransformSetting(name="google_max_results", display_name="Google Max Results", description="Maximum Google result pages to crawl when search corroboration is enabled", default="5", field_type="integer", min_value=1, max_value=20),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        email = entity.value.strip().lower()
        if not EMAIL_RE.fullmatch(email):
            return TransformResult(messages=[f"Invalid email address: {entity.value}"])

        timeout_seconds = self.parse_int_setting(config.settings.get("timeout_seconds", "10"), setting_name="timeout_seconds", default=10, min_value=1, declared_max=30)
        include_domain_entity = self._parse_bool(config.settings.get("include_domain_entity", "true"), default=True)
        include_source_urls = self._parse_bool(config.settings.get("include_source_urls", "true"), default=True)
        google_search_enabled = self._parse_bool(config.settings.get("google_search_enabled", "false"), default=False)
        google_max_results = self.parse_int_setting(config.settings.get("google_max_results", "5"), setting_name="google_max_results", default=5, min_value=1, declared_max=20)

        local_part, domain = email.split("@", 1)
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        mx_status, mx_hosts, mx_error = self._mx_evidence(domain, timeout_seconds=timeout_seconds)
        source_urls = self._source_urls(entity) if include_source_urls else []
        search_urls: list[str] = []
        search_error = ""
        if google_search_enabled:
            search_urls, search_error = await self._google_evidence(email, timeout_seconds=timeout_seconds, max_results=google_max_results)
        observed = bool(entity.properties.get("observed"))
        inferred = bool(entity.properties.get("inferred"))
        evidence_score = self._score_evidence(observed=observed, inferred=inferred, mx_status=mx_status, source_urls=source_urls, search_urls=search_urls)

        if include_domain_entity:
            domain_entity = Entity(
                type=EntityType.DOMAIN,
                value=domain,
                properties={"extracted_from": email, "mx_status": mx_status, "mx_hosts": mx_hosts},
                source=self.name,
            )
            entities.append(domain_entity)
            edges.append(Edge(source_id=entity.id, target_id=domain_entity.id, label="email hosted at", source_transform=self.name))

        for url in source_urls:
            url_entity = Entity(type=EntityType.URL, value=url, properties={"observed_email": email, "evidence_type": "source_url"}, source=self.name)
            entities.append(url_entity)
            edges.append(Edge(source_id=entity.id, target_id=url_entity.id, label="observed on", source_transform=self.name))

        for url in search_urls:
            url_entity = Entity(type=EntityType.URL, value=url, properties={"observed_email": email, "evidence_type": "google_search_match"}, source=self.name)
            entities.append(url_entity)
            edges.append(Edge(source_id=entity.id, target_id=url_entity.id, label="search corroboration", source_transform=self.name))

        summary_lines = [
            f"Email: {email}",
            f"Domain: {domain}",
            f"MX status: {mx_status}",
            f"Role account local-part: {'yes' if local_part in ROLE_LOCAL_PARTS else 'no'}",
            f"Observed flag on entity: {'yes' if observed else 'no'}",
            f"Inferred flag on entity: {'yes' if inferred else 'no'}",
            f"Observed source URLs: {len(source_urls)}",
            f"Google corroboration URLs: {len(search_urls)}",
            f"Evidence score: {evidence_score:.2f}",
            "Caveat: MX presence suggests the domain can receive mail, but does not prove that this mailbox exists.",
            "Caveat: Search-result corroboration only means the exact email string was found on fetched pages; it does not prove ownership or current mailbox validity.",
        ]
        if mx_hosts:
            summary_lines.append(f"MX hosts: {', '.join(mx_hosts)}")
        if mx_error:
            summary_lines.append(f"MX lookup error: {mx_error}")
        if search_error:
            summary_lines.append(f"Google search note: {search_error}")
        rationale = entity.properties.get("rationale")
        if isinstance(rationale, str) and rationale.strip():
            summary_lines.append(f"Prior rationale: {rationale.strip()}")

        document_entity = Entity(
            type=EntityType.DOCUMENT,
            value=f"Email evidence for {email}",
            properties={
                "content": "\n".join(summary_lines),
                "email": email,
                "domain": domain,
                "mx_status": mx_status,
                "mx_hosts": mx_hosts,
                "mx_error": mx_error,
                "observed": observed,
                "inferred": inferred,
                "source_urls": source_urls,
                "search_urls": search_urls,
                "role_account": local_part in ROLE_LOCAL_PARTS,
                "evidence_score": round(evidence_score, 2),
                "google_search_enabled": google_search_enabled,
            },
            source=self.name,
        )
        entities.append(document_entity)
        edges.append(Edge(source_id=entity.id, target_id=document_entity.id, label="evidence for", source_transform=self.name))

        messages.append(f"Collected evidence for {email}: mx={mx_status}, sources={len(source_urls)}, search_matches={len(search_urls)}, score={evidence_score:.2f}")
        if local_part in ROLE_LOCAL_PARTS:
            messages.append("The address looks like a role-based mailbox rather than a person-specific mailbox.")
        if mx_error:
            messages.append(f"MX lookup issue: {mx_error}")
        if search_error:
            messages.append(f"Google search note: {search_error}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    @staticmethod
    def _mx_evidence(domain: str, *, timeout_seconds: int) -> tuple[str, list[str], str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = float(timeout_seconds)
        resolver.lifetime = float(timeout_seconds)
        try:
            answers = resolver.resolve(domain, "MX")
            hosts = sorted({str(answer.exchange).rstrip('.').lower() for answer in answers})
            if hosts:
                return "mx_present", hosts, ""
            return "mx_absent", [], "No MX hosts returned"
        except dns.resolver.NoAnswer:
            return "mx_absent", [], "No MX answer"
        except dns.resolver.NXDOMAIN:
            return "domain_missing", [], "Domain does not exist"
        except Exception as exc:
            return "mx_unknown", [], str(exc)

    async def _google_evidence(self, email: str, *, timeout_seconds: int, max_results: int) -> tuple[list[str], str]:
        query = quote(f'"{email}"')
        search_url = f"https://www.google.com/search?q={query}&num={max_results}&hl=en"
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds), follow_redirects=True, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}) as client:
                response = await client.get(search_url)
                response.raise_for_status()
                candidate_urls = self._extract_google_result_urls(response.text)
                confirmed: list[str] = []
                seen: set[str] = set()
                for candidate in candidate_urls[:max_results]:
                    if candidate.lower() in seen:
                        continue
                    seen.add(candidate.lower())
                    try:
                        page = await client.get(candidate)
                        page.raise_for_status()
                        if email.lower() in (page.text or '').lower():
                            confirmed.append(str(page.url))
                    except Exception:
                        continue
                return confirmed, ""
        except Exception as exc:
            return [], str(exc)

    @staticmethod
    def _extract_google_result_urls(html: str) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()
        for match in GOOGLE_RESULT_RE.finditer(html):
            raw = (match.group(1) or match.group(2) or '').strip()
            if not raw:
                continue
            parsed = urlparse(raw)
            target = raw
            if raw.startswith('/url?'):
                qs = parse_qs(parsed.query)
                target = qs.get('q', [''])[0]
            parsed_target = urlparse(target)
            if parsed_target.scheme not in {'http', 'https'} or not parsed_target.netloc:
                continue
            host = parsed_target.hostname.lower() if parsed_target.hostname else ''
            if 'google.' in host:
                continue
            lowered = target.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            results.append(target)
        return results

    @staticmethod
    def _source_urls(entity: Entity) -> list[str]:
        props = entity.properties or {}
        raw_values: list[str] = []
        for key in ("observed_on_url", "source_url", "profile_url"):
            raw = props.get(key)
            if isinstance(raw, str):
                raw_values.append(raw)
        for key in ("source_urls", "observed_on_urls", "links"):
            raw = props.get(key)
            if isinstance(raw, list):
                raw_values.extend(str(item) for item in raw)
        deduped: list[str] = []
        seen: set[str] = set()
        for raw in raw_values:
            url = raw.strip()
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            lowered = url.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(url)
        return deduped

    @staticmethod
    def _score_evidence(*, observed: bool, inferred: bool, mx_status: str, source_urls: list[str], search_urls: list[str]) -> float:
        score = 0.0
        if observed:
            score += 0.6
        if inferred:
            score += 0.15
        if mx_status == "mx_present":
            score += 0.15
        if source_urls:
            score += min(0.25, 0.1 + (len(source_urls) * 0.05))
        if search_urls:
            score += min(0.25, 0.1 + (len(search_urls) * 0.05))
        return min(score, 0.99)

    @staticmethod
    def _parse_bool(raw: str | None, *, default: bool) -> bool:
        if raw is None:
            return default
        normalized = str(raw).strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        return default