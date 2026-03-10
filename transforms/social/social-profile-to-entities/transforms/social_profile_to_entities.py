from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse

import httpx
from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_RE = re.compile(r'''<meta[^>]+(?:property|name)=["'](?:og:title|twitter:title)["'][^>]+content=["'](.*?)["'][^>]*>''', re.IGNORECASE | re.DOTALL)
CANONICAL_RE = re.compile(r'''<link[^>]+rel=["']canonical["'][^>]+href=["'](.*?)["'][^>]*>''', re.IGNORECASE | re.DOTALL)
HREF_RE = re.compile(r'''href\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))''', re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
PROFILE_PATH_PATTERNS = [
    re.compile(r"^/@([A-Za-z0-9._-]{2,32})/?$", re.IGNORECASE),
    re.compile(r"^/(?:user|users|profile|profiles|member|members|u)/([A-Za-z0-9._-]{2,32})/?$", re.IGNORECASE),
    re.compile(r"^/([A-Za-z0-9._-]{2,32})/?$"),
]
ASSET_EXTENSIONS = (
    ".css", ".js", ".json", ".xml", ".txt", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".pdf", ".zip",
)
USER_AGENT = "OGI Social Profile Entity Extractor/1.1"


class SocialProfileToEntities(BaseTransform):
    name = "social_profile_to_entities"
    display_name = "Social Profile to Entities"
    description = "Fetches a public social profile URL from a SocialMedia entity and extracts observed identifiers"
    input_types = [EntityType.SOCIAL_MEDIA]
    output_types = [EntityType.PERSON, EntityType.USERNAME, EntityType.EMAIL_ADDRESS, EntityType.URL, EntityType.DOMAIN]
    category = "Social Media"
    settings = [
        TransformSetting(name="timeout_seconds", display_name="Timeout Seconds", description="Per-request timeout for fetching the social profile page", default="15", field_type="integer", min_value=3, max_value=60),
        TransformSetting(name="max_results", display_name="Max Results", description="Maximum extracted identifiers to return", default="30", field_type="integer", min_value=1, max_value=200),
        TransformSetting(name="max_content_chars", display_name="Max Content Chars", description="Maximum HTML/text characters to inspect during extraction", default="40000", field_type="integer", min_value=1000, max_value=200000),
        TransformSetting(name="same_host_links_only", display_name="Same Host Links Only", description="Restrict extracted links to the same host as the input profile URL", default="false", field_type="boolean"),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        source_url = self._resolve_profile_url(entity)
        if not source_url:
            return TransformResult(messages=["SocialMedia entity did not contain a usable profile URL.", "Set properties.profile_url or properties.url, or use a URL-valued SocialMedia entity."])

        timeout_seconds = self.parse_int_setting(config.settings.get("timeout_seconds", "15"), setting_name="timeout_seconds", default=15, min_value=3, declared_max=60)
        max_results = self.parse_int_setting(config.settings.get("max_results", "30"), setting_name="max_results", default=30, min_value=1, declared_max=200)
        max_content_chars = self.parse_int_setting(config.settings.get("max_content_chars", "40000"), setting_name="max_content_chars", default=40000, min_value=1000, declared_max=200000)
        same_host_links_only = self._parse_bool(config.settings.get("same_host_links_only", "false"), default=False)

        try:
            html, resolved_url = await self._fetch(source_url, timeout_seconds=timeout_seconds)
        except Exception as exc:
            return TransformResult(messages=[f"Failed to fetch social profile URL: {exc}"])

        html = html[:max_content_chars]
        entities, edges, messages = self._extract_entities(source_entity=entity, source_url=resolved_url, html=html, max_results=max_results, same_host_links_only=same_host_links_only)
        messages.insert(0, f"Fetched social profile page: {resolved_url}")
        return TransformResult(entities=entities, edges=edges, messages=messages)

    @staticmethod
    def _resolve_profile_url(entity: Entity) -> str:
        candidates = [str(entity.properties.get("profile_url") or "").strip(), str(entity.properties.get("url") or "").strip(), entity.value.strip()]
        for candidate in candidates:
            if SocialProfileToEntities._is_supported_url(candidate):
                return candidate
        return ""

    async def _fetch(self, url: str, *, timeout_seconds: int) -> tuple[str, str]:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_seconds), follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text or "", str(response.url)

    def _extract_entities(self, *, source_entity: Entity, source_url: str, html: str, max_results: int, same_host_links_only: bool) -> tuple[list[Entity], list[Edge], list[str]]:
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []
        seen: set[tuple[str, str]] = set()
        parsed_source = urlparse(source_url)
        source_host = (parsed_source.hostname or "").lower()
        links = self._extract_links(html, source_url)
        text = self._html_to_text(html)

        username_from_url = self._extract_username_from_path(parsed_source.path or "")
        if username_from_url:
            self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.USERNAME, value=username_from_url, label="observed username", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "profile_url"})

        person_name = self._extract_person_name(html)
        if person_name:
            self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.PERSON, value=person_name, label="possible profile name", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "page_title"})

        for email in sorted(set(EMAIL_RE.findall(text))):
            self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.EMAIL_ADDRESS, value=email, label="observed email", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "page_content"})
            if len(entities) >= max_results:
                break

        for username in self._extract_usernames(source_url, links):
            self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.USERNAME, value=username, label="observed username", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "profile_page"})
            if len(entities) >= max_results:
                break

        for link in links:
            host = (urlparse(link).hostname or "").lower()
            if same_host_links_only and host and host != source_host:
                continue
            self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.URL, value=link, label="observed link", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "profile_link"})
            if host and host != source_host:
                self._append_entity(entities, edges, seen, source_entity=source_entity, entity_type=EntityType.DOMAIN, value=host, label="links to domain", source_name=self.name, properties={"observed_on_url": source_url, "observation_type": "linked_domain"})
            if len(entities) >= max_results:
                break

        messages.append(f"Extracted {len(entities)} identifier entities from the social profile page.")
        if not entities:
            messages.append("No identifiers extracted from the fetched social profile page.")
        return entities[:max_results], edges, messages

    @staticmethod
    def _append_entity(entities: list[Entity], edges: list[Edge], seen: set[tuple[str, str]], *, source_entity: Entity, entity_type: EntityType, value: str, label: str, source_name: str, properties: dict[str, str]) -> None:
        cleaned = value.strip()
        if not cleaned:
            return
        key = (entity_type.value, cleaned.lower())
        if key in seen:
            return
        seen.add(key)
        new_entity = Entity(type=entity_type, value=cleaned, properties=properties, source=source_name)
        entities.append(new_entity)
        edges.append(Edge(source_id=source_entity.id, target_id=new_entity.id, label=label, source_transform=source_name))

    @classmethod
    def _extract_person_name(cls, html: str) -> str:
        for pattern in (META_RE, TITLE_RE):
            match = pattern.search(html)
            if not match:
                continue
            raw = cls._clean_text(match.group(1))
            candidate = re.split(r"\s+[|\-·•]\s+", raw, maxsplit=1)[0].strip()
            candidate = re.sub(r"(?i)(?:'s)?\s+profile$", "", candidate).strip()
            if cls._looks_like_person_name(candidate):
                return candidate
        return ""

    @classmethod
    def _extract_usernames(cls, source_url: str, links: list[str]) -> list[str]:
        candidates: set[str] = set()
        source_candidate = cls._extract_username_from_path(urlparse(source_url).path or "")
        if source_candidate:
            candidates.add(source_candidate)
        for link in links[:50]:
            candidate = cls._extract_username_from_path(urlparse(link).path or "")
            if candidate:
                candidates.add(candidate)
        return sorted(candidate for candidate in candidates if cls._looks_like_username(candidate))

    @classmethod
    def _extract_links(cls, html: str, base_url: str) -> list[str]:
        links: list[str] = []
        canonical = CANONICAL_RE.search(html)
        if canonical:
            absolute = urljoin(base_url, cls._clean_attr(canonical.group(1)))
            if cls._is_supported_url(absolute):
                links.append(absolute)
        for match in HREF_RE.finditer(html):
            raw = cls._clean_attr(match.group(1) or match.group(2) or match.group(3) or "")
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            if cls._is_supported_url(absolute) and cls._looks_like_profile_or_bio_link(absolute, base_url):
                links.append(absolute)
        deduped: list[str] = []
        seen_links: set[str] = set()
        for link in links:
            normalized = link.strip()
            if normalized.lower() in seen_links:
                continue
            seen_links.add(normalized.lower())
            deduped.append(normalized)
        return deduped

    @staticmethod
    def _html_to_text(html: str) -> str:
        no_tags = TAG_RE.sub(" ", html)
        return WHITESPACE_RE.sub(" ", unescape(no_tags)).strip()

    @staticmethod
    def _clean_text(value: str) -> str:
        return WHITESPACE_RE.sub(" ", unescape(TAG_RE.sub(" ", value))).strip()

    @staticmethod
    def _clean_attr(value: str) -> str:
        return unescape(value).strip()

    @classmethod
    def _extract_username_from_path(cls, path: str) -> str:
        for pattern in PROFILE_PATH_PATTERNS:
            match = pattern.match(path or "")
            if match:
                return match.group(1)
        return ""

    @classmethod
    def _looks_like_profile_or_bio_link(cls, url: str, base_url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        lower_path = (parsed.path or "").lower()
        if not lower_path or lower_path == "/":
            return False
        if lower_path.endswith(ASSET_EXTENSIONS):
            return False
        if any(part in lower_path for part in ("/css/", "/img/", "/images/", "/static/", "/assets/", "/opensearch/", "/manifest")):
            return False
        if cls._extract_username_from_path(parsed.path or ""):
            return True
        return parsed.hostname.lower() != (urlparse(base_url).hostname or "").lower()

    @staticmethod
    def _looks_like_person_name(value: str) -> bool:
        parts = [part for part in re.split(r"\s+", value.strip()) if part]
        if len(parts) < 2 or len(parts) > 5:
            return False
        if any(len(part) < 2 for part in parts):
            return False
        return all(re.fullmatch(r"[A-Za-z][A-Za-z'.-]*", part) for part in parts)

    @staticmethod
    def _looks_like_username(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9._-]{2,32}", value))

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

    @staticmethod
    def _is_supported_url(url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)