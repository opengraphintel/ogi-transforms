from __future__ import annotations

import html
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

PHONE_PATTERN = re.compile(
    r"(?:(?<=\s)|(?<=^)|(?<=[(:]))"
    r"(\+?\d[\d\s()./-]{5,}\d)"
    r"(?=(?:\s|$|[),.;:]))"
)
EXTENSION_PATTERN = re.compile(r"(?i)(?:ext\.?|extension|x)\s*\d{1,6}$")
TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
GENERIC_CONTACT_HINTS = ("contact", "team", "people", "staff", "directory", "bio", "speaker", "about")
ALLOWED_TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
)
USER_AGENT = "OGI Person Phone Extractor/1.0"


def _normalize_space(value: str) -> str:
    return WHITESPACE_RE.sub(" ", value).strip()


def _coerce_string_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    return []


def _coerce_name_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


class PersonToPhoneNumbers(BaseTransform):
    name = "person_to_phone_numbers"
    display_name = "Person to Phone Numbers"
    description = "Finds public phone numbers associated with a person from attached text, documents, and profile URLs with proximity-based scoring"
    input_types = [EntityType.PERSON]
    output_types = [EntityType.PHONE_NUMBER]
    category = "Web"
    settings = [
        TransformSetting(name="default_region", display_name="Default Region", description="Default region used when parsing numbers without an international prefix", default="US", field_type="string", pattern="^[A-Za-z]{2}$"),
        TransformSetting(name="max_results", display_name="Max Results", description="Maximum number of phone numbers to return", default="15", field_type="integer", min_value=1, max_value=100),
        TransformSetting(name="max_sources", display_name="Max Sources", description="Maximum number of attached URLs or embedded documents to inspect", default="8", field_type="integer", min_value=1, max_value=50),
        TransformSetting(name="context_window_chars", display_name="Context Window Chars", description="Character window captured around each phone number for scoring and analyst review", default="180", field_type="integer", min_value=60, max_value=600),
        TransformSetting(name="name_proximity_chars", display_name="Name Proximity Chars", description="Maximum distance between the person's name and phone number before the match is considered weak", default="220", field_type="integer", min_value=40, max_value=1000),
        TransformSetting(name="min_confidence", display_name="Min Confidence", description="Minimum confidence required to emit a phone number", default="0.6", field_type="number", min_value=0, max_value=1),
        TransformSetting(name="include_generic_contact_pages", display_name="Include Generic Contact Pages", description="Allow URLs with contact-like paths even when the person's name is not in the URL", default="true", field_type="boolean"),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        default_region = str(config.settings.get("default_region", "US") or "US").strip().upper() or "US"
        max_results = self.parse_int_setting(config.settings.get("max_results", "15"), setting_name="max_results", default=15, min_value=1, declared_max=100)
        max_sources = self.parse_int_setting(config.settings.get("max_sources", "8"), setting_name="max_sources", default=8, min_value=1, declared_max=50)
        context_window = self.parse_int_setting(config.settings.get("context_window_chars", "180"), setting_name="context_window_chars", default=180, min_value=60, declared_max=600)
        name_proximity = self.parse_int_setting(config.settings.get("name_proximity_chars", "220"), setting_name="name_proximity_chars", default=220, min_value=40, declared_max=1000)
        min_confidence = self.parse_float_setting(config.settings.get("min_confidence", "0.6"), setting_name="min_confidence", default=0.6, min_value=0, declared_max=1)
        include_generic_contact_pages = self._parse_bool(config.settings.get("include_generic_contact_pages", "true"), default=True)

        sources = await self._collect_sources(entity, max_sources=max_sources, include_generic_contact_pages=include_generic_contact_pages)
        if not sources:
            return TransformResult(messages=["No attached text, documents, or eligible URLs found on the person entity."])

        names = self._candidate_names(entity)
        context_terms = self._context_terms(entity)
        entities: list[Entity] = []
        edges: list[Edge] = []
        seen: set[str] = set()

        matches: list[dict[str, Any]] = []
        for source in sources:
            matches.extend(
                self._extract_from_source(
                    source,
                    names=names,
                    context_terms=context_terms,
                    default_region=default_region,
                    context_window=context_window,
                    name_proximity=name_proximity,
                )
            )

        matches.sort(key=lambda item: (-float(item["confidence"]), item["normalized"], item["source_label"]))

        for match in matches:
            if match["confidence"] < min_confidence:
                continue
            key = match["normalized"].lower()
            if key in seen:
                continue
            seen.add(key)
            phone_entity = Entity(
                type=EntityType.PHONE_NUMBER,
                value=match["normalized"],
                properties={
                    "confidence": round(match["confidence"], 2),
                    "raw_value": match["raw_value"],
                    "normalized": match["normalized"],
                    "context_snippet": match["context_snippet"],
                    "observed_in": match["observed_in"],
                    "observed_on_url": match["observed_on_url"],
                    "source_label": match["source_label"],
                    "name_proximity": match["name_proximity"],
                    "matched_name": match["matched_name"],
                    "rationale": match["rationale"],
                },
                source=self.name,
            )
            entities.append(phone_entity)
            edges.append(Edge(source_id=entity.id, target_id=phone_entity.id, label="possible phone", source_transform=self.name))
            if len(entities) >= max_results:
                break

        if not entities:
            return TransformResult(messages=["No sufficiently corroborated phone numbers were found for the person."])

        fetched_sources = sum(1 for source in sources if source["observed_in"] == "url_content")
        return TransformResult(
            entities=entities,
            edges=edges,
            messages=[
                f"Inspected {len(sources)} source(s) for person-linked phone numbers.",
                f"Fetched {fetched_sources} URL source(s).",
                f"Generated {len(entities)} phone number candidate(s).",
            ],
        )

    async def _collect_sources(self, entity: Entity, *, max_sources: int, include_generic_contact_pages: bool) -> list[dict[str, str]]:
        props = entity.properties or {}
        sources: list[dict[str, str]] = []

        for key in ("bio", "description", "notes"):
            raw = props.get(key)
            if isinstance(raw, str) and raw.strip():
                sources.append({
                    "text": _normalize_space(raw),
                    "observed_in": "person_property",
                    "observed_on_url": "",
                    "source_label": key,
                })

        for item in self._embedded_documents(props):
            sources.append(item)

        for url in self._candidate_urls(entity, include_generic_contact_pages=include_generic_contact_pages):
            if len(sources) >= max_sources:
                break
            try:
                fetched = await self._fetch_url_text(url)
            except Exception:
                continue
            if fetched:
                sources.append({
                    "text": fetched,
                    "observed_in": "url_content",
                    "observed_on_url": url,
                    "source_label": url,
                })

        return sources[:max_sources]

    def _embedded_documents(self, props: dict[str, Any]) -> list[dict[str, str]]:
        sources: list[dict[str, str]] = []
        for key in ("documents", "document", "document_texts"):
            raw = props.get(key)
            if isinstance(raw, dict):
                raw = [raw]
            if not isinstance(raw, list):
                continue
            for item in raw:
                if isinstance(item, str) and item.strip():
                    sources.append({
                        "text": _normalize_space(item),
                        "observed_in": "embedded_document",
                        "observed_on_url": "",
                        "source_label": key,
                    })
                elif isinstance(item, dict):
                    content = item.get("content")
                    if not isinstance(content, str) or not content.strip():
                        continue
                    label = str(item.get("title") or item.get("url") or key).strip()
                    sources.append({
                        "text": _normalize_space(content),
                        "observed_in": "embedded_document",
                        "observed_on_url": str(item.get("url") or "").strip(),
                        "source_label": label or key,
                    })
        return sources

    def _candidate_urls(self, entity: Entity, *, include_generic_contact_pages: bool) -> list[str]:
        props = entity.properties or {}
        raw_urls: list[str] = []
        for key in ("profile_url", "profile_urls", "website", "websites", "links", "document_urls"):
            raw_urls.extend(_coerce_string_list(props.get(key)))

        name_tokens = [token.lower() for name in self._candidate_names(entity) for token in re.split(r"[\s._-]+", name) if len(token) >= 3]
        deduped: list[str] = []
        seen: set[str] = set()
        for raw_url in raw_urls:
            url = raw_url.strip()
            if not self._is_supported_url(url):
                continue
            parsed = urlparse(url)
            path = (parsed.path or "").lower()
            if not include_generic_contact_pages:
                if not any(token in path for token in name_tokens):
                    continue
            else:
                if not any(token in path for token in name_tokens) and not any(hint in path for hint in GENERIC_CONTACT_HINTS):
                    continue
            normalized = url.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(url)
        return deduped

    async def _fetch_url_text(self, url: str) -> str:
        parsed = urlparse(url)
        if self._is_blocked_host(parsed.hostname or ""):
            return ""
        async with httpx.AsyncClient(timeout=httpx.Timeout(15), follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
            response = await client.get(url)
            response.raise_for_status()
            content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
            if content_type and not self._is_allowed_content_type(content_type):
                return ""
            body = response.text or ""
            return self._html_to_text(body) if "html" in content_type or not content_type else _normalize_space(body)

    def _extract_from_source(self, source: dict[str, str], *, names: list[str], context_terms: list[str], default_region: str, context_window: int, name_proximity: int) -> list[dict[str, Any]]:
        text = source["text"]
        matches = []
        for candidate in self._extract_phone_candidates(text, default_region=default_region, context_window=context_window):
            score = candidate["confidence"]
            snippet = candidate["context_snippet"].lower()
            matched_name = ""
            proximity_distance: int | None = None

            for name in names:
                distance = self._distance_to_name(text.lower(), candidate["start"], candidate["end"], name.lower(), max_distance=name_proximity)
                if distance is None:
                    continue
                matched_name = name
                proximity_distance = distance
                score += 0.28 if distance <= max(40, name_proximity // 4) else 0.18
                break

            if any(term in snippet for term in context_terms):
                score += 0.1
            if source["observed_in"] == "url_content":
                score += 0.08
            if source["source_label"].lower().endswith(("/contact", "/team", "/people")):
                score += 0.05
            if not matched_name:
                score -= 0.18

            confidence = max(0.0, min(round(score, 2), 0.97))
            rationale_parts = [f"source={source['observed_in']}"]
            if matched_name:
                rationale_parts.append(f"name_proximity={proximity_distance}")
            if any(term in snippet for term in context_terms):
                rationale_parts.append("context_term_match")

            matches.append({
                "raw_value": candidate["raw_value"],
                "normalized": candidate["normalized"],
                "confidence": confidence,
                "context_snippet": candidate["context_snippet"],
                "observed_in": source["observed_in"],
                "observed_on_url": source["observed_on_url"],
                "source_label": source["source_label"],
                "name_proximity": proximity_distance,
                "matched_name": matched_name,
                "rationale": ";".join(rationale_parts),
            })
        return matches

    def _extract_phone_candidates(self, text: str, *, default_region: str, context_window: int) -> list[dict[str, Any]]:
        try:
            import phonenumbers  # type: ignore
        except Exception:
            phonenumbers = None

        matches: list[dict[str, Any]] = []
        seen_ranges: set[tuple[int, int]] = set()
        if phonenumbers is not None:
            for match in phonenumbers.PhoneNumberMatcher(text, default_region):
                number = match.number
                if not phonenumbers.is_possible_number(number):
                    continue
                normalized = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
                confidence = 0.62 if phonenumbers.is_valid_number(number) else 0.5
                matches.append({
                    "raw_value": _normalize_space(text[match.start:match.end]),
                    "normalized": normalized,
                    "confidence": confidence,
                    "context_snippet": self._context_snippet(text, match.start, match.end, context_window),
                    "start": match.start,
                    "end": match.end,
                })
                seen_ranges.add((match.start, match.end))

        for regex_match in PHONE_PATTERN.finditer(text):
            start, end = regex_match.span(1)
            if any(self._ranges_overlap((start, end), seen_range) for seen_range in seen_ranges):
                continue
            raw_value = _normalize_space(regex_match.group(1))
            normalized = self._normalize_fallback(raw_value, default_region=default_region)
            if not normalized:
                continue
            matches.append({
                "raw_value": raw_value,
                "normalized": normalized,
                "confidence": 0.45 if normalized.startswith("+") else 0.35,
                "context_snippet": self._context_snippet(text, start, end, context_window),
                "start": start,
                "end": end,
            })

        return matches

    def _candidate_names(self, entity: Entity) -> list[str]:
        props = entity.properties or {}
        names: list[str] = []
        if entity.value.strip():
            names.append(entity.value.strip())
        for key in ("display_name",):
            raw = props.get(key)
            if isinstance(raw, str) and raw.strip():
                names.append(raw.strip())
        first_name = str(props.get("first_name", "")).strip()
        last_name = str(props.get("last_name", "")).strip()
        if first_name and last_name:
            names.append(f"{first_name} {last_name}")
        names.extend(alias.strip() for alias in _coerce_name_list(props.get("aliases")) if alias.strip())
        deduped: list[str] = []
        seen: set[str] = set()
        for name in names:
            lowered = name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(name)
        return deduped

    def _context_terms(self, entity: Entity) -> list[str]:
        props = entity.properties or {}
        terms: list[str] = []
        for key in ("title", "role", "organization", "employer", "company"):
            raw = props.get(key)
            if isinstance(raw, str) and raw.strip():
                terms.append(raw.strip().lower())
        return terms

    @staticmethod
    def _distance_to_name(text: str, start: int, end: int, name: str, *, max_distance: int) -> int | None:
        positions = [match.start() for match in re.finditer(re.escape(name), text)]
        if not positions:
            return None
        distances = []
        for pos in positions:
            name_end = pos + len(name)
            if name_end <= start:
                distances.append(start - name_end)
            elif pos >= end:
                distances.append(pos - end)
            else:
                distances.append(0)
        closest = min(distances)
        return closest if closest <= max_distance else None

    @staticmethod
    def _context_snippet(text: str, start: int, end: int, width: int) -> str:
        left = max(0, start - width)
        right = min(len(text), end + width)
        return _normalize_space(text[left:right])

    @staticmethod
    def _ranges_overlap(first: tuple[int, int], second: tuple[int, int]) -> bool:
        return not (first[1] <= second[0] or second[1] <= first[0])

    @staticmethod
    def _normalize_fallback(raw_value: str, *, default_region: str) -> str:
        cleaned = EXTENSION_PATTERN.sub("", raw_value).strip()
        digits = "".join(ch for ch in cleaned if ch.isdigit())
        if len(digits) < 7 or len(digits) > 15:
            return ""
        if cleaned.startswith("+"):
            return f"+{digits}"
        if default_region == "US":
            if len(digits) == 10:
                return f"+1{digits}"
            if len(digits) == 11 and digits.startswith("1"):
                return f"+{digits}"
        return digits

    @staticmethod
    def _html_to_text(raw: str) -> str:
        no_script = re.sub(r"(?is)<script.*?>.*?</script>", " ", raw)
        no_style = re.sub(r"(?is)<style.*?>.*?</style>", " ", no_script)
        no_tags = TAG_RE.sub(" ", no_style)
        return _normalize_space(html.unescape(no_tags))

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

    @staticmethod
    def _is_allowed_content_type(content_type: str) -> bool:
        lower = (content_type or "").lower()
        return any(lower.startswith(prefix) for prefix in ALLOWED_TEXT_CONTENT_TYPES)

    @staticmethod
    def _is_blocked_host(hostname: str) -> bool:
        host = hostname.strip().lower()
        if not host:
            return True
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        except ValueError:
            return False

