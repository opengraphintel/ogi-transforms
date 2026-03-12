from __future__ import annotations

import re
from typing import Any

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

PHONE_PATTERN = re.compile(
    r"(?:(?<=\s)|(?<=^)|(?<=[(:]))"
    r"(\+?\d[\d\s()./-]{5,}\d)"
    r"(?=(?:\s|$|[),.;:]))"
)
EXTENSION_PATTERN = re.compile(r"(?i)(?:ext\.?|extension|x)\s*\d{1,6}$")
WHITESPACE_RE = re.compile(r"\s+")


def _normalize_space(value: str) -> str:
    return WHITESPACE_RE.sub(" ", value).strip()


class DocumentToPhoneNumbers(BaseTransform):
    name = "document_to_phone_numbers"
    display_name = "Document to Phone Numbers"
    description = "Extracts observed phone numbers from document content, normalizes them when possible, and preserves source context"
    input_types = [EntityType.DOCUMENT]
    output_types = [EntityType.PHONE_NUMBER]
    category = "Web"
    settings = [
        TransformSetting(name="default_region", display_name="Default Region", description="Default region used when parsing numbers without an international prefix", default="US", field_type="string", pattern="^[A-Za-z]{2}$"),
        TransformSetting(name="max_results", display_name="Max Results", description="Maximum number of phone numbers to return", default="20", field_type="integer", min_value=1, max_value=200),
        TransformSetting(name="context_window_chars", display_name="Context Window Chars", description="Character window captured around each phone number for analyst review", default="120", field_type="integer", min_value=40, max_value=500),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        text = self._document_text(entity)
        if not text:
            return TransformResult(messages=["No text content found in document"])

        default_region = str(config.settings.get("default_region", "US") or "US").strip().upper() or "US"
        max_results = self.parse_int_setting(config.settings.get("max_results", "20"), setting_name="max_results", default=20, min_value=1, declared_max=200)
        context_window = self.parse_int_setting(config.settings.get("context_window_chars", "120"), setting_name="context_window_chars", default=120, min_value=40, declared_max=500)

        entities: list[Entity] = []
        edges: list[Edge] = []
        seen: set[str] = set()
        document_url = str((entity.properties or {}).get("url") or "").strip()

        for candidate in self._extract_candidates(text, default_region=default_region, context_window=context_window):
            key = (candidate["normalized"] or candidate["raw_value"]).lower()
            if key in seen:
                continue
            seen.add(key)

            phone_entity = Entity(
                type=EntityType.PHONE_NUMBER,
                value=candidate["normalized"] or candidate["raw_value"],
                properties={
                    "confidence": candidate["confidence"],
                    "raw_value": candidate["raw_value"],
                    "normalized": candidate["normalized"],
                    "context_snippet": candidate["context_snippet"],
                    "observed_in": "document_content",
                    "observed_on_url": document_url,
                    "normalization_method": candidate["normalization_method"],
                },
                source=self.name,
            )
            entities.append(phone_entity)
            edges.append(Edge(source_id=entity.id, target_id=phone_entity.id, label="observed phone", source_transform=self.name))
            if len(entities) >= max_results:
                break

        if not entities:
            return TransformResult(messages=["No phone numbers found in document content"])

        return TransformResult(
            entities=entities,
            edges=edges,
            messages=[f"Extracted {len(entities)} phone number(s) from document content."],
        )

    @staticmethod
    def _document_text(entity: Entity) -> str:
        props = entity.properties or {}
        content = props.get("content")
        if isinstance(content, str) and content.strip():
            return _normalize_space(content)
        return _normalize_space(entity.value or "")

    def _extract_candidates(self, text: str, *, default_region: str, context_window: int) -> list[dict[str, Any]]:
        try:
            import phonenumbers  # type: ignore
        except Exception:
            phonenumbers = None

        matches: list[dict[str, Any]] = []
        seen_ranges: set[tuple[int, int]] = set()

        if phonenumbers is not None:
            for match in phonenumbers.PhoneNumberMatcher(text, default_region):
                number = match.number
                raw_value = text[match.start:match.end]
                if not phonenumbers.is_possible_number(number):
                    continue
                normalized = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
                confidence = 0.93 if phonenumbers.is_valid_number(number) else 0.78
                matches.append({
                    "raw_value": _normalize_space(raw_value),
                    "normalized": normalized,
                    "confidence": round(confidence, 2),
                    "context_snippet": self._context_snippet(text, match.start, match.end, context_window),
                    "normalization_method": "phonenumbers",
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
            confidence = 0.68 if normalized.startswith("+") else 0.55
            matches.append({
                "raw_value": raw_value,
                "normalized": normalized,
                "confidence": round(confidence, 2),
                "context_snippet": self._context_snippet(text, start, end, context_window),
                "normalization_method": "regex_fallback",
                "start": start,
                "end": end,
            })

        matches.sort(key=lambda item: (-float(item["confidence"]), item["normalized"], item["start"]))
        return matches

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
