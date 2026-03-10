from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}$")


def _slug_token(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", ascii_only.lower())


def _coerce_name_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


def _coerce_string_list(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    return []


class PersonToEmails(BaseTransform):
    name = "person_to_emails"
    display_name = "Person to Emails"
    description = "Generates likely email addresses for a person using known domains and clearly distinguishes observed versus inferred candidates"
    input_types = [EntityType.PERSON]
    output_types = [EntityType.EMAIL_ADDRESS]
    category = "Email"
    settings = [
        TransformSetting(name="max_results", display_name="Max Results", description="Maximum observed and inferred email candidates to return", default="20", field_type="integer", min_value=1, max_value=200),
        TransformSetting(name="include_observed_emails", display_name="Include Observed Emails", description="Include emails already present in the person entity properties", default="true", field_type="boolean"),
        TransformSetting(name="include_inferred_emails", display_name="Include Inferred Emails", description="Infer likely email formats from the person's name and known domains", default="true", field_type="boolean"),
        TransformSetting(name="max_domains", display_name="Max Domains", description="Maximum number of candidate domains to use for inference", default="5", field_type="integer", min_value=1, max_value=50),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        max_results = self.parse_int_setting(config.settings.get("max_results", "20"), setting_name="max_results", default=20, min_value=1, declared_max=200)
        include_observed = self._parse_bool(config.settings.get("include_observed_emails", "true"), default=True)
        include_inferred = self._parse_bool(config.settings.get("include_inferred_emails", "true"), default=True)
        max_domains = self.parse_int_setting(config.settings.get("max_domains", "5"), setting_name="max_domains", default=5, min_value=1, declared_max=50)

        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []
        seen: set[str] = set()

        if include_observed:
            observed = self._observed_emails(entity)
            for email, confidence, rationale in observed:
                if email.lower() in seen:
                    continue
                seen.add(email.lower())
                email_entity = Entity(
                    type=EntityType.EMAIL_ADDRESS,
                    value=email,
                    properties={
                        "confidence": round(confidence, 2),
                        "evidence_type": "observed",
                        "observed": True,
                        "inferred": False,
                        "rationale": rationale,
                    },
                    source=self.name,
                )
                entities.append(email_entity)
                edges.append(Edge(source_id=entity.id, target_id=email_entity.id, label="observed email", source_transform=self.name))
                if len(entities) >= max_results:
                    break
            if observed:
                messages.append(f"Included {min(len(observed), len(entities))} observed email candidates from person properties.")

        if len(entities) >= max_results:
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if include_inferred:
            domains = self._candidate_domains(entity)[:max_domains]
            if not domains:
                messages.append("No known domains found on the person entity, so no inferred emails were generated.")
            else:
                inferred = self._infer_emails(entity, domains)
                added = 0
                for email, confidence, rationale in inferred:
                    if email.lower() in seen:
                        continue
                    seen.add(email.lower())
                    email_entity = Entity(
                        type=EntityType.EMAIL_ADDRESS,
                        value=email,
                        properties={
                            "confidence": round(confidence, 2),
                            "evidence_type": "inferred",
                            "observed": False,
                            "inferred": True,
                            "rationale": rationale,
                            "corroborated": False,
                        },
                        source=self.name,
                    )
                    entities.append(email_entity)
                    edges.append(Edge(source_id=entity.id, target_id=email_entity.id, label="possible email", source_transform=self.name))
                    added += 1
                    if len(entities) >= max_results:
                        break
                if domains:
                    messages.append(f"Generated {added} inferred email candidates across {len(domains)} known domain(s).")

        if not entities:
            messages.append("Not enough person and domain data to derive email candidates.")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _observed_emails(self, entity: Entity) -> list[tuple[str, float, str]]:
        props = entity.properties or {}
        values: list[str] = []
        for key in ("emails", "observed_emails", "email", "primary_email"):
            values.extend(_coerce_string_list(props.get(key)))
        text_sources = [entity.value]
        for key in ("bio", "description", "notes"):
            raw = props.get(key)
            if isinstance(raw, str):
                text_sources.append(raw)
        values.extend(match.group(0) for text in text_sources for match in EMAIL_RE.finditer(text))

        seen: set[str] = set()
        results: list[tuple[str, float, str]] = []
        for raw in values:
            email = raw.strip().lower()
            if not email or email in seen or not EMAIL_RE.fullmatch(email):
                continue
            seen.add(email)
            results.append((email, 0.95, "observed_in_person_properties"))
        return results

    def _candidate_domains(self, entity: Entity) -> list[str]:
        props = entity.properties or {}
        raw_domains: list[str] = []
        for key in ("domains", "email_domains", "employer_domain", "employer_domains", "organization_domain", "organization_domains"):
            raw_domains.extend(_coerce_string_list(props.get(key)))
        for key in ("website", "websites", "profile_url", "profile_urls", "links"):
            for value in _coerce_string_list(props.get(key)):
                parsed = urlparse(value)
                if parsed.hostname:
                    raw_domains.append(parsed.hostname)
                else:
                    raw_domains.append(value)

        deduped: list[str] = []
        seen: set[str] = set()
        for raw in raw_domains:
            domain = raw.strip().lower()
            if domain.startswith("www."):
                domain = domain[4:]
            if domain.endswith("."):
                domain = domain[:-1]
            if not DOMAIN_RE.fullmatch(domain) or domain in seen:
                continue
            seen.add(domain)
            deduped.append(domain)
        return deduped

    def _candidate_names(self, entity: Entity) -> list[tuple[str, str]]:
        props = entity.properties or {}
        candidates: list[tuple[str, str]] = []
        first_name = str(props.get("first_name", "")).strip()
        last_name = str(props.get("last_name", "")).strip()
        display_name = str(props.get("display_name", "")).strip()
        aliases = _coerce_name_list(props.get("aliases"))
        if entity.value.strip():
            candidates.append((entity.value.strip(), "entity_value"))
        if display_name:
            candidates.append((display_name, "display_name"))
        if first_name and last_name:
            candidates.append((f"{first_name} {last_name}", "first_last_name"))
        candidates.extend((alias.strip(), "alias") for alias in aliases if alias.strip())
        return candidates

    def _infer_emails(self, entity: Entity, domains: list[str]) -> list[tuple[str, float, str]]:
        generated: dict[str, tuple[float, str]] = {}
        for raw_name, source in self._candidate_names(entity):
            for local_part, confidence, pattern_name in self._generate_local_parts(raw_name):
                for domain in domains:
                    email = f"{local_part}@{domain}"
                    rationale = f"inferred_from_name_pattern:{pattern_name};name_source={source};domain={domain}"
                    existing = generated.get(email)
                    if existing is None or confidence > existing[0]:
                        generated[email] = (confidence, rationale)
        return [
            (email, confidence, rationale)
            for email, (confidence, rationale) in sorted(generated.items(), key=lambda item: (-item[1][0], item[0]))
        ]

    def _generate_local_parts(self, candidate_name: str) -> list[tuple[str, float, str]]:
        parts = [part for part in re.split(r"[\s._-]+", candidate_name.strip()) if part]
        if not parts:
            return []

        base_tokens = [_slug_token(part) for part in parts]
        base_tokens = [token for token in base_tokens if token]
        if not base_tokens:
            return []
        if len(base_tokens) == 1:
            token = base_tokens[0]
            if len(token) >= 3:
                return [(token, 0.38, "single_name")]
            return []

        first = base_tokens[0]
        last = base_tokens[-1]
        middle_initial = base_tokens[1][0:1] if len(base_tokens) > 2 and base_tokens[1] else ""
        patterns = [
            (f"{first}.{last}", 0.72, "first.last"),
            (f"{first}{last}", 0.68, "firstlast"),
            (f"{first[0]}{last}", 0.66, "flast"),
            (f"{first}{last[0]}", 0.6, "firstl"),
            (f"{first}_{last}", 0.58, "first_last"),
            (f"{first}-{last}", 0.54, "first-last"),
            (f"{first[0]}_{last}", 0.56, "f_last"),
            (f"{first[0]}-{last}", 0.54, "f-last"),
            (f"{first[0]}{last[0]}", 0.5, "fl"),
            (f"{first[0]}.{last}", 0.52, "f.last"),
            (f"{first}.{last[0]}", 0.5, "first.l"),
        ]
        if middle_initial:
            patterns.append((f"{first[0]}{middle_initial}{last}", 0.57, "fmlast"))

        deduped: list[tuple[str, float, str]] = []
        seen: set[str] = set()
        for local_part, confidence, label in patterns:
            if len(local_part) < 3 or local_part in seen:
                continue
            seen.add(local_part)
            deduped.append((local_part, confidence, label))
        return deduped

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
