from __future__ import annotations

import importlib.resources
import logging
import re
from typing import Any

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


class UsernameMaigret(BaseTransform):
    name = "username_maigret"
    display_name = "Username OSINT (Maigret)"
    description = "Finds claimed usernames across many supported sites using the Maigret Python library"
    input_types = [EntityType.SOCIAL_MEDIA, EntityType.PERSON, EntityType.USERNAME]
    output_types = [EntityType.SOCIAL_MEDIA, EntityType.URL]
    category = "Social Media"
    settings = [
        TransformSetting(
            name="top_sites",
            display_name="Top Sites",
            description="Maximum number of ranked Maigret sites to query",
            default="200",
            field_type="integer",
            min_value=10,
            max_value=500,
        ),
        TransformSetting(
            name="include_disabled_sites",
            display_name="Include Disabled Sites",
            description="Include sites that Maigret marks as disabled",
            default="false",
            field_type="boolean",
        ),
        TransformSetting(
            name="parse_profile_data",
            display_name="Parse Profile Data",
            description="Enable Maigret profile-page parsing for additional identifiers when available",
            default="false",
            field_type="boolean",
        ),
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of claimed accounts to return",
            default="100",
            field_type="integer",
            min_value=1,
            max_value=500,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        username = self._normalize_input(entity)
        if not username:
            return TransformResult(
                messages=[
                    "Input value did not contain a usable username candidate.",
                    "Prefer feeding this transform from person_to_usernames or a known handle.",
                ]
            )

        top_sites = self._parse_bounded_int(
            config.settings.get("top_sites", "200"),
            default=200,
            min_value=10,
            max_value=500,
        )
        include_disabled_sites = self._parse_bool(
            config.settings.get("include_disabled_sites", "false"),
            default=False,
        )
        parse_profile_data = self._parse_bool(
            config.settings.get("parse_profile_data", "false"),
            default=False,
        )
        max_results = self._parse_bounded_int(
            config.settings.get("max_results", "100"),
            default=100,
            min_value=1,
            max_value=500,
        )

        messages = [f"Scanning username '{username}' with Maigret across up to {top_sites} ranked sites."]
        try:
            raw_results = await self._scan_username(
                username,
                top_sites=top_sites,
                include_disabled_sites=include_disabled_sites,
                parse_profile_data=parse_profile_data,
            )
        except Exception as exc:
            return TransformResult(
                messages=[
                    f"Maigret scan failed: {exc}",
                    "Ensure dependency is installed: maigret==0.5.0",
                ]
            )

        entities: list[Entity] = []
        edges: list[Edge] = []
        seen_profiles: set[tuple[str, str]] = set()
        found_count = 0
        error_count = 0

        for row in raw_results:
            status = str(row.get("status", "")).strip().lower()
            if status != "claimed":
                if status == "unknown":
                    error_count += 1
                continue

            platform = str(row.get("site_name", "")).strip() or "Unknown"
            profile_url = str(row.get("url", "")).strip()
            account_name = str(row.get("username", "")).strip() or username
            ids = row.get("ids", {})
            tags = row.get("tags", [])
            context = str(row.get("context", "")).strip()

            dedupe_key = (platform.lower(), (profile_url or account_name).lower())
            if dedupe_key in seen_profiles:
                continue
            seen_profiles.add(dedupe_key)

            social_entity = Entity(
                type=EntityType.SOCIAL_MEDIA,
                value=f"{account_name}@{platform}",
                properties={
                    "platform": platform,
                    "username": account_name,
                    "profile_url": profile_url,
                    "ids": ids if isinstance(ids, dict) else {},
                    "tags": tags if isinstance(tags, list) else [],
                    "status": row.get("status", ""),
                    "context": context,
                    "tool": "maigret",
                },
                source=self.name,
            )
            entities.append(social_entity)
            edges.append(
                Edge(
                    source_id=entity.id,
                    target_id=social_entity.id,
                    label="has account",
                    source_transform=self.name,
                )
            )

            if profile_url:
                url_entity = Entity(
                    type=EntityType.URL,
                    value=profile_url,
                    properties={
                        "platform": platform,
                        "username": account_name,
                        "tool": "maigret",
                    },
                    source=self.name,
                )
                entities.append(url_entity)
                edges.append(
                    Edge(
                        source_id=social_entity.id,
                        target_id=url_entity.id,
                        label="profile URL",
                        source_transform=self.name,
                    )
                )

            found_count += 1
            if found_count >= max_results:
                break

        messages.append(f"Scan summary: found={found_count}, errors={error_count}.")
        if found_count == 0:
            messages.append("No claimed profiles found.")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _scan_username(
        self,
        username: str,
        *,
        top_sites: int,
        include_disabled_sites: bool,
        parse_profile_data: bool,
    ) -> list[dict[str, Any]]:
        try:
            from maigret.checking import maigret
            from maigret.sites import MaigretDatabase
        except Exception as exc:
            raise RuntimeError(f"Failed to import Maigret library: {exc}") from exc

        logger = logging.getLogger(self.name)
        db = MaigretDatabase().load_from_str(self._load_maigret_db())
        sites = db.ranked_sites_dict(
            top=top_sites,
            disabled=include_disabled_sites,
            id_type="username",
        )

        results = await maigret(
            username=username,
            site_dict=sites,
            logger=logger,
            timeout=30,
            is_parsing_enabled=parse_profile_data,
            id_type="username",
            no_progressbar=True,
            retries=0,
            check_domains=False,
        )

        normalized: list[dict[str, Any]] = []
        for site_name, payload in results.items():
            normalized.append(self._coerce_result(site_name, payload, username))
        return normalized

    @staticmethod
    def _load_maigret_db() -> str:
        try:
            resource = importlib.resources.files("maigret").joinpath("resources/data.json")
            return resource.read_text(encoding="utf-8")
        except Exception as exc:
            raise RuntimeError(f"Failed to load Maigret site database: {exc}") from exc

    @staticmethod
    def _coerce_result(site_name: str, payload: Any, username: str) -> dict[str, Any]:
        if hasattr(payload, "get"):
            status_obj = payload.get("status")
            url = payload.get("url_user", "") or ""
        else:
            status_obj = getattr(payload, "status", None)
            url = getattr(payload, "url_user", "") or ""

        ids_data = getattr(status_obj, "ids_data", None) if status_obj is not None else None
        if ids_data is None and hasattr(payload, "get"):
            ids_data = payload.get("ids", {})

        tags = getattr(status_obj, "tags", None) if status_obj is not None else None
        if tags is None and hasattr(payload, "get"):
            tags = payload.get("tags", [])

        context = getattr(status_obj, "context", None) if status_obj is not None else None
        error = getattr(status_obj, "error", None) if status_obj is not None else None

        return {
            "site_name": site_name,
            "username": username,
            "url": str(url or ""),
            "status": str(getattr(status_obj, "status", status_obj) or ""),
            "ids": ids_data if isinstance(ids_data, dict) else {},
            "tags": tags if isinstance(tags, list) else [],
            "context": str(context or error or ""),
        }

    @staticmethod
    def _normalize_input(entity: Entity) -> str:
        raw = str(entity.value or "").strip()
        if not raw:
            return ""

        if entity.type == EntityType.SOCIAL_MEDIA and "@" in raw:
            candidate = raw.split("@", 1)[0].strip()
            return candidate if USERNAME_RE.fullmatch(candidate) else ""

        if entity.type == EntityType.PERSON:
            candidate = raw.lower().replace(" ", "")
            return candidate if USERNAME_RE.fullmatch(candidate) else ""

        return raw if USERNAME_RE.fullmatch(raw) else ""

    @staticmethod
    def _parse_bool(raw: str, default: bool) -> bool:
        if raw is None:
            return default
        value = str(raw).strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        return default

    @staticmethod
    def _parse_bounded_int(raw: str, default: int, min_value: int, max_value: int) -> int:
        try:
            parsed = int(str(raw).strip())
        except Exception:
            return default
        return max(min_value, min(max_value, parsed))
