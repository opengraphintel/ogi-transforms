from __future__ import annotations

import re
from typing import Any

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

FOUND_STATUSES = {"found", "registered", "exists"}
VALID_SCOPES = {"all", "social", "dev", "creator", "community", "gaming"}


class UsernameUserScanner(BaseTransform):
    name = "username_user_scanner"
    display_name = "Username OSINT (user-scanner)"
    description = "Finds username presence across many platforms using the user-scanner library"
    input_types = [EntityType.SOCIAL_MEDIA, EntityType.PERSON]
    output_types = [EntityType.SOCIAL_MEDIA, EntityType.URL]
    category = "Social Media"
    settings = [
        TransformSetting(
            name="scan_scope",
            display_name="Scan Scope",
            description="Category to scan. 'all' scans all user_scan categories.",
            default="all",
            field_type="select",
            options=["all", "social", "dev", "creator", "community", "gaming"],
        ),
        TransformSetting(
            name="only_found",
            display_name="Only Found",
            description="Only include found platforms in output entities",
            default="true",
            field_type="boolean",
        ),
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of found accounts to return",
            default="100",
            field_type="integer",
            min_value=1,
            max_value=500,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        username = self._normalize_username(entity.value)
        if not username:
            return TransformResult(messages=["Input value did not contain a usable username."])

        scope = self._normalize_scope(config.settings.get("scan_scope", "all"))
        only_found = self._parse_bool(config.settings.get("only_found", "true"), default=True)
        max_results = self._parse_bounded_int(config.settings.get("max_results", "100"), default=100, min_value=1, max_value=500)

        messages: list[str] = [f"Scanning username '{username}' with scope '{scope}'."]
        try:
            raw_results = await self._scan_username(username, scope)
        except Exception as exc:
            return TransformResult(
                messages=[
                    f"Username scan failed: {exc}",
                    "Ensure dependency is installed: user-scanner>=1.3.3",
                ]
            )

        normalized: list[dict[str, str]] = []
        for item in raw_results:
            parsed = self._coerce_result(item, username)
            if parsed is not None:
                normalized.append(parsed)

        entities: list[Entity] = []
        edges: list[Edge] = []
        found_count = 0
        not_found_count = 0
        error_count = 0

        seen_profiles: set[tuple[str, str]] = set()

        for row in normalized:
            status_raw = row.get("status", "")
            status = status_raw.strip().lower()
            is_found = status in FOUND_STATUSES
            platform = row.get("site_name", "").strip() or "Unknown"
            profile_url = row.get("url", "").strip()
            category = row.get("category", "").strip()
            reason = row.get("reason", "").strip()

            if not is_found:
                if status == "error":
                    error_count += 1
                    messages.append(f"{platform}: error ({reason or 'unknown'})")
                else:
                    not_found_count += 1
                    if not only_found:
                        messages.append(f"{platform}: not found")
                continue

            if found_count >= max_results:
                break

            dedupe_key = (platform.lower(), profile_url.lower())
            if dedupe_key in seen_profiles:
                continue
            seen_profiles.add(dedupe_key)

            social_entity = Entity(
                type=EntityType.SOCIAL_MEDIA,
                value=f"{username}@{platform}",
                properties={
                    "platform": platform,
                    "username": username,
                    "profile_url": profile_url,
                    "status": status_raw,
                    "category": category,
                    "reason": reason,
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
                        "username": username,
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

        messages.append(
            f"Scan summary: found={found_count}, not_found={not_found_count}, errors={error_count}."
        )

        if found_count == 0:
            messages.append("No matching profiles found.")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _scan_username(self, username: str, scope: str) -> list[Any]:
        try:
            from user_scanner.core import engine
        except Exception as exc:
            raise RuntimeError(f"Failed to import user-scanner library: {exc}") from exc

        if scope == "all":
            results = await engine.check_all(username, is_email=False)
        else:
            results = await engine.check_category(scope, username, is_email=False)

        if results is None:
            return []
        if isinstance(results, list):
            return results
        return list(results)

    @staticmethod
    def _coerce_result(item: Any, username: str) -> dict[str, str] | None:
        data: dict[str, Any]
        if isinstance(item, dict):
            data = item
        elif hasattr(item, "as_dict") and callable(item.as_dict):
            try:
                data = item.as_dict()
            except Exception:
                return None
        else:
            data = {
                "username": getattr(item, "username", username),
                "category": getattr(item, "category", ""),
                "site_name": getattr(item, "site_name", ""),
                "status": getattr(item, "status", ""),
                "url": getattr(item, "url", ""),
                "reason": getattr(item, "reason", ""),
            }

        return {
            "username": str(data.get("username", username) or username),
            "category": str(data.get("category", "") or ""),
            "site_name": str(data.get("site_name", "") or ""),
            "status": str(data.get("status", "") or ""),
            "url": str(data.get("url", "") or ""),
            "reason": str(data.get("reason", "") or ""),
        }

    @staticmethod
    def _normalize_scope(raw: str) -> str:
        scope = str(raw or "all").strip().lower()
        return scope if scope in VALID_SCOPES else "all"

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
        if parsed < min_value:
            return min_value
        if parsed > max_value:
            return max_value
        return parsed

    @staticmethod
    def _normalize_username(raw: str) -> str:
        value = str(raw or "").strip()
        if not value:
            return ""

        if value.startswith("http://") or value.startswith("https://"):
            parts = value.rstrip("/").split("/")
            value = parts[-1] if parts else value

        if value.startswith("@"):
            value = value[1:]

        if "@" in value and " " not in value and value.count("@") == 1:
            value = value.split("@", 1)[0]

        cleaned = re.sub(r"[^A-Za-z0-9._-]", "", value)
        return cleaned.strip("._-")
