from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
DEFAULT_USER_AGENT = "OGI Username Maigret Adoption/1.1"


class UsernameMaigret(BaseTransform):
    name = "username_maigret"
    display_name = "Username OSINT (Maigret Adoption)"
    description = "Finds claimed usernames using an OGI-native checker with a vendored Maigret site database"
    input_types = [EntityType.SOCIAL_MEDIA, EntityType.PERSON, EntityType.USERNAME]
    output_types = [EntityType.SOCIAL_MEDIA, EntityType.URL]
    category = "Social Media"
    settings = [
        TransformSetting(
            name="top_sites",
            display_name="Top Sites",
            description="Maximum number of ranked sites from the vendored Maigret database to query",
            default="200",
            field_type="integer",
            min_value=10,
            max_value=1000,
        ),
        TransformSetting(
            name="include_disabled_sites",
            display_name="Include Disabled Sites",
            description="Include sites that the vendored Maigret database marks as disabled",
            default="false",
            field_type="boolean",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="Per-request timeout used by the adoption checker",
            default="15",
            field_type="integer",
            min_value=3,
            max_value=60,
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

        top_sites = self.parse_int_setting(
            config.settings.get("top_sites", "200"),
            setting_name="top_sites",
            default=200,
            min_value=10,
            declared_max=1000,
        )
        include_disabled_sites = self._parse_bool(config.settings.get("include_disabled_sites", "false"), False)
        timeout_seconds = self.parse_int_setting(
            config.settings.get("timeout_seconds", "15"),
            setting_name="timeout_seconds",
            default=15,
            min_value=3,
            declared_max=60,
        )
        max_results = self.parse_int_setting(
            config.settings.get("max_results", "100"),
            setting_name="max_results",
            default=100,
            min_value=1,
            declared_max=500,
        )

        try:
            site_data = self._load_site_data()
            sites = self._ranked_sites(site_data, include_disabled_sites=include_disabled_sites, top_sites=top_sites)
        except Exception as exc:
            return TransformResult(messages=[f"Failed to load vendored Maigret database: {exc}"])

        messages = [f"Scanning username '{username}' against {len(sites)} vendored Maigret sites."]
        try:
            claimed, errors = await self._scan_sites(username, sites, timeout_seconds=timeout_seconds)
        except Exception as exc:
            return TransformResult(messages=[f"Maigret adoption scan failed: {exc}"])

        entities: list[Entity] = []
        edges: list[Edge] = []
        seen_profiles: set[tuple[str, str]] = set()
        found_count = 0

        for row in claimed:
            platform = row["site_name"]
            profile_url = row["url"]
            account_name = row["username"]
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
                    "status": row["status"],
                    "check_type": row["check_type"],
                    "http_status": row["http_status"],
                    "tool": "maigret-adoption",
                    "database_source": "vendored_maigret_data_json",
                    "tags": row["tags"],
                },
                source=self.name,
            )
            entities.append(social_entity)
            edges.append(Edge(source_id=entity.id, target_id=social_entity.id, label="has account", source_transform=self.name))

            if profile_url:
                url_entity = Entity(
                    type=EntityType.URL,
                    value=profile_url,
                    properties={
                        "platform": platform,
                        "username": account_name,
                        "tool": "maigret-adoption",
                    },
                    source=self.name,
                )
                entities.append(url_entity)
                edges.append(Edge(source_id=social_entity.id, target_id=url_entity.id, label="profile URL", source_transform=self.name))

            found_count += 1
            if found_count >= max_results:
                break

        messages.append(f"Scan summary: found={found_count}, errors={errors}.")
        if found_count == 0:
            messages.append("No claimed profiles found.")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _scan_sites(self, username: str, sites: list[dict[str, Any]], *, timeout_seconds: int) -> tuple[list[dict[str, Any]], int]:
        claimed: list[dict[str, Any]] = []
        errors = 0
        timeout = httpx.Timeout(timeout_seconds)
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, limits=limits) as client:
            for site in sites:
                result = await self._check_site(client, site, username)
                if result["status"] == "Unknown":
                    errors += 1
                elif result["status"] == "Claimed":
                    claimed.append(result)
        return claimed, errors

    async def _check_site(self, client: httpx.AsyncClient, site: dict[str, Any], username: str) -> dict[str, Any]:
        rendered = self._render_site_urls(site, username)
        if not rendered:
            return {"site_name": site["name"], "username": username, "url": "", "status": "Unknown", "check_type": site.get("check_type", ""), "http_status": 0, "tags": site.get("tags", [])}

        profile_url, probe_url = rendered
        method = "HEAD" if site.get("check_type") == "status_code" and site.get("request_head_only") else "GET"
        headers = {"User-Agent": DEFAULT_USER_AGENT, "Connection": "close"}
        headers.update(site.get("headers", {}))

        try:
            response = await client.request(
                method,
                probe_url,
                headers=headers,
                follow_redirects=(site.get("check_type") != "response_url"),
            )
            html = response.text if method == "GET" else ""
            status = self._evaluate_site(site, response.status_code, html)
            return {
                "site_name": site["name"],
                "username": username,
                "url": profile_url,
                "status": status,
                "check_type": site.get("check_type", "message"),
                "http_status": response.status_code,
                "tags": site.get("tags", []),
            }
        except Exception:
            return {
                "site_name": site["name"],
                "username": username,
                "url": profile_url,
                "status": "Unknown",
                "check_type": site.get("check_type", "message"),
                "http_status": 0,
                "tags": site.get("tags", []),
            }

    @staticmethod
    def _evaluate_site(site: dict[str, Any], status_code: int, html: str) -> str:
        check_type = site.get("check_type", "message")
        presence = site.get("presence_strs", [])
        absence = site.get("absence_strs", [])
        has_presence = (not presence) or any(flag in html for flag in presence)
        has_absence = any(flag in html for flag in absence)

        if check_type == "message":
            return "Claimed" if has_presence and not has_absence else "Available"
        if check_type == "status_code":
            return "Claimed" if 200 <= status_code < 300 else "Available"
        if check_type == "response_url":
            return "Claimed" if 200 <= status_code < 300 and has_presence else "Available"
        return "Unknown"

    @staticmethod
    def _render_site_urls(site: dict[str, Any], username: str) -> tuple[str, str] | None:
        url_template = site.get("url")
        url_main = site.get("url_main")
        if not url_template or not url_main:
            return None

        url_subpath = site.get("url_subpath", "")
        quoted = quote(username)
        profile_url = url_template.format(urlMain=url_main, urlSubpath=url_subpath, username=quoted)
        profile_url = re.sub(r"(?<!:)/+", "/", profile_url)
        probe_template = site.get("url_probe") or profile_url
        probe_url = probe_template.format(urlMain=url_main, urlSubpath=url_subpath, username=quoted)
        for key, value in site.get("get_params", {}).items():
            probe_url += f"&{key}={value}"
        return profile_url, probe_url

    @classmethod
    def _ranked_sites(cls, data: dict[str, Any], *, include_disabled_sites: bool, top_sites: int) -> list[dict[str, Any]]:
        engines = data.get("engines", {})
        ranked: list[dict[str, Any]] = []
        for name, raw_site in data.get("sites", {}).items():
            site = cls._normalize_site(name, raw_site, engines)
            if site.get("type") != "username":
                continue
            if site.get("disabled") and not include_disabled_sites:
                continue
            if not site.get("url"):
                continue
            ranked.append(site)
        ranked.sort(key=lambda item: item.get("alexa_rank", 2**31 - 1))
        return ranked[:top_sites]

    @classmethod
    def _normalize_site(cls, name: str, raw_site: dict[str, Any], engines: dict[str, Any]) -> dict[str, Any]:
        site = cls._camel_to_snake_obj(raw_site)
        engine_name = site.get("engine")
        if isinstance(engine_name, str) and engine_name in engines:
            engine = cls._camel_to_snake_obj(engines[engine_name])
            site = cls._merge_site(engine, site)
        site["name"] = name
        site.setdefault("type", "username")
        site.setdefault("tags", [])
        site.setdefault("headers", {})
        site.setdefault("errors", {})
        site.setdefault("get_params", {})
        site.setdefault("presence_strs", [])
        site.setdefault("absence_strs", [])
        site.setdefault("check_type", "message")
        site.setdefault("disabled", False)
        site.setdefault("request_head_only", False)
        site.setdefault("alexa_rank", 2**31 - 1)
        return site

    @classmethod
    def _merge_site(cls, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            elif isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = [*merged[key], *value]
            else:
                merged[key] = value
        return merged

    @staticmethod
    def _camel_to_snake_obj(value: Any) -> Any:
        if isinstance(value, dict):
            return {UsernameMaigret._camel_to_snake(key): UsernameMaigret._camel_to_snake_obj(val) for key, val in value.items()}
        if isinstance(value, list):
            return [UsernameMaigret._camel_to_snake_obj(item) for item in value]
        return value

    @staticmethod
    def _camel_to_snake(value: str) -> str:
        result = []
        for index, char in enumerate(value):
            if char.isupper() and index > 0 and value[index - 1] != "_":
                result.append("_")
            result.append(char.lower())
        return "".join(result)

    @staticmethod
    def _load_site_data() -> dict[str, Any]:
        resource = Path(__file__).resolve().parent.parent / "resources" / "data.json"
        return json.loads(resource.read_text(encoding="utf-8"))

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
