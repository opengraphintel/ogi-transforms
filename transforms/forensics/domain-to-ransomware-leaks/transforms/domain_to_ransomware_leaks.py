import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

API_BASE = "https://api-pro.ransomware.live"


class DomainToRansomwareLeaks(BaseTransform):
    name = "domain_to_ransomware_leaks"
    display_name = "Domain to Ransomware Leak Posts"
    description = "Checks whether a domain or organization appears on a ransomware leak site"
    input_types = [EntityType.DOMAIN, EntityType.ORGANIZATION]
    output_types = [
        EntityType.DOCUMENT,
        EntityType.ORGANIZATION,
        EntityType.LOCATION,
        EntityType.URL,
        EntityType.VULNERABILITY,
    ]
    category = "Forensics"
    settings = [
        TransformSetting(
            name="ransomwarelive_api_key",
            display_name="Ransomware.live API Key",
            description="API PRO key for ransomware.live",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for ransomware.live requests",
            default="20",
            field_type="integer",
            min_value=5,
            max_value=60,
        ),
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of leak posts to emit",
            default="25",
            field_type="integer",
            min_value=1,
            max_value=200,
        ),
        TransformSetting(
            name="include_group_intel",
            display_name="Include Group Intelligence",
            description="Fetch leak site URLs and exploited CVEs for each ransomware group found",
            default="true",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        query = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("ransomwarelive_api_key") or "").strip()
        if not api_key:
            messages.append(
                "Ransomware.live API key required. Get a free key at "
                "https://www.ransomware.live/my and configure it under API Keys."
            )
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not query:
            messages.append("Entity value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)
        max_results = self._get_max_results(config)
        include_group_intel = self._get_include_group_intel(config)
        headers = {"accept": "application/json", "X-API-KEY": api_key}

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers) as client:
                response = await client.get(f"{API_BASE}/victims/search", params={"q": query})
                response.raise_for_status()
                payload = response.json()

                victims = self._as_records(payload)
                if not victims:
                    messages.append(f"No ransomware leak posts found for '{query}'")
                    return TransformResult(entities=entities, edges=edges, messages=messages)

                messages.append(f"Leak posts matching '{query}': {len(victims)}")
                victims = victims[:max_results]

                group_entities: dict[str, Entity] = {}
                location_entities: dict[str, Entity] = {}

                for victim in victims:
                    victim_name = self._clean(victim.get("victim"))
                    group_name = self._clean(victim.get("group"))
                    website = self._clean(victim.get("website"))
                    country = self._clean(victim.get("country"))
                    attackdate = self._clean(victim.get("attackdate"))
                    discovered = self._clean(victim.get("discovered"))
                    activity = self._clean(victim.get("activity"))
                    permalink = self._clean(victim.get("permalink"))

                    summary_lines = [
                        f"Victim: {victim_name or '(unnamed)'}",
                        f"Ransomware group: {group_name or 'unknown'}",
                    ]
                    if website:
                        summary_lines.append(f"Website: {website}")
                    if activity:
                        summary_lines.append(f"Sector: {activity}")
                    if country:
                        summary_lines.append(f"Country: {country}")
                    if attackdate:
                        summary_lines.append(f"Attack/publication date: {attackdate}")
                    if discovered:
                        summary_lines.append(f"Discovered by ransomware.live: {discovered}")
                    if permalink:
                        summary_lines.append(f"Permalink: {permalink}")

                    doc_title = f"Ransomware leak post: {victim_name or query}"
                    if group_name:
                        doc_title += f" ({group_name})"

                    doc_entity = Entity(
                        type=EntityType.DOCUMENT,
                        value=doc_title,
                        properties={
                            "content": "\n".join(summary_lines),
                            "victim": victim_name,
                            "ransomware_group": group_name,
                            "victim_website": website,
                            "country": country,
                            "sector": activity,
                            "attack_date": attackdate,
                            "discovered": discovered,
                            "permalink": permalink,
                            "source": "ransomware.live",
                        },
                        source=self.name,
                    )
                    entities.append(doc_entity)
                    edges.append(Edge(
                        source_id=entity.id,
                        target_id=doc_entity.id,
                        label="listed on leak site",
                        source_transform=self.name,
                    ))

                    if group_name:
                        key = group_name.lower()
                        if key not in group_entities:
                            group_entity = Entity(
                                type=EntityType.ORGANIZATION,
                                value=group_name,
                                properties={
                                    "kind": "ransomware_group",
                                    "source": "ransomware.live",
                                },
                                source=self.name,
                            )
                            group_entities[key] = group_entity
                            entities.append(group_entity)
                        edges.append(Edge(
                            source_id=group_entities[key].id,
                            target_id=doc_entity.id,
                            label="published leak post",
                            source_transform=self.name,
                        ))

                    if country:
                        key = country.lower()
                        if key not in location_entities:
                            location_entity = Entity(
                                type=EntityType.LOCATION,
                                value=country,
                                properties={"country": country, "source": "ransomware.live"},
                                source=self.name,
                            )
                            location_entities[key] = location_entity
                            entities.append(location_entity)
                        edges.append(Edge(
                            source_id=doc_entity.id,
                            target_id=location_entities[key].id,
                            label="victim located in",
                            source_transform=self.name,
                        ))

                if include_group_intel:
                    for key, group_entity in group_entities.items():
                        await self._add_group_intel(
                            client, key, group_entity, entities, edges, messages
                        )

                groups_found = sorted(e.value for e in group_entities.values())
                if groups_found:
                    messages.append(f"Groups: {', '.join(groups_found)}")

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status in (401, 403):
                messages.append("Invalid or unauthorized ransomware.live API key")
            elif status == 429:
                messages.append("Ransomware.live monthly quota exceeded (500,000 requests/month)")
            elif status == 404:
                messages.append(f"No ransomware.live record found for '{query}'")
            else:
                messages.append(f"Ransomware.live HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting ransomware.live: {e}")
        except Exception as e:
            messages.append(f"Error during ransomware leak lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _add_group_intel(
        self,
        client: httpx.AsyncClient,
        group_slug: str,
        group_entity: Entity,
        entities: list[Entity],
        edges: list[Edge],
        messages: list[str],
    ) -> None:
        """Attach leak site URLs and exploited CVEs for one ransomware group."""
        try:
            response = await client.get(f"{API_BASE}/groups/{group_slug}")
            response.raise_for_status()
            data = response.json()
        except Exception:
            # Group intel is supplementary; a failure here must not lose the victims.
            messages.append(f"Could not load group intelligence for {group_entity.value}")
            return

        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else {}
        if not isinstance(data, dict):
            return

        description = self._clean(data.get("description"))
        if description:
            group_entity.properties["description"] = description[:2000]
        for field in ("firstseen", "lastseen", "victims"):
            value = self._clean(data.get(field))
            if value:
                group_entity.properties[field] = value

        for location in self._as_records(data.get("locations"))[:10]:
            url_value = self._clean(location.get("fqdn")) or self._clean(location.get("slug"))
            if not url_value:
                continue
            if not url_value.startswith("http"):
                url_value = f"http://{url_value}"
            url_entity = Entity(
                type=EntityType.URL,
                value=url_value,
                properties={
                    "kind": "ransomware_leak_site",
                    "ransomware_group": group_entity.value,
                    "available": self._clean(location.get("available")),
                    "source": "ransomware.live",
                },
                source=self.name,
            )
            entities.append(url_entity)
            edges.append(Edge(
                source_id=group_entity.id,
                target_id=url_entity.id,
                label="operates leak site",
                source_transform=self.name,
            ))

        seen_cves: set[str] = set()
        for vuln in self._as_records(data.get("vulnerabilities"))[:25]:
            cve = self._clean(vuln.get("cve") or vuln.get("id") or vuln.get("name"))
            if not cve or cve.lower() in seen_cves:
                continue
            seen_cves.add(cve.lower())
            vuln_entity = Entity(
                type=EntityType.VULNERABILITY,
                value=cve,
                properties={
                    "cvss": self._clean(vuln.get("cvss") or vuln.get("score")),
                    "exploited_by": group_entity.value,
                    "source": "ransomware.live",
                },
                source=self.name,
            )
            entities.append(vuln_entity)
            edges.append(Edge(
                source_id=group_entity.id,
                target_id=vuln_entity.id,
                label="exploits",
                source_transform=self.name,
            ))

    @staticmethod
    def _as_records(payload: object) -> list[dict]:
        """Normalize the API's list-or-wrapped-list responses to a list of dicts."""
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("victims", "data", "results"):
                nested = payload.get(key)
                if isinstance(nested, list):
                    return [item for item in nested if isinstance(item, dict)]
        return []

    @staticmethod
    def _clean(value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 20)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 20.0
        return max(5.0, min(timeout, 60.0))

    def _get_max_results(self, config: TransformConfig) -> int:
        return self.parse_int_setting(
            config.settings.get("max_results"),
            setting_name="max_results",
            default=25,
            min_value=1,
            declared_max=200,
        )

    def _get_include_group_intel(self, config: TransformConfig) -> bool:
        raw = str(config.settings.get("include_group_intel", "true")).strip().lower()
        return raw not in {"false", "0", "no", "off"}
