import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"

_LABEL_KEYS = ("domain", "url", "name", "value", "title")


class DomainToHudsonRock(BaseTransform):
    name = "domain_to_hudson_rock"
    display_name = "Domain to Hudson Rock"
    description = (
        "Checks a domain against Hudson Rock's free infostealer intelligence "
        "and maps employee/user compromise stats and third-party exposure to "
        "graph entities"
    )
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.DOMAIN, EntityType.URL, EntityType.DOCUMENT]
    category = "Domain Intelligence"
    settings = [
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Hudson Rock request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum third-party Domain entities to emit",
            default="50",
            field_type="integer",
            min_value=1,
            max_value=200,
        ),
        TransformSetting(
            name="max_urls",
            display_name="Max URLs",
            description="Maximum exposed login URLs to emit as URL entities",
            default="25",
            field_type="integer",
            min_value=0,
            max_value=200,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        value = entity.value.strip().lower()
        if not value:
            return TransformResult(messages=["Domain value is empty"])

        try:
            async with httpx.AsyncClient(
                timeout=self._get_timeout_seconds(config)
            ) as client:
                response = await client.get(
                    API_URL,
                    params={"domain": value},
                    headers={
                        "accept": "application/json",
                        "user-agent": "OGI-Transforms/1.0",
                    },
                )
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            return TransformResult(messages=[self._http_error(e, value)])
        except httpx.RequestError as e:
            return TransformResult(
                messages=[f"Request error contacting Hudson Rock: {e}"]
            )
        except Exception as e:
            return TransformResult(messages=[f"Error during Hudson Rock lookup: {e}"])

        return self._build(
            entity,
            data,
            max_results=self._get_max_results(config),
            max_urls=self._get_max_urls(config),
        )

    def _build(
        self,
        entity: Entity,
        data: object,
        max_results: int,
        max_urls: int,
    ) -> TransformResult:
        if not isinstance(data, dict):
            return TransformResult(
                messages=["Hudson Rock returned an unexpected response payload"]
            )

        api_message = _clean(data.get("message"))
        nested = data.get("data") if isinstance(data.get("data"), dict) else {}

        total_stealers = _int(data.get("totalStealers"))
        employees = _int(data.get("employees"))
        users = _int(data.get("users"))
        third_parties = _int(data.get("third_parties"))

        # ``stealerFamilies``/``applications`` are count maps that include an
        # aggregate "total" key; drop it so only real labels surface.
        families = [
            f
            for f in _unique(_labels(data.get("stealerFamilies")))
            if f.lower() != "total"
        ]
        applications = [
            a
            for a in _unique(_labels(data.get("applications")))
            if a.lower() != "total"
        ]
        third_party_domains = _unique(_labels(data.get("thirdPartyDomains")))
        employee_urls = _unique(_labels(nested.get("employees_urls")))
        client_urls = _unique(_labels(nested.get("clients_urls")))

        has_data = any(
            [
                total_stealers,
                employees,
                users,
                third_parties,
                third_party_domains,
                employee_urls,
                client_urls,
            ]
        )
        if not has_data:
            return TransformResult(
                messages=[
                    api_message or f"No Hudson Rock infostealer data for {entity.value}"
                ]
            )

        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        enriched = {
            **entity.properties,
            "hudsonrock_compromised": True,
            "hudsonrock_total_stealers": total_stealers,
            "hudsonrock_employees_compromised": employees,
            "hudsonrock_users_compromised": users,
            "hudsonrock_third_parties": third_parties,
            "hudsonrock_total_urls": _int(data.get("totalUrls")),
            "hudsonrock_is_shopify": bool(data.get("is_shopify")),
            "hudsonrock_last_employee_compromised": _clean(
                data.get("last_employee_compromised")
            ),
            "hudsonrock_last_user_compromised": _clean(
                data.get("last_user_compromised")
            ),
            "hudsonrock_stealer_families": ", ".join(families[:20]),
        }
        entities.append(entity.model_copy(update={"properties": enriched}))

        report = Entity(
            type=EntityType.DOCUMENT,
            value=f"Hudson Rock domain breach report for {entity.value}",
            properties={
                "provider": "hudsonrock",
                "source_query": entity.value,
                "total_stealers": total_stealers,
                "content": _summary(
                    entity.value,
                    api_message,
                    data,
                    families,
                    applications,
                    third_party_domains,
                    employee_urls,
                    client_urls,
                ),
            },
            source=self.name,
        )
        entities.append(report)
        edges.append(
            Edge(
                source_id=entity.id,
                target_id=report.id,
                label="has evidence",
                source_transform=self.name,
            )
        )

        for domain in third_party_domains[:max_results]:
            domain_entity = Entity(
                type=EntityType.DOMAIN,
                value=domain,
                properties={"source": "hudsonrock", "kind": "third_party_exposure"},
                source=self.name,
            )
            entities.append(domain_entity)
            edges.append(
                Edge(
                    source_id=entity.id,
                    target_id=domain_entity.id,
                    label="third-party exposure",
                    source_transform=self.name,
                )
            )

        if max_urls > 0:
            self._emit_urls(
                entity,
                employee_urls[:max_urls],
                "employee credentials exposed",
                entities,
                edges,
            )
            self._emit_urls(
                entity,
                client_urls[:max_urls],
                "client credentials exposed",
                entities,
                edges,
            )

        messages.append(
            f"Hudson Rock domain exposure: {employees} employees, {users} users, "
            f"{total_stealers} infections"
        )
        if families:
            messages.append(f"Stealer families: {', '.join(families[:5])}")
        if api_message:
            messages.append(api_message)
        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _emit_urls(
        self,
        entity: Entity,
        urls: list[str],
        label: str,
        entities: list[Entity],
        edges: list[Edge],
    ) -> None:
        for url in urls:
            url_entity = Entity(
                type=EntityType.URL,
                value=url,
                properties={"source": "hudsonrock", "kind": "exposed_login_url"},
                source=self.name,
            )
            entities.append(url_entity)
            edges.append(
                Edge(
                    source_id=entity.id,
                    target_id=url_entity.id,
                    label=label,
                    source_transform=self.name,
                )
            )

    def _http_error(self, error: httpx.HTTPStatusError, value: str) -> str:
        status = error.response.status_code
        if status == 404:
            return f"No Hudson Rock infostealer data for {value}"
        if status == 429:
            return "Hudson Rock rate limit exceeded; try again later"
        return f"Hudson Rock HTTP error: {error}"

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        try:
            timeout = float(config.settings.get("timeout_seconds", 15))
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))

    def _get_max_results(self, config: TransformConfig) -> int:
        try:
            value = int(config.settings.get("max_results", 50))
        except (TypeError, ValueError):
            return 50
        return max(1, min(value, 200))

    def _get_max_urls(self, config: TransformConfig) -> int:
        try:
            value = int(config.settings.get("max_urls", 25))
        except (TypeError, ValueError):
            return 25
        return max(0, min(value, 200))


def _summary(
    query: str,
    api_message: str,
    data: dict,
    families: list[str],
    applications: list[str],
    third_party_domains: list[str],
    employee_urls: list[str],
    client_urls: list[str],
) -> str:
    last_employee = _clean(data.get("last_employee_compromised")) or "unknown"
    last_user = _clean(data.get("last_user_compromised")) or "unknown"
    lines = [
        f"Domain: {query}",
        f"Total infections: {_int(data.get('totalStealers'))}",
        f"Employees compromised: {_int(data.get('employees'))}",
        f"Users compromised: {_int(data.get('users'))}",
        f"Third parties: {_int(data.get('third_parties'))}",
        f"Total exposed URLs: {_int(data.get('totalUrls'))}",
        f"Shopify store: {bool(data.get('is_shopify'))}",
        f"Last employee compromised: {last_employee}",
        f"Last user compromised: {last_user}",
    ]
    if api_message:
        lines.extend(["", api_message])
    if families:
        lines.extend(["", f"Stealer families: {', '.join(families[:20])}"])
    if applications:
        lines.extend(["", f"Applications: {', '.join(applications[:20])}"])
    if third_party_domains:
        lines.extend(
            ["", f"Third-party domains: {', '.join(third_party_domains[:20])}"]
        )
    if employee_urls:
        lines.extend(["", f"Top employee login URLs: {', '.join(employee_urls[:10])}"])
    if client_urls:
        lines.extend(["", f"Top client login URLs: {', '.join(client_urls[:10])}"])
    lines.extend(
        ["", "Data: Hudson Rock free OSINT tier - https://www.hudsonrock.com/"]
    )
    return "\n".join(lines).strip()


def _labels(raw: object) -> list[str]:
    """Extract label strings from a list (of strings or dicts) or a count mapping."""
    out: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = ""
                for key in _LABEL_KEYS:
                    candidate = _clean(item.get(key))
                    if candidate:
                        value = candidate
                        break
            else:
                value = ""
            if value:
                out.append(value)
    elif isinstance(raw, dict):
        out = [_clean(key) for key in raw.keys() if _clean(key)]
    return out


def _unique(values) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for raw in values:
        cleaned = _clean(raw)
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(cleaned)
    return results


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()
