import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"


class UsernameToHudsonRock(BaseTransform):
    name = "username_to_hudson_rock"
    display_name = "Username & Phone to Hudson Rock"
    description = (
        "Checks a username, social handle, or phone number against Hudson "
        "Rock's free infostealer intelligence and maps any compromise to "
        "graph entities"
    )
    # Hudson Rock queries phone numbers through the username endpoint, so this
    # transform also accepts PhoneNumber entities.
    input_types = [
        EntityType.USERNAME,
        EntityType.SOCIAL_MEDIA,
        EntityType.PHONE_NUMBER,
    ]
    output_types = [
        EntityType.USERNAME,
        EntityType.EMAIL_ADDRESS,
        EntityType.IP_ADDRESS,
        EntityType.DOCUMENT,
    ]
    category = "Social Intelligence"
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
            description="Maximum infected-host IPs and leaked-login entities to emit",
            default="50",
            field_type="integer",
            min_value=1,
            max_value=200,
        ),
        TransformSetting(
            name="include_logins",
            display_name="Include Leaked Logins",
            description="Emit leaked logins as Username/EmailAddress entities",
            default="true",
            field_type="boolean",
        ),
        TransformSetting(
            name="mask_passwords",
            display_name="Mask Passwords",
            description="Mask leaked passwords in the evidence document",
            default="true",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        value = entity.value.strip()
        if not value:
            return TransformResult(messages=["Username/phone value is empty"])

        try:
            async with httpx.AsyncClient(
                timeout=self._get_timeout_seconds(config)
            ) as client:
                response = await client.get(
                    API_URL,
                    params={"username": value},
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

        entities, edges, messages = build_from_stealers(
            self,
            entity,
            data,
            max_results=self._get_max_results(config),
            include_logins=self._flag(config, "include_logins", True),
            mask_passwords=self._flag(config, "mask_passwords", True),
        )
        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _http_error(self, error: httpx.HTTPStatusError, value: str) -> str:
        status = error.response.status_code
        if status == 404:
            return f"No Hudson Rock infostealer records for {value}"
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

    def _flag(self, config: TransformConfig, key: str, default: bool) -> bool:
        raw = config.settings.get(key, default)
        return str(raw).strip().lower() not in {"false", "0", "no", "off"}


# --- Shared infostealer response mapping -----------------------------------
# The search-by-username and search-by-email endpoints return the same
# ``stealers`` payload shape, so this mapping is kept identical across the
# Hudson Rock identifier transforms.


def build_from_stealers(
    transform: BaseTransform,
    entity: Entity,
    data: object,
    max_results: int,
    include_logins: bool,
    mask_passwords: bool,
) -> tuple[list[Entity], list[Edge], list[str]]:
    if not isinstance(data, dict):
        return [], [], ["Hudson Rock returned an unexpected response payload"]

    api_message = _clean(data.get("message"))
    stealers = [s for s in (data.get("stealers") or []) if isinstance(s, dict)]
    if not stealers:
        return (
            [],
            [],
            [api_message or f"No Hudson Rock infostealer records for {entity.value}"],
        )

    entities: list[Entity] = []
    edges: list[Edge] = []
    messages: list[str] = []

    families = _unique(s.get("stealer_family") for s in stealers)
    operating_systems = _unique(s.get("operating_system") for s in stealers)
    ips = _unique(s.get("ip") for s in stealers)
    dates = sorted(
        _clean(s.get("date_compromised"))
        for s in stealers
        if _clean(s.get("date_compromised"))
    )

    enriched = {
        **entity.properties,
        "hudsonrock_compromised": True,
        "hudsonrock_stealer_count": len(stealers),
        "hudsonrock_total_corporate_services": _int(
            data.get("total_corporate_services")
        ),
        "hudsonrock_total_user_services": _int(data.get("total_user_services")),
        "hudsonrock_first_compromised": dates[0] if dates else "",
        "hudsonrock_last_compromised": dates[-1] if dates else "",
        "hudsonrock_stealer_families": ", ".join(families),
        "hudsonrock_operating_systems": ", ".join(operating_systems),
    }
    entities.append(entity.model_copy(update={"properties": enriched}))

    report = Entity(
        type=EntityType.DOCUMENT,
        value=f"Hudson Rock infostealer report for {entity.value}",
        properties={
            "provider": "hudsonrock",
            "source_query": entity.value,
            "stealer_count": len(stealers),
            "content": _summary(entity.value, api_message, stealers, mask_passwords),
        },
        source=transform.name,
    )
    entities.append(report)
    edges.append(
        Edge(
            source_id=entity.id,
            target_id=report.id,
            label="has evidence",
            source_transform=transform.name,
        )
    )

    for ip in ips[:max_results]:
        ip_entity = Entity(
            type=EntityType.IP_ADDRESS,
            value=ip,
            properties={"source": "hudsonrock", "kind": "infected_host"},
            source=transform.name,
        )
        entities.append(ip_entity)
        edges.append(
            Edge(
                source_id=entity.id,
                target_id=ip_entity.id,
                label="compromised on host",
                source_transform=transform.name,
            )
        )

    if include_logins:
        logins = _unique(
            login
            for s in stealers
            for login in (s.get("top_logins") or [])
            if isinstance(login, str)
        )
        for login in logins[:max_results]:
            login_type = (
                EntityType.EMAIL_ADDRESS
                if _looks_like_email(login)
                else EntityType.USERNAME
            )
            login_entity = Entity(
                type=login_type,
                value=login,
                properties={"source": "hudsonrock", "kind": "leaked_login"},
                source=transform.name,
            )
            entities.append(login_entity)
            edges.append(
                Edge(
                    source_id=entity.id,
                    target_id=login_entity.id,
                    label="leaked credential",
                    source_transform=transform.name,
                )
            )

    messages.append(f"Hudson Rock infostealer infections found: {len(stealers)}")
    if families:
        messages.append(f"Stealer families: {', '.join(families[:5])}")
    if api_message:
        messages.append(api_message)
    return entities, edges, messages


def _summary(
    query: str, api_message: str, stealers: list[dict], mask_passwords: bool
) -> str:
    lines = [f"Query: {query}", f"Infostealer infections: {len(stealers)}"]
    if api_message:
        lines.extend(["", api_message])
    for index, stealer in enumerate(stealers, start=1):
        logins = [x for x in (stealer.get("top_logins") or []) if isinstance(x, str)]
        passwords = [
            x for x in (stealer.get("top_passwords") or []) if isinstance(x, str)
        ]
        if mask_passwords:
            passwords = [_mask(p) for p in passwords]
        antiviruses = [
            x for x in (stealer.get("antiviruses") or []) if isinstance(x, str)
        ]
        date = _clean(stealer.get("date_compromised")) or "unknown"
        family = _clean(stealer.get("stealer_family")) or "unknown"
        os_name = _clean(stealer.get("operating_system")) or "unknown"
        computer = _clean(stealer.get("computer_name")) or "unknown"
        host_ip = _clean(stealer.get("ip")) or "unknown"
        malware = _clean(stealer.get("malware_path")) or "unknown"
        lines.extend(
            [
                "",
                f"[{index}] Date compromised: {date}",
                f"    Stealer family: {family}",
                f"    Operating system: {os_name}",
                f"    Computer name: {computer}",
                f"    Infected IP: {host_ip}",
                f"    Malware path: {malware}",
                f"    Antiviruses: {', '.join(antiviruses) or 'none'}",
                f"    Top logins: {', '.join(logins) or 'none'}",
                f"    Top passwords: {', '.join(passwords) or 'none'}",
            ]
        )
    lines.extend(
        ["", "Data: Hudson Rock free OSINT tier - https://www.hudsonrock.com/"]
    )
    return "\n".join(lines).strip()


def _mask(value: str) -> str:
    value = str(value)
    if not value:
        return ""
    if len(value) == 1:
        return "*"
    return value[0] + "*" * (len(value) - 1)


def _looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.rsplit("@", 1)[-1]


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
