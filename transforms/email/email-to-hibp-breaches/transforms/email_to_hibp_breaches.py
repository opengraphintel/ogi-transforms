import html
from urllib.parse import quote

import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class EmailToHIBPBreaches(BaseTransform):
    name = "email_to_hibp_breaches"
    display_name = "Email to HIBP Breaches"
    description = "Looks up an email address in Have I Been Pwned"
    input_types = [EntityType.EMAIL_ADDRESS]
    output_types = [EntityType.DOCUMENT]
    category = "Email Intelligence"
    settings = [
        TransformSetting(
            name="hibp_api_key",
            display_name="HIBP API Key",
            description="API key for Have I Been Pwned account breach lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the HIBP request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="include_unverified",
            display_name="Include Unverified",
            description="Include breaches flagged as unverified",
            default="true",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        email_value = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("hibp_api_key") or "").strip()
        if not api_key:
            return TransformResult(messages=["HIBP API key required. Configure it under API Keys."])
        if not email_value:
            return TransformResult(messages=["Email value is empty"])

        try:
            breaches = await self._fetch_breaches(
                email_value,
                api_key,
                self._include_unverified(config),
                self._get_timeout_seconds(config),
            )
            if not breaches:
                return TransformResult(messages=[f"No HIBP breaches found for {email_value}"])

            evidence = Entity(
                type=EntityType.DOCUMENT,
                value=f"HIBP breaches for {email_value}",
                properties={
                    "provider": "hibp",
                    "email": email_value,
                    "breach_count": len(breaches),
                    "report_url": f"https://haveibeenpwned.com/account/{quote(email_value)}",
                    "content": self._build_summary(email_value, breaches),
                },
                source=self.name,
            )
            entities.append(evidence)
            edges.append(Edge(source_id=entity.id, target_id=evidence.id, label="has evidence", source_transform=self.name))
            messages.append(f"HIBP breaches found: {len(breaches)}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid HIBP API key")
            elif e.response.status_code == 403:
                messages.append("HIBP request rejected. Ensure a valid user-agent and API key are configured")
            elif e.response.status_code == 404:
                messages.append(f"No HIBP breaches found for {email_value}")
            elif e.response.status_code == 429:
                messages.append("HIBP rate limit exceeded")
            else:
                messages.append(f"HIBP HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting HIBP: {e}")
        except Exception as e:
            messages.append(f"Error during HIBP breach lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    async def _fetch_breaches(self, email_value: str, api_key: str, include_unverified: bool, timeout_seconds: float) -> list[dict]:
        params = {
            "truncateResponse": "false",
            "includeUnverified": str(include_unverified).lower(),
        }
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email_value)}",
                params=params,
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "OGI-Transforms/1.0",
                    "accept": "application/json",
                },
            )
            response.raise_for_status()
            payload = response.json()
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def _build_summary(self, email_value: str, breaches: list[dict]) -> str:
        lines = [
            f"Email: {email_value}",
            f"Breaches found: {len(breaches)}",
            f"HIBP URL: https://haveibeenpwned.com/account/{quote(email_value)}",
            "",
        ]
        for breach in breaches:
            data_classes = breach.get("DataClasses") if isinstance(breach.get("DataClasses"), list) else []
            description = html.unescape(self._clean(breach.get("Description")))
            lines.extend([
                f"Name: {self._clean(breach.get('Name')) or 'unknown'}",
                f"Title: {self._clean(breach.get('Title')) or 'unknown'}",
                f"Domain: {self._clean(breach.get('Domain')) or 'unknown'}",
                f"Breach date: {self._clean(breach.get('BreachDate')) or 'unknown'}",
                f"Added date: {self._clean(breach.get('AddedDate')) or 'unknown'}",
                f"Pwn count: {self._clean(breach.get('PwnCount')) or 'unknown'}",
                f"Verified: {self._clean(breach.get('IsVerified')) or 'unknown'}",
                f"Sensitive: {self._clean(breach.get('IsSensitive')) or 'unknown'}",
                f"Spam list: {self._clean(breach.get('IsSpamList')) or 'unknown'}",
                f"Data classes: {', '.join(self._clean(item) for item in data_classes if self._clean(item)) or 'none'}",
                f"Description: {description or 'unknown'}",
                "",
            ])
        return "\n".join(lines).strip()

    def _include_unverified(self, config: TransformConfig) -> bool:
        raw = config.settings.get("include_unverified", "true")
        return str(raw).strip().lower() not in {"false", "0", "no", "off"}

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))
