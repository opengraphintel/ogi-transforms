import httpx

from ogi.models import Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class IPToIPinfoProfile(BaseTransform):
    name = "ip_to_ipinfo_profile"
    display_name = "IP to IPinfo Profile"
    description = "Enriches an IP address with IPinfo profile data"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [EntityType.IP_ADDRESS]
    category = "IP Intelligence"
    settings = [
        TransformSetting(
            name="ipinfo_api_key",
            display_name="IPinfo API Key",
            description="API token for IPinfo lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the IPinfo request",
            default="10",
            field_type="integer",
            min_value=3,
            max_value=30,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list = []
        messages: list[str] = []

        api_key = str(config.settings.get("ipinfo_api_key") or "").strip()
        if not api_key:
            messages.append("IPinfo API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not ip:
            messages.append("IP value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    f"https://api.ipinfo.io/lookup/{ip}",
                    headers={
                        "accept": "application/json",
                        "authorization": f"Bearer {api_key}",
                    },
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("IPinfo returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
            asn = data.get("as") if isinstance(data.get("as"), dict) else {}

            enriched_properties: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "ipinfo_hostname": self._clean(data.get("hostname")),
                "ipinfo_city": self._clean(geo.get("city")),
                "ipinfo_region": self._clean(geo.get("region")),
                "ipinfo_region_code": self._clean(geo.get("region_code")),
                "ipinfo_country": self._clean(geo.get("country")),
                "ipinfo_country_code": self._clean(geo.get("country_code")),
                "ipinfo_continent": self._clean(geo.get("continent")),
                "ipinfo_continent_code": self._clean(geo.get("continent_code")),
                "ipinfo_timezone": self._clean(geo.get("timezone")),
                "ipinfo_postal_code": self._clean(geo.get("postal_code")),
                "ipinfo_asn": self._clean(asn.get("asn")),
                "ipinfo_as_name": self._clean(asn.get("name")),
                "ipinfo_as_domain": self._clean(asn.get("domain")),
                "ipinfo_as_route": self._clean(asn.get("route")),
                "ipinfo_as_type": self._clean(asn.get("type")),
                "ipinfo_is_anonymous": bool(data.get("is_anonymous", False)),
                "ipinfo_is_anycast": bool(data.get("is_anycast", False)),
                "ipinfo_is_hosting": bool(data.get("is_hosting", False)),
                "ipinfo_is_mobile": bool(data.get("is_mobile", False)),
                "ipinfo_is_satellite": bool(data.get("is_satellite", False)),
            }

            latitude = geo.get("latitude")
            longitude = geo.get("longitude")
            if isinstance(latitude, (int, float)):
                enriched_properties["ipinfo_latitude"] = float(latitude)
            if isinstance(longitude, (int, float)):
                enriched_properties["ipinfo_longitude"] = float(longitude)

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            if enriched_properties.get("ipinfo_country"):
                messages.append(f"Country: {enriched_properties['ipinfo_country']}")
            if enriched_properties.get("ipinfo_region") or enriched_properties.get("ipinfo_city"):
                city = enriched_properties.get("ipinfo_city") or ""
                region = enriched_properties.get("ipinfo_region") or ""
                messages.append(f"Location: {city}, {region}".strip(", "))
            if enriched_properties.get("ipinfo_asn"):
                as_name = enriched_properties.get("ipinfo_as_name") or ""
                messages.append(f"ASN: {enriched_properties['ipinfo_asn']} {as_name}".strip())
            if enriched_properties.get("ipinfo_hostname"):
                messages.append(f"Hostname: {enriched_properties['ipinfo_hostname']}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid IPinfo API key")
            elif e.response.status_code == 429:
                messages.append("IPinfo rate limit exceeded")
            else:
                messages.append(f"IPinfo HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting IPinfo: {e}")
        except Exception as e:
            messages.append(f"Error during IPinfo profile lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 10)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 10.0
        return max(3.0, min(timeout, 30.0))