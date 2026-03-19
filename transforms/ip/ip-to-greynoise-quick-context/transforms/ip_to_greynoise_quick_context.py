import httpx

from ogi.models import Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig


class IPToGreyNoiseQuickContext(BaseTransform):
    name = "ip_to_greynoise_quick_context"
    display_name = "IP to GreyNoise Quick Context"
    description = "Enriches an IP address with GreyNoise community quick context"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [EntityType.IP_ADDRESS]
    category = "IP Intelligence"

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list = []
        messages: list[str] = []

        timeout_seconds = self._get_timeout_seconds(config)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("GreyNoise returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            enriched_properties: dict[str, str | bool | int | float | None] = {
                **entity.properties,
                "greynoise_noise": bool(data.get("noise", False)),
                "greynoise_riot": bool(data.get("riot", False)),
            }

            for field in ("classification", "name", "link", "last_seen", "message"):
                value = data.get(field)
                if value not in (None, ""):
                    enriched_properties[f"greynoise_{field}"] = str(value)

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            classification = str(data.get("classification") or "unknown")
            noise = bool(data.get("noise", False))
            riot = bool(data.get("riot", False))
            messages.append(
                f"GreyNoise classification: {classification}; noise={str(noise).lower()}; riot={str(riot).lower()}"
            )

            name = data.get("name")
            if name:
                messages.append(f"GreyNoise name: {name}")

            last_seen = data.get("last_seen")
            if last_seen:
                messages.append(f"GreyNoise last seen: {last_seen}")

            link = data.get("link")
            if link:
                messages.append(f"GreyNoise visualizer: {link}")

            api_message = data.get("message")
            if api_message and str(api_message).strip().lower() != "success":
                messages.append(f"GreyNoise message: {api_message}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                messages.append(f"GreyNoise has no community data for {ip}")
            elif e.response.status_code == 429:
                messages.append("GreyNoise community rate limit exceeded")
            else:
                messages.append(f"GreyNoise HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting GreyNoise: {e}")
        except Exception as e:
            messages.append(f"Error during GreyNoise quick context lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 10)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 10.0
        return max(3.0, min(timeout, 30.0))