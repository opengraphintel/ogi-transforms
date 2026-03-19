import httpx

from ogi.models import Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting


class URLToUrlscanLookup(BaseTransform):
    name = "url_to_urlscan_lookup"
    display_name = "URL to urlscan Lookup"
    description = "Looks up the most recent matching urlscan result for a URL"
    input_types = [EntityType.URL]
    output_types = [EntityType.URL]
    category = "Web"
    settings = [
        TransformSetting(
            name="urlscan_api_key",
            display_name="urlscan API Key",
            description="API key for urlscan historical search lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the urlscan search request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=60,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        url = entity.value.strip()
        entities: list[Entity] = []
        edges: list = []
        messages: list[str] = []

        api_key = str(config.settings.get("urlscan_api_key") or "").strip()
        if not api_key:
            messages.append("urlscan API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        if not url:
            messages.append("URL value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)
        query = self._build_query(url)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": query, "size": 1},
                    headers={
                        "accept": "application/json",
                        "api-key": api_key,
                    },
                )
                response.raise_for_status()
                data = response.json()

            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or not results:
                messages.append(f"No urlscan results found for {url}")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            result = results[0] if isinstance(results[0], dict) else {}
            task = result.get("task") if isinstance(result.get("task"), dict) else {}
            page = result.get("page") if isinstance(result.get("page"), dict) else {}
            stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
            result_id = str(result.get("_id") or "").strip()
            report_url = f"https://urlscan.io/result/{result_id}/" if result_id else ""

            enriched_properties: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "urlscan_result_id": result_id,
                "urlscan_report_url": report_url,
                "urlscan_task_url": str(task.get("url") or "").strip(),
                "urlscan_page_url": str(page.get("url") or "").strip(),
                "urlscan_page_domain": str(page.get("domain") or "").strip(),
                "urlscan_page_ip": str(page.get("ip") or "").strip(),
                "urlscan_country": str(page.get("country") or "").strip(),
                "urlscan_server": str(page.get("server") or "").strip(),
                "urlscan_status": str(page.get("status") or "").strip(),
                "urlscan_visibility": str(task.get("visibility") or "").strip(),
                "urlscan_scan_date": str(task.get("time") or "").strip(),
            }

            domains_count = stats.get("domainStats")
            if isinstance(domains_count, int):
                enriched_properties["urlscan_domain_count"] = domains_count

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            messages.append(f"Found urlscan result {result_id or 'unknown'}")
            if report_url:
                messages.append(f"urlscan report: {report_url}")
            if enriched_properties.get("urlscan_page_domain"):
                messages.append(
                    f"Page domain: {enriched_properties['urlscan_page_domain']}"
                )
            if enriched_properties.get("urlscan_page_ip"):
                messages.append(f"Page IP: {enriched_properties['urlscan_page_ip']}")
            if enriched_properties.get("urlscan_scan_date"):
                messages.append(
                    f"Scanned: {enriched_properties['urlscan_scan_date']}"
                )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid urlscan API key")
            elif e.response.status_code == 429:
                messages.append("urlscan rate limit exceeded")
            else:
                messages.append(f"urlscan HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting urlscan: {e}")
        except Exception as e:
            messages.append(f"Error during urlscan lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _build_query(self, url: str) -> str:
        escaped = url.replace('\\', '\\\\').replace('"', '\\"')
        return f'task.url:"{escaped}" OR page.url:"{escaped}"'

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 60.0))