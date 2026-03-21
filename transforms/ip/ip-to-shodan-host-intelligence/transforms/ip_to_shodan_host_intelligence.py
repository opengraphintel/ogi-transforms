import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

INTERESTING_HEADERS = {
    "server",
    "x-powered-by",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
}


class IPToShodanHostIntelligence(BaseTransform):
    name = "ip_to_shodan_host_intelligence"
    display_name = "IP to Shodan Host Intelligence"
    description = "Builds a deep Shodan host profile with service, HTTP, SSL, and evidence context"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [
        EntityType.IP_ADDRESS,
        EntityType.AS_NUMBER,
        EntityType.ORGANIZATION,
        EntityType.DOMAIN,
        EntityType.SUBDOMAIN,
        EntityType.LOCATION,
        EntityType.DOCUMENT,
        EntityType.HTTP_HEADER,
        EntityType.SSL_CERTIFICATE,
        EntityType.URL,
    ]
    category = "IP Intelligence"
    settings = [
        TransformSetting(
            name="shodan_api_key",
            display_name="Shodan API Key",
            description="API key for Shodan host lookups",
            required=True,
            field_type="secret",
        ),
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Shodan host request",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
        TransformSetting(
            name="include_services",
            display_name="Include Services",
            description="Emit URL and HTTP header entities from service observations",
            default="true",
            field_type="boolean",
        ),
        TransformSetting(
            name="include_vulnerabilities",
            display_name="Include Vulnerabilities",
            description="Include vulnerability identifiers in the evidence summary",
            default="true",
            field_type="boolean",
        ),
        TransformSetting(
            name="include_ssl",
            display_name="Include SSL",
            description="Emit certificate entities from SSL-enabled services",
            default="true",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        api_key = str(config.settings.get("shodan_api_key") or "").strip()
        if not api_key:
            messages.append("Shodan API key required. Configure it under API Keys.")
            return TransformResult(entities=entities, edges=edges, messages=messages)
        if not ip:
            messages.append("IP value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        include_services = self._get_bool(config.settings.get("include_services", "true"))
        include_vulnerabilities = self._get_bool(config.settings.get("include_vulnerabilities", "true"))
        include_ssl = self._get_bool(config.settings.get("include_ssl", "true"))

        try:
            async with httpx.AsyncClient(timeout=self._get_timeout_seconds(config)) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": api_key},
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("Shodan returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            records = data.get("data") if isinstance(data.get("data"), list) else []
            vulnerability_ids = self._collect_vulnerability_ids(data, records)

            enriched_properties: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "shodan_ip_str": self._clean(data.get("ip_str")),
                "shodan_asn": self._clean(data.get("asn")),
                "shodan_isp": self._clean(data.get("isp")),
                "shodan_org": self._clean(data.get("org")),
                "shodan_os": self._clean(data.get("os")),
                "shodan_hostnames": self._join_list(data.get("hostnames")),
                "shodan_domains": self._join_list(data.get("domains")),
                "shodan_ports": self._join_list(data.get("ports")),
                "shodan_tags": self._join_list(data.get("tags")),
                "shodan_city": self._clean(data.get("city")),
                "shodan_region_code": self._clean(data.get("region_code")),
                "shodan_country_code": self._clean(data.get("country_code")),
                "shodan_country_name": self._clean(data.get("country_name")),
                "shodan_postal_code": self._clean(data.get("postal_code")),
                "shodan_last_update": self._clean(data.get("last_update")),
                "shodan_service_count": len(records),
                "shodan_vulnerabilities": ", ".join(vulnerability_ids),
                "shodan_link": f"https://www.shodan.io/host/{ip}",
            }
            latitude = data.get("latitude")
            longitude = data.get("longitude")
            if isinstance(latitude, (int, float)):
                enriched_properties["shodan_latitude"] = float(latitude)
            if isinstance(longitude, (int, float)):
                enriched_properties["shodan_longitude"] = float(longitude)

            entities.append(entity.model_copy(update={"properties": enriched_properties}))

            asn_value = self._clean(data.get("asn"))
            if asn_value:
                as_entity = Entity(
                    type=EntityType.AS_NUMBER,
                    value=asn_value,
                    properties={"org": self._clean(data.get("org")), "isp": self._clean(data.get("isp")), "source": "shodan"},
                    source=self.name,
                )
                entities.append(as_entity)
                edges.append(Edge(source_id=entity.id, target_id=as_entity.id, label="belongs to ASN", source_transform=self.name))
                messages.append(f"ASN: {asn_value}")

            org_value = self._clean(data.get("org"))
            if org_value:
                org_entity = Entity(
                    type=EntityType.ORGANIZATION,
                    value=org_value,
                    properties={"asn": asn_value, "isp": self._clean(data.get("isp")), "source": "shodan"},
                    source=self.name,
                )
                entities.append(org_entity)
                edges.append(Edge(source_id=entity.id, target_id=org_entity.id, label="operated by", source_transform=self.name))
                messages.append(f"Organization: {org_value}")

            location_entity = self._build_location_entity(data)
            if location_entity is not None:
                entities.append(location_entity)
                edges.append(Edge(source_id=entity.id, target_id=location_entity.id, label="located in", source_transform=self.name))
                messages.append(f"Location: {location_entity.value}")

            evidence_doc = Entity(
                type=EntityType.DOCUMENT,
                value=f"Shodan host intelligence for {ip}",
                properties={
                    "provider": "shodan",
                    "report_url": f"https://www.shodan.io/host/{ip}",
                    "content": self._build_summary(ip, data, records, vulnerability_ids, include_vulnerabilities),
                },
                source=self.name,
            )
            entities.append(evidence_doc)
            edges.append(Edge(source_id=entity.id, target_id=evidence_doc.id, label="has evidence", source_transform=self.name))

            seen_names: set[tuple[EntityType, str]] = set()
            for hostname in self._iter_clean_list(data.get("hostnames")):
                entity_type = EntityType.SUBDOMAIN if "." in hostname else EntityType.DOMAIN
                key = (entity_type, hostname.lower())
                if key in seen_names:
                    continue
                seen_names.add(key)
                host_entity = Entity(type=entity_type, value=hostname, properties={"source": "shodan", "kind": "hostname"}, source=self.name)
                entities.append(host_entity)
                edges.append(Edge(source_id=entity.id, target_id=host_entity.id, label="resolves to", source_transform=self.name))

            for domain_value in self._iter_clean_list(data.get("domains")):
                key = (EntityType.DOMAIN, domain_value.lower())
                if key in seen_names:
                    continue
                seen_names.add(key)
                domain_entity = Entity(type=EntityType.DOMAIN, value=domain_value, properties={"source": "shodan", "kind": "domain"}, source=self.name)
                entities.append(domain_entity)
                edges.append(Edge(source_id=entity.id, target_id=domain_entity.id, label="associated with domain", source_transform=self.name))

            header_count = 0
            cert_count = 0
            url_count = 0
            seen_urls: set[str] = set()
            seen_headers: set[tuple[str, str]] = set()
            seen_certs: set[str] = set()
            url_entities_by_value: dict[str, Entity] = {}

            if include_services or include_ssl:
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    port = record.get("port")
                    http_block = record.get("http") if isinstance(record.get("http"), dict) else {}
                    ssl_block = record.get("ssl") if isinstance(record.get("ssl"), dict) else {}
                    service_host = self._pick_service_host(http_block, record, data)
                    url_value = self._build_service_url(service_host, port, bool(http_block), bool(ssl_block))

                    if include_services and url_value:
                        lowered = url_value.lower()
                        if lowered not in seen_urls:
                            seen_urls.add(lowered)
                            url_entity = Entity(
                                type=EntityType.URL,
                                value=url_value,
                                properties={
                                    "port": self._clean(port),
                                    "host": service_host,
                                    "source": "shodan",
                                },
                                source=self.name,
                            )
                            url_entities_by_value[lowered] = url_entity
                            entities.append(url_entity)
                            edges.append(Edge(source_id=entity.id, target_id=url_entity.id, label="hosts service", source_transform=self.name))
                            url_count += 1
                        url_entity = url_entities_by_value.get(lowered)
                    else:
                        url_entity = None

                    if include_services and http_block:
                        headers = http_block.get("headers") if isinstance(http_block.get("headers"), dict) else {}
                        for header_name, header_value in headers.items():
                            header_name_clean = self._clean(header_name)
                            header_value_clean = self._clean(header_value)
                            if not header_name_clean or not header_value_clean:
                                continue
                            if header_name_clean.lower() not in INTERESTING_HEADERS:
                                continue
                            header_key = (header_name_clean.lower(), header_value_clean)
                            if header_key in seen_headers:
                                continue
                            seen_headers.add(header_key)
                            header_entity = Entity(
                                type=EntityType.HTTP_HEADER,
                                value=f"{header_name_clean}: {header_value_clean}",
                                properties={
                                    "header_name": header_name_clean,
                                    "header_value": header_value_clean,
                                    "port": self._clean(port),
                                    "source": "shodan",
                                },
                                source=self.name,
                            )
                            entities.append(header_entity)
                            edges.append(
                                Edge(
                                    source_id=(url_entity.id if url_entity is not None else entity.id),
                                    target_id=header_entity.id,
                                    label="has header",
                                    source_transform=self.name,
                                )
                            )
                            header_count += 1

                    if include_ssl and ssl_block:
                        cert_entity = self._build_certificate_entity(ssl_block)
                        if cert_entity is not None:
                            fingerprint = self._clean(cert_entity.properties.get("fingerprint_sha256") or cert_entity.value)
                            if fingerprint and fingerprint not in seen_certs:
                                seen_certs.add(fingerprint)
                                entities.append(cert_entity)
                                edges.append(Edge(source_id=entity.id, target_id=cert_entity.id, label="secured by", source_transform=self.name))
                                cert_count += 1

            if enriched_properties.get("shodan_ports"):
                messages.append(f"Ports: {enriched_properties['shodan_ports']}")
            if vulnerability_ids and include_vulnerabilities:
                messages.append(f"Vulnerabilities: {', '.join(vulnerability_ids)}")
            if url_count:
                messages.append(f"URLs: {url_count}")
            if header_count:
                messages.append(f"HTTP headers: {header_count}")
            if cert_count:
                messages.append(f"Certificates: {cert_count}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                messages.append("Invalid Shodan API key")
            elif e.response.status_code == 404:
                messages.append(f"Shodan has no host data for {ip}")
            elif e.response.status_code == 429:
                messages.append("Shodan rate limit exceeded")
            else:
                messages.append(f"Shodan HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Shodan: {e}")
        except Exception as e:
            messages.append(f"Error during Shodan host lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _build_summary(self, ip: str, data: dict, records: list[object], vulnerabilities: list[str], include_vulnerabilities: bool) -> str:
        lines = [
            f"IP: {self._clean(data.get('ip_str')) or ip}",
            f"ASN: {self._clean(data.get('asn')) or 'unknown'}",
            f"Organization: {self._clean(data.get('org')) or 'unknown'}",
            f"ISP: {self._clean(data.get('isp')) or 'unknown'}",
            f"OS: {self._clean(data.get('os')) or 'unknown'}",
            f"Hostnames: {self._join_list(data.get('hostnames')) or 'none'}",
            f"Domains: {self._join_list(data.get('domains')) or 'none'}",
            f"Ports: {self._join_list(data.get('ports')) or 'none'}",
            f"Tags: {self._join_list(data.get('tags')) or 'none'}",
            f"Service observations: {len(records)}",
            f"Last update: {self._clean(data.get('last_update')) or 'unknown'}",
            f"Shodan URL: https://www.shodan.io/host/{ip}",
        ]
        if include_vulnerabilities:
            lines.append(f"Vulnerabilities: {', '.join(vulnerabilities) if vulnerabilities else 'none'}")
        return "\n".join(lines)

    def _collect_vulnerability_ids(self, data: dict, records: list[object]) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []
        sources = [data.get("vulns")]
        sources.extend(record.get("vulns") for record in records if isinstance(record, dict))
        for source in sources:
            if isinstance(source, dict):
                items = source.keys()
            elif isinstance(source, list):
                items = source
            else:
                continue
            for item in items:
                cleaned = self._clean(item)
                if not cleaned or cleaned in seen:
                    continue
                seen.add(cleaned)
                results.append(cleaned)
        results.sort()
        return results

    def _pick_service_host(self, http_block: dict, record: dict, root_data: dict) -> str:
        for candidate in (
            http_block.get("host"),
            record.get("hostnames"),
            root_data.get("hostnames"),
            record.get("domains"),
            root_data.get("domains"),
            root_data.get("ip_str"),
        ):
            if isinstance(candidate, str):
                cleaned = self._clean(candidate)
                if cleaned:
                    return cleaned
            if isinstance(candidate, list):
                for item in candidate:
                    cleaned = self._clean(item)
                    if cleaned:
                        return cleaned
        return ""

    def _build_service_url(self, host: str, port: object, has_http: bool, has_ssl: bool) -> str:
        host_clean = self._clean(host)
        port_clean = self._clean(port)
        if not host_clean or not port_clean:
            return ""
        try:
            port_int = int(port_clean)
        except ValueError:
            return ""
        if not has_http and not has_ssl:
            return ""
        scheme = "https" if has_ssl or port_int in {443, 8443, 9443} else "http"
        default_port = 443 if scheme == "https" else 80
        if port_int == default_port:
            return f"{scheme}://{host_clean}"
        return f"{scheme}://{host_clean}:{port_int}"

    def _build_location_entity(self, data: dict) -> Entity | None:
        city = self._clean(data.get("city"))
        region_code = self._clean(data.get("region_code"))
        country_name = self._clean(data.get("country_name"))
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        parts = [part for part in (city, region_code, country_name) if part]
        if not parts and not isinstance(latitude, (int, float)) and not isinstance(longitude, (int, float)):
            return None
        location_value = ", ".join(parts) if parts else self._clean(data.get("ip_str")) or "Unknown location"
        properties: dict[str, str | float] = {
            "city": city,
            "region_code": region_code,
            "country": country_name,
            "country_code": self._clean(data.get("country_code")),
            "postal_code": self._clean(data.get("postal_code")),
            "source": "shodan",
        }
        if isinstance(latitude, (int, float)):
            properties["lat"] = float(latitude)
        if isinstance(longitude, (int, float)):
            properties["lon"] = float(longitude)
        return Entity(type=EntityType.LOCATION, value=location_value, properties=properties, source=self.name)

    def _build_certificate_entity(self, ssl_block: dict) -> Entity | None:
        cert = ssl_block.get("cert") if isinstance(ssl_block.get("cert"), dict) else {}
        if not cert:
            return None
        subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
        issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}
        value = self._clean(subject.get("CN")) or self._clean(cert.get("serial")) or "Observed certificate"
        sans = cert.get("subjectAltName") if isinstance(cert.get("subjectAltName"), list) else []
        return Entity(
            type=EntityType.SSL_CERTIFICATE,
            value=value,
            properties={
                "subject": self._clean(subject.get("CN")),
                "issuer": self._clean(issuer.get("CN")),
                "serial_number": self._clean(cert.get("serial")),
                "fingerprint_sha1": self._clean(cert.get("fingerprint")),
                "fingerprint_sha256": self._clean(cert.get("fingerprint_sha256")),
                "issued": self._clean(cert.get("issued")),
                "expires": self._clean(cert.get("expires")),
                "sans": ", ".join(self._iter_clean_list(sans)),
                "source": "shodan",
            },
            source=self.name,
        )

    def _clean(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _join_list(self, value: object) -> str:
        return ", ".join(self._iter_clean_list(value))

    def _iter_clean_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        seen: set[str] = set()
        results: list[str] = []
        for item in value:
            cleaned = str(item).strip()
            if not cleaned:
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            results.append(cleaned)
        return results

    def _get_bool(self, raw: object) -> bool:
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))
