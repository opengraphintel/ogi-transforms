import httpx

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

ONIONOO_DETAILS_URL = "https://onionoo.torproject.org/details"


class IPToTorRelay(BaseTransform):
    name = "ip_to_tor_relay"
    display_name = "IP to Tor Relay"
    description = "Checks whether an IP address is a Tor relay or exit node using Onionoo"
    input_types = [EntityType.IP_ADDRESS]
    output_types = [
        EntityType.IP_ADDRESS,
        EntityType.ORGANIZATION,
        EntityType.LOCATION,
        EntityType.AS_NUMBER,
    ]
    category = "IP Intelligence"
    settings = [
        TransformSetting(
            name="timeout_seconds",
            display_name="Timeout Seconds",
            description="HTTP timeout for the Onionoo lookup",
            default="15",
            field_type="integer",
            min_value=5,
            max_value=30,
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        ip = entity.value.strip()
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        if not ip:
            messages.append("IP value is empty")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        timeout_seconds = self._get_timeout_seconds(config)

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.get(
                    ONIONOO_DETAILS_URL,
                    params={"search": ip},
                    headers={"accept": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

            if not isinstance(data, dict):
                messages.append("Onionoo returned an unexpected response payload")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            relays = [r for r in (data.get("relays") or []) if isinstance(r, dict)]
            # Onionoo's search is a prefix match, so confirm the address really
            # belongs to the relay before claiming this IP runs Tor.
            relay = next((r for r in relays if ip in self._relay_addresses(r)), None)

            if relay is None:
                entities.append(entity.model_copy(update={
                    "properties": {**entity.properties, "tor_relay": False},
                }))
                messages.append(f"{ip} is not a known Tor relay in the current Onionoo data")
                return TransformResult(entities=entities, edges=edges, messages=messages)

            flags = [str(f) for f in (relay.get("flags") or []) if str(f).strip()]
            is_exit = "Exit" in flags
            exit_addresses = [str(a) for a in (relay.get("exit_addresses") or [])]
            country_name = self._clean(relay.get("country_name"))
            as_number = self._clean(relay.get("as"))
            as_name = self._clean(relay.get("as_name"))

            enriched: dict[str, str | int | float | bool | None] = {
                **entity.properties,
                "tor_relay": True,
                "tor_relay_nickname": self._clean(relay.get("nickname")),
                "tor_relay_fingerprint": self._clean(relay.get("fingerprint")),
                "tor_relay_flags": ", ".join(flags),
                "tor_is_exit_node": is_exit,
                "tor_is_guard_node": "Guard" in flags,
                "tor_relay_running": bool(relay.get("running")),
                "tor_relay_first_seen": self._clean(relay.get("first_seen")),
                "tor_relay_last_seen": self._clean(relay.get("last_seen")),
                "tor_relay_country": self._clean(relay.get("country")),
                "tor_relay_country_name": country_name,
                "tor_relay_as": as_number,
                "tor_relay_as_name": as_name,
                "tor_relay_platform": self._clean(relay.get("platform")),
                "tor_relay_version": self._clean(relay.get("version")),
                "tor_relay_contact": self._clean(relay.get("contact")),
                "tor_relay_observed_bandwidth": self._as_int(relay.get("observed_bandwidth")),
                "tor_relay_consensus_weight": self._as_int(relay.get("consensus_weight")),
                "tor_relay_exit_probability": self._as_float(relay.get("exit_probability")),
                "tor_relay_exit_addresses": ", ".join(exit_addresses),
            }
            entities.append(entity.model_copy(update={"properties": enriched}))

            if as_number:
                asn_entity = Entity(
                    type=EntityType.AS_NUMBER,
                    value=as_number,
                    properties={"as_name": as_name, "source": "onionoo"},
                    source=self.name,
                )
                entities.append(asn_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=asn_entity.id,
                    label="announced by",
                    source_transform=self.name,
                ))

            if as_name:
                org_entity = Entity(
                    type=EntityType.ORGANIZATION,
                    value=as_name,
                    properties={"source": "onionoo", "kind": "relay_host"},
                    source=self.name,
                )
                entities.append(org_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=org_entity.id,
                    label="relay hosted by",
                    source_transform=self.name,
                ))

            if country_name:
                location_entity = Entity(
                    type=EntityType.LOCATION,
                    value=country_name,
                    properties={"country": country_name, "source": "onionoo"},
                    source=self.name,
                )
                entities.append(location_entity)
                edges.append(Edge(
                    source_id=entity.id,
                    target_id=location_entity.id,
                    label="relay located in",
                    source_transform=self.name,
                ))

            role = "exit node" if is_exit else "relay"
            nickname = self._clean(relay.get("nickname")) or "unnamed"
            messages.append(f"{ip} is a Tor {role} ({nickname})")
            if flags:
                messages.append(f"Flags: {', '.join(flags)}")
            if relay.get("first_seen"):
                messages.append(f"First seen: {self._clean(relay.get('first_seen'))}")
            if not relay.get("running"):
                messages.append("Relay is currently listed as not running")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                messages.append(f"Onionoo rejected the query for {ip}")
            elif e.response.status_code == 429:
                messages.append("Onionoo rate limit exceeded")
            else:
                messages.append(f"Onionoo HTTP error: {e}")
        except httpx.RequestError as e:
            messages.append(f"Request error contacting Onionoo: {e}")
        except Exception as e:
            messages.append(f"Error during Tor relay lookup: {e}")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _relay_addresses(self, relay: dict) -> set[str]:
        """Collect every IP the relay publishes, stripped of ports and brackets."""
        addresses: set[str] = set()
        for raw in (relay.get("or_addresses") or []):
            addresses.add(self._strip_port(str(raw)))
        for raw in (relay.get("exit_addresses") or []):
            addresses.add(self._strip_port(str(raw)))
        return {a for a in addresses if a}

    @staticmethod
    def _strip_port(value: str) -> str:
        value = value.strip()
        if value.startswith("["):
            # IPv6 is published as [2001:db8::1]:9001
            end = value.find("]")
            return value[1:end] if end > 0 else value
        # IPv4 is published as 1.2.3.4:9001; bare IPv6 has many colons
        if value.count(":") == 1:
            return value.rsplit(":", 1)[0]
        return value

    @staticmethod
    def _clean(value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    @staticmethod
    def _as_int(value: object) -> int | None:
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_float(value: object) -> float | None:
        try:
            return float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    def _get_timeout_seconds(self, config: TransformConfig) -> float:
        raw_value = config.settings.get("timeout_seconds", 15)
        try:
            timeout = float(raw_value)
        except (TypeError, ValueError):
            return 15.0
        return max(5.0, min(timeout, 30.0))
