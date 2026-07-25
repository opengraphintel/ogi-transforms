import base64
import hashlib
import re

from ogi.models import Edge, Entity, EntityType, TransformResult
from ogi.transforms.base import BaseTransform, TransformConfig, TransformSetting

# v3 addresses are 56 base32 chars; the retired v2 scheme used 16.
ONION_PATTERN = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)

# Per rend-spec-v3: checksum = SHA3-256(".onion checksum" || pubkey || version)[:2]
CHECKSUM_SALT = b".onion checksum"
ONION_V3_VERSION = 3


class OnionAddressValidator(BaseTransform):
    name = "onion_address_validator"
    display_name = "Onion Address Validator"
    description = "Extracts .onion addresses from text and verifies their v3 checksums offline"
    input_types = [EntityType.DOCUMENT, EntityType.URL, EntityType.DOMAIN]
    output_types = [EntityType.URL]
    category = "Web"
    settings = [
        TransformSetting(
            name="max_results",
            display_name="Max Results",
            description="Maximum number of valid onion services to emit",
            default="50",
            field_type="integer",
            min_value=1,
            max_value=500,
        ),
        TransformSetting(
            name="emit_invalid",
            display_name="Report Invalid Addresses",
            description="Report addresses that failed validation as messages",
            default="true",
            field_type="boolean",
        ),
    ]

    async def run(self, entity: Entity, config: TransformConfig) -> TransformResult:
        entities: list[Entity] = []
        edges: list[Edge] = []
        messages: list[str] = []

        text = str(entity.properties.get("content") or entity.value or "").strip()
        if not text:
            messages.append("No text content to scan for onion addresses")
            return TransformResult(entities=entities, edges=edges, messages=messages)

        max_results = self._get_max_results(config)
        emit_invalid = self._get_emit_invalid(config)

        seen: set[str] = set()
        valid_count = 0
        invalid: list[str] = []
        legacy_v2: list[str] = []

        for match in ONION_PATTERN.finditer(text):
            address = f"{match.group(1)}.onion".lower()
            if address in seen:
                continue
            seen.add(address)

            label = match.group(1)
            if len(label) == 16:
                legacy_v2.append(address)
                continue

            ok, detail = self._validate_v3(label)
            if not ok:
                invalid.append(f"{address} ({detail})")
                continue

            if valid_count >= max_results:
                continue

            onion_entity = Entity(
                type=EntityType.URL,
                value=f"http://{address}",
                properties={
                    "onion_address": address,
                    "onion_version": 3,
                    "onion_public_key_hex": detail,
                    "checksum_valid": True,
                    "source": "onion_address_validator",
                },
                source=self.name,
            )
            entities.append(onion_entity)
            edges.append(Edge(
                source_id=entity.id,
                target_id=onion_entity.id,
                label="references onion service",
                source_transform=self.name,
            ))
            valid_count += 1

        messages.append(f"Valid v3 onion services: {valid_count}")
        if valid_count >= max_results and len(seen) > max_results:
            messages.append(f"Result cap of {max_results} reached; additional addresses were skipped")
        if legacy_v2:
            messages.append(
                f"Ignored {len(legacy_v2)} v2 address(es); v2 onion services were shut down in October 2021"
            )
        if invalid and emit_invalid:
            messages.append(f"Failed checksum validation: {len(invalid)}")
            for item in invalid[:10]:
                messages.append(f"  invalid: {item}")
        if not seen:
            messages.append("No .onion addresses found in the supplied text")

        return TransformResult(entities=entities, edges=edges, messages=messages)

    def _validate_v3(self, label: str) -> tuple[bool, str]:
        """Verify a v3 onion label's checksum. Returns (ok, pubkey hex or reason)."""
        try:
            raw = base64.b32decode(label.upper())
        except Exception:
            return False, "not valid base32"

        if len(raw) != 35:
            return False, f"decoded to {len(raw)} bytes, expected 35"

        pubkey, checksum, version = raw[:32], raw[32:34], raw[34]
        if version != ONION_V3_VERSION:
            return False, f"unsupported version byte {version}"

        expected = hashlib.sha3_256(
            CHECKSUM_SALT + pubkey + bytes([ONION_V3_VERSION])
        ).digest()[:2]
        if checksum != expected:
            return False, "checksum mismatch"

        return True, pubkey.hex()

    def _get_max_results(self, config: TransformConfig) -> int:
        return self.parse_int_setting(
            config.settings.get("max_results"),
            setting_name="max_results",
            default=50,
            min_value=1,
            declared_max=500,
        )

    def _get_emit_invalid(self, config: TransformConfig) -> bool:
        raw = str(config.settings.get("emit_invalid", "true")).strip().lower()
        return raw not in {"false", "0", "no", "off"}
