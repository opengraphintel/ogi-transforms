from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from uuid import uuid4

from ogi.models import Entity, EntityType
from ogi.transforms.base import TransformConfig

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from transforms.person_to_phone_numbers import PersonToPhoneNumbers


def _person(**properties: object) -> Entity:
    return Entity(
        type=EntityType.PERSON,
        value="Alice Example",
        properties=properties,
        project_id=uuid4(),
        source="test",
    )


def test_person_to_phone_numbers_scores_name_proximity() -> None:
    transform = PersonToPhoneNumbers()
    entity = _person(
        bio="Alice Example is the Security Lead at Example Corp. Reach her at (415) 555-0101 for conference logistics.",
        role="Security Lead",
        employer="Example Corp",
    )

    result = asyncio.run(transform.run(entity, TransformConfig(settings={"default_region": "US"})))

    assert len(result.entities) == 1
    phone = result.entities[0]
    assert phone.type == EntityType.PHONE_NUMBER
    assert phone.value == "+14155550101"
    assert phone.properties.get("matched_name") == "Alice Example"
    assert float(phone.properties.get("confidence", 0)) >= 0.7
    assert any(edge.label == "possible phone" for edge in result.edges)


def test_person_to_phone_numbers_uses_attached_url_sources(monkeypatch) -> None:
    transform = PersonToPhoneNumbers()
    entity = _person(
        profile_urls=["https://example.com/team/alice-example"],
        title="Security Lead",
    )

    async def fake_fetch(url: str) -> str:
        assert url == "https://example.com/team/alice-example"
        return "Alice Example, Security Lead, Example Corp. Direct line: +1 415 555 0101."

    monkeypatch.setattr(transform, "_fetch_url_text", fake_fetch)

    result = asyncio.run(transform.run(entity, TransformConfig(settings={"default_region": "US"})))

    assert len(result.entities) == 1
    phone = result.entities[0]
    assert phone.properties.get("observed_on_url") == "https://example.com/team/alice-example"
    assert phone.properties.get("observed_in") == "url_content"
    assert "name_proximity" in phone.properties.get("rationale", "")


def test_person_to_phone_numbers_filters_weak_generic_matches() -> None:
    transform = PersonToPhoneNumbers()
    entity = _person(
        notes="Main office: (415) 555-0199. General support queue for all visitors.",
    )

    result = asyncio.run(transform.run(entity, TransformConfig(settings={"default_region": "US", "min_confidence": "0.6"})))

    assert result.entities == []
    assert any("No sufficiently corroborated" in message for message in result.messages)
