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

from transforms.document_to_phone_numbers import DocumentToPhoneNumbers


def _document(content: str, *, url: str = "https://example.com/team") -> Entity:
    return Entity(
        type=EntityType.DOCUMENT,
        value="Team page",
        properties={"content": content, "url": url},
        project_id=uuid4(),
        source="test",
    )


def test_document_to_phone_numbers_extracts_candidates() -> None:
    transform = DocumentToPhoneNumbers()
    entity = _document("Alice Example | Security Lead | Phone: (415) 555-0101")

    result = asyncio.run(transform.run(entity, TransformConfig(settings={"default_region": "US"})))

    assert len(result.entities) == 1
    phone = result.entities[0]
    assert phone.type == EntityType.PHONE_NUMBER
    assert phone.value == "+14155550101"
    assert phone.properties.get("observed_on_url") == "https://example.com/team"
    assert "Alice Example" in str(phone.properties.get("context_snippet"))
    assert any(edge.label == "observed phone" for edge in result.edges)


def test_document_to_phone_numbers_returns_message_when_empty() -> None:
    transform = DocumentToPhoneNumbers()
    entity = _document("")

    result = asyncio.run(transform.run(entity, TransformConfig(settings={})))

    assert result.entities == []
    assert result.edges == []
    assert result.messages == ["No phone numbers found in document content"]

