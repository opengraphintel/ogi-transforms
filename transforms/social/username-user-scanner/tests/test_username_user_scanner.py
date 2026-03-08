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

from transforms.username_user_scanner import UsernameUserScanner


def _entity(value: str = "alice") -> Entity:
    return Entity(
        type=EntityType.SOCIAL_MEDIA,
        value=value,
        project_id=uuid4(),
        source="test",
    )


def _username_entity(value: str = "alice") -> Entity:
    return Entity(
        type=EntityType.USERNAME,
        value=value,
        project_id=uuid4(),
        source="test",
    )


def _email_entity(value: str = "alice@example.com") -> Entity:
    return Entity(
        type=EntityType.EMAIL_ADDRESS,
        value=value,
        project_id=uuid4(),
        source="test",
    )


def test_run_maps_found_results(monkeypatch) -> None:
    transform = UsernameUserScanner()

    async def fake_scan(identifier: str, scope: str, *, is_email: bool):
        assert identifier == "alice"
        assert is_email is False
        return [
            {
                "username": identifier,
                "category": "Social",
                "site_name": "GitHub",
                "status": "Found",
                "url": "https://github.com/alice",
                "reason": "",
            },
            {
                "username": identifier,
                "category": "Social",
                "site_name": "Reddit",
                "status": "Not Found",
                "url": "https://reddit.com/user/alice",
                "reason": "",
            },
        ]

    monkeypatch.setattr(transform, "_scan_identifier", fake_scan)

    result = asyncio.run(
        transform.run(
            _entity(),
            TransformConfig(settings={"scan_scope": "social", "only_found": "true", "max_results": "10"}),
        )
    )

    assert len(result.entities) == 2
    assert len(result.edges) == 2
    assert any(e.type == EntityType.SOCIAL_MEDIA for e in result.entities)
    assert any(e.type == EntityType.URL for e in result.entities)
    assert any("found=1" in msg for msg in result.messages)


def test_run_respects_max_results(monkeypatch) -> None:
    transform = UsernameUserScanner()

    async def fake_scan(identifier: str, scope: str, *, is_email: bool):
        return [
            {"site_name": "GitHub", "status": "Found", "url": "https://github.com/alice"},
            {"site_name": "Reddit", "status": "Found", "url": "https://reddit.com/user/alice"},
        ]

    monkeypatch.setattr(transform, "_scan_identifier", fake_scan)

    result = asyncio.run(
        transform.run(_entity(), TransformConfig(settings={"max_results": "1", "only_found": "true"}))
    )

    social_entities = [e for e in result.entities if e.type == EntityType.SOCIAL_MEDIA]
    url_entities = [e for e in result.entities if e.type == EntityType.URL]
    assert len(social_entities) == 1
    assert len(url_entities) == 1


def test_run_handles_scan_failure(monkeypatch) -> None:
    transform = UsernameUserScanner()

    async def fake_scan(identifier: str, scope: str, *, is_email: bool):
        raise RuntimeError("boom")

    monkeypatch.setattr(transform, "_scan_identifier", fake_scan)

    result = asyncio.run(transform.run(_entity(), TransformConfig(settings={})))
    assert result.entities == []
    assert any("Username scan failed" in msg for msg in result.messages)


def test_run_accepts_username_entity(monkeypatch) -> None:
    transform = UsernameUserScanner()

    async def fake_scan(identifier: str, scope: str, *, is_email: bool):
        assert identifier == "alice"
        assert is_email is False
        return [{"site_name": "GitHub", "status": "Found", "url": "https://github.com/alice"}]

    monkeypatch.setattr(transform, "_scan_identifier", fake_scan)

    result = asyncio.run(
        transform.run(_username_entity(), TransformConfig(settings={"only_found": "true"}))
    )

    assert any(e.type == EntityType.SOCIAL_MEDIA for e in result.entities)
    assert any("found=1" in msg for msg in result.messages)


def test_run_accepts_email_entity(monkeypatch) -> None:
    transform = UsernameUserScanner()

    async def fake_scan(identifier: str, scope: str, *, is_email: bool):
        assert identifier == "alice@example.com"
        assert is_email is True
        return [
            {
                "email": identifier,
                "site_name": "GitHub",
                "status": "Registered",
                "url": "https://github.com",
            },
        ]

    monkeypatch.setattr(transform, "_scan_identifier", fake_scan)

    result = asyncio.run(
        transform.run(_email_entity(), TransformConfig(settings={"only_found": "true"}))
    )

    social_entities = [e for e in result.entities if e.type == EntityType.SOCIAL_MEDIA]
    assert social_entities
    assert social_entities[0].value == "GitHub registration (alice@example.com)"
    assert social_entities[0].properties.get("input_is_email") is True
    assert any(edge.label == "registered on" for edge in result.edges)


def test_scan_identifier_dispatches_email(monkeypatch) -> None:
    transform = UsernameUserScanner()

    def fake_email(identifier: str, scope: str):
        assert identifier == "alice@example.com"
        assert scope == "all"
        return [{"status": "Registered"}]

    def fail_user(identifier: str, scope: str):
        raise AssertionError("username path should not be used for email input")

    monkeypatch.setattr(transform, "_scan_email_scope", fake_email)
    monkeypatch.setattr(transform, "_scan_username_scope", fail_user)

    result = asyncio.run(transform._scan_identifier("alice@example.com", "all", is_email=True))
    assert result == [{"status": "Registered"}]


def test_scan_identifier_dispatches_username(monkeypatch) -> None:
    transform = UsernameUserScanner()

    def fail_email(identifier: str, scope: str):
        raise AssertionError("email path should not be used for username input")

    def fake_user(identifier: str, scope: str):
        assert identifier == "alice"
        assert scope == "all"
        return [{"status": "Found"}]

    monkeypatch.setattr(transform, "_scan_email_scope", fail_email)
    monkeypatch.setattr(transform, "_scan_username_scope", fake_user)

    result = asyncio.run(transform._scan_identifier("alice", "all", is_email=False))
    assert result == [{"status": "Found"}]
