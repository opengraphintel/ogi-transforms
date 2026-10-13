from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from ogi.models import Entity, EntityType
from ogi.transforms.base import TransformConfig

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from transforms.username_maigret import (  # noqa: E402
    AVAILABLE,
    CLAIMED,
    UNKNOWN,
    JsonObject,
    JsonValue,
    SiteDefinition,
    UsernameMaigret,
    build_site,
    evaluate_response,
    load_sites,
    parse_site_tags,
    render_urls,
    request_method,
    request_payload,
    select_sites,
)


def _site(name: str = "Example", **raw: JsonValue) -> SiteDefinition:
    data: JsonObject = {
        "urlMain": "https://example.com",
        "url": "{urlMain}/u/{username}",
    }
    data.update(raw)
    return build_site(name, data, {})


def _write_database(
    tmp_path: Path, sites: JsonObject, engines: JsonObject | None = None
) -> Path:
    path = tmp_path / "data.json"
    path.write_text(
        json.dumps({"sites": sites, "engines": engines or {}, "tags": []}),
        encoding="utf-8",
    )
    return path


def _username_entity(value: str = "alice") -> Entity:
    return Entity(
        type=EntityType.USERNAME, value=value, project_id=uuid4(), source="test"
    )


def test_engine_template_fills_fields_the_site_leaves_out(tmp_path: Path) -> None:
    path = _write_database(
        tmp_path,
        sites={
            "ForumA": {
                "engine": "Forum",
                "urlMain": "https://a.example",
                "absenceStrs": ["Account closed"],
            },
            "ForumB": {
                "engine": "Forum",
                "urlMain": "https://b.example",
                "checkType": "status_code",
            },
        },
        engines={
            "Forum": {
                "name": "Forum",
                "site": {
                    "checkType": "message",
                    "url": "{urlMain}{urlSubpath}/members/?username={username}",
                    "absenceStrs": ["member cannot be found"],
                    "presenseStrs": ["Joined"],
                },
            }
        },
    )

    sites = {site.name: site for site in load_sites(path)}

    forum_a = sites["ForumA"]
    assert forum_a.check_type == "message"
    assert forum_a.url == "{urlMain}{urlSubpath}/members/?username={username}"
    assert forum_a.absence_strs == ["Account closed", "member cannot be found"]
    assert forum_a.presence_strs == ["Joined"]
    assert render_urls(forum_a, "alice") == (
        "https://a.example/members/?username=alice",
        "https://a.example/members/?username=alice",
    )
    # A value the site states itself wins over the engine template.
    assert sites["ForumB"].check_type == "status_code"


def test_both_spellings_of_presence_and_absence_are_read() -> None:
    site = _site(
        presenseStrs=["Maigret spelling"],
        presenceStrs=["English spelling"],
        absenseStrs=["typo"],
    )

    assert site.presence_strs == ["Maigret spelling", "English spelling"]
    assert site.absence_strs == ["typo"]


def test_nested_keys_keep_their_original_spelling() -> None:
    site = _site(
        headers={"User-Agent": "curl/8.6.0"}, errors={"Please Log In": "Login required"}
    )

    assert site.headers == {"User-Agent": "curl/8.6.0"}
    assert site.errors == {"Please Log In": "Login required"}


def test_message_check_follows_maigret_rules() -> None:
    site = _site(
        checkType="message",
        presenseStrs=["profile-card"],
        absenceStrs=["User not found"],
    )

    assert evaluate_response(site, 200, "<div class='profile-card'>") == (CLAIMED, "")
    assert evaluate_response(site, 200, "<div class='profile-card'>User not found") == (
        AVAILABLE,
        "",
    )
    assert evaluate_response(site, 200, "<p>nothing here</p>") == (AVAILABLE, "")
    assert evaluate_response(site, 200, "") == (AVAILABLE, "")


def test_message_check_treats_a_generic_404_as_not_found() -> None:
    # Absence strings alone would call any page without them a claimed account.
    site = _site(checkType="message", absenceStrs=["User not found"])

    assert evaluate_response(site, 200, "<h1>alice</h1>") == (CLAIMED, "")
    assert evaluate_response(site, 404, "<h1>Not Found</h1>") == (AVAILABLE, "")
    assert evaluate_response(site, 410, "<h1>Gone</h1>") == (AVAILABLE, "")


def test_block_pages_and_refusals_are_unknown_not_available() -> None:
    site = _site(
        checkType="message",
        absenceStrs=["User not found"],
        errors={"Too many requests": "Rate limited"},
    )

    assert evaluate_response(site, 200, "<title>Just a moment...</title>") == (
        UNKNOWN,
        "Bot protection",
    )
    assert evaluate_response(site, 200, "Too many requests, slow down") == (
        UNKNOWN,
        "Site-specific: Rate limited",
    )
    assert evaluate_response(site, 403, "Forbidden") == (UNKNOWN, "Access denied")
    assert evaluate_response(site, 429, "") == (UNKNOWN, "Rate limited")
    assert evaluate_response(site, 503, "") == (UNKNOWN, "Server error")

    tolerant = _site(
        checkType="message", absenceStrs=["User not found"], ignore403=True
    )
    assert evaluate_response(tolerant, 403, "<h1>alice</h1>") == (CLAIMED, "")


def test_status_code_and_response_url_checks() -> None:
    by_status = _site(checkType="status_code")
    assert evaluate_response(by_status, 200, "")[0] == CLAIMED
    assert evaluate_response(by_status, 404, "")[0] == AVAILABLE

    by_redirect = _site(checkType="response_url", presenseStrs=["og:profile"])
    assert (
        evaluate_response(by_redirect, 200, '<meta property="og:profile">')[0]
        == CLAIMED
    )
    assert evaluate_response(by_redirect, 200, "<html></html>")[0] == AVAILABLE
    assert evaluate_response(by_redirect, 302, "")[0] == AVAILABLE


def test_selection_drops_unusable_sites_and_ranks_the_rest() -> None:
    sites = [
        _site("Ranked", checkType="status_code", alexaRank=5),
        _site("Unranked", checkType="status_code"),
        _site("Top", checkType="status_code", alexaRank=1),
        _site("ClaimsEverything", checkType="message"),
        _site("Disabled", checkType="status_code", disabled=True, alexaRank=2),
        _site("TorOnly", checkType="status_code", protocol="tor", alexaRank=3),
        _site(
            "Protected",
            checkType="status_code",
            protection=["tls_fingerprint"],
            alexaRank=4,
        ),
        _site("OtherIdentifier", checkType="status_code", type="gaia_id", alexaRank=1),
    ]

    selection = select_sites(
        sites, top_sites=10, include_disabled=False, include_protected=False
    )
    assert [site.name for site in selection.sites] == ["Top", "Ranked", "Unranked"]
    assert selection.protected_skipped == 1

    widened = select_sites(
        sites, top_sites=10, include_disabled=True, include_protected=True
    )
    assert [site.name for site in widened.sites] == [
        "Top",
        "Disabled",
        "Protected",
        "Ranked",
        "Unranked",
    ]

    capped = select_sites(
        sites, top_sites=1, include_disabled=False, include_protected=False
    )
    assert [site.name for site in capped.sites] == ["Top"]
    assert capped.protected_skipped == 0


def test_tags_select_by_site_tag_or_engine_name() -> None:
    sites = [
        _site("Board", checkType="status_code", tags=["forum", "de"]),
        _site("Wiki", checkType="status_code", tags=["wiki"]),
        _site("Discourse", checkType="status_code", engine="DiscourseJson"),
    ]

    def names(raw: str) -> list[str]:
        selection = select_sites(
            sites,
            top_sites=10,
            include_disabled=False,
            include_protected=False,
            tags=parse_site_tags(raw),
        )
        return sorted(site.name for site in selection.sites)

    assert names("forum") == ["Board"]
    assert names("Wiki, discoursejson") == ["Discourse", "Wiki"]
    assert names("") == ["Board", "Discourse", "Wiki"]


def test_url_rendering_quotes_usernames_and_appends_params() -> None:
    site = _site(
        url="{urlMain}{urlSubpath}/u/{username}",
        urlSubpath="/forum",
        urlProbe="{urlMain}/api/users/{username}.json",
        getParams={"format": "json"},
    )

    assert render_urls(site, "a b") == (
        "https://example.com/forum/u/a%20b",
        "https://example.com/api/users/a%20b.json?format=json",
    )
    assert render_urls(_site(url="{urlMain}/u/{nickname}"), "alice") is None


def test_post_payload_is_formatted_like_maigret() -> None:
    graphql = _site(
        requestMethod="POST",
        requestPayload={
            "query": '{{ matchedUser(username: "{username}") {{ username }} }}',
            "page_size": 5,
        },
    )

    assert request_method(graphql) == "POST"
    assert request_payload(graphql, "alice") == {
        "query": '{ matchedUser(username: "alice") { username } }',
        "page_size": 5,
    }
    assert request_payload(_site(requestPayload={"q": "{unknown}"}), "alice") is None


def test_run_reports_claimed_accounts_and_skips_what_it_cannot_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sites = (
        _site(
            "Found",
            url="https://found.example/{username}",
            checkType="message",
            presenseStrs=["Joined"],
            alexaRank=1,
        ),
        _site(
            "Missing",
            url="https://missing.example/{username}",
            checkType="message",
            absenceStrs=["No such user"],
            alexaRank=2,
        ),
        _site(
            "Blocked",
            url="https://blocked.example/{username}",
            checkType="status_code",
            alexaRank=3,
        ),
        _site(
            "DigitsOnly",
            url="https://digits.example/{username}",
            checkType="status_code",
            regexCheck="^[0-9]+$",
            alexaRank=4,
        ),
        _site(
            "Api",
            url="https://api.example/u/{username}",
            urlProbe="https://api.example/graphql",
            checkType="message",
            absenceStrs=['"user":null'],
            requestMethod="POST",
            requestPayload={"username": "{username}"},
            alexaRank=5,
        ),
        _site(
            "Shielded",
            url="https://shielded.example/{username}",
            checkType="status_code",
            protection=["cf_js_challenge"],
            alexaRank=6,
        ),
    )
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        host = request.url.host
        if host == "found.example":
            return httpx.Response(200, text="<p>Joined 2019</p>")
        if host == "missing.example":
            return httpx.Response(200, text="<p>No such user</p>")
        if host == "blocked.example":
            return httpx.Response(200, text="<title>Just a moment...</title>")
        if host == "api.example":
            assert request.method == "POST"
            assert json.loads(request.content) == {"username": "alice"}
            return httpx.Response(200, json={"user": {"name": "alice"}})
        return httpx.Response(404)

    transform = UsernameMaigret()
    monkeypatch.setattr(transform, "_site_database", lambda: sites)
    monkeypatch.setattr(
        transform,
        "_build_client",
        lambda *, timeout_seconds, concurrency: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
    )

    source = _username_entity("alice")
    result = asyncio.run(transform.run(source, TransformConfig(settings={})))

    social = [
        entity for entity in result.entities if entity.type == EntityType.SOCIAL_MEDIA
    ]
    urls = [entity for entity in result.entities if entity.type == EntityType.URL]
    assert sorted(entity.value for entity in social) == ["alice@Api", "alice@Found"]
    assert sorted(entity.value for entity in urls) == [
        "https://api.example/u/alice",
        "https://found.example/alice",
    ]
    assert all(entity.properties["maigret_version"] for entity in social)
    assert len(result.edges) == 4
    assert {edge.source_id for edge in result.edges if edge.label == "has account"} == {
        source.id
    }

    assert "https://digits.example/alice" not in requested
    assert "https://shielded.example/alice" not in requested
    assert any(
        "Skipped 1 bot-protected sites" in message for message in result.messages
    )
    assert any(
        "found=2, not_found=1, unknown=1, skipped=1" in message
        and "Bot protection 1" in message
        for message in result.messages
    )


def test_run_rejects_input_without_a_username() -> None:
    entity = Entity(
        type=EntityType.PERSON,
        value="Dr. Jane O'Neil",
        project_id=uuid4(),
        source="test",
    )

    result = asyncio.run(UsernameMaigret().run(entity, TransformConfig(settings={})))

    assert result.entities == []
    assert "did not contain a usable username" in result.messages[0]


def test_vendored_database_is_usable() -> None:
    sites = load_sites()
    by_name = {site.name: site for site in sites}
    assert len(sites) > 5000

    selectable = select_sites(
        sites, top_sites=len(sites), include_disabled=True, include_protected=True
    ).sites
    assert len(selectable) > 4500
    for site in selectable:
        assert render_urls(site, "alice") is not None, site.name
        if site.request_payload:
            assert request_payload(site, "alice") is not None, site.name

    # Engine templates must reach the sites that rely on them.
    assert by_name["GitHubGist"].check_type == "response_url"
    discourse = [site for site in sites if site.engine == "DiscourseJson"]
    assert discourse and all(site.url and site.url_probe for site in discourse)


def test_vendored_regex_checks_compile() -> None:
    for site in load_sites():
        if site.regex_check:
            re.compile(site.regex_check)
