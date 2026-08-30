"""Dashboard API coverage for portable Project bundles."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from kiro_crew.dashboard import handlers_project
from kiro_crew.dashboard.handlers_project import (
    api_project_create,
    api_project_get,
    api_project_remove,
    api_project_update,
    api_projects_list,
)
from kiro_crew.dashboard.routes import connections
from kiro_crew.dashboard.state import _ChatSlot
from kiro_crew.history import ConversationLog
from kiro_crew.project_capabilities import ProjectCapabilityManager
from kiro_crew.project_manifest import (
    ProjectManifestError,
    create_project_manifest,
    load_project_manifest,
    project_manifest_revision,
)
from kiro_crew.project_registry import ProjectRegistry, ProjectRegistryError


def _request(
    app: web.Application,
    *,
    method: str = "GET",
    match_info: dict[str, str] | None = None,
    body: object | None = None,
    owner: bool = False,
):
    request = make_mocked_request(method, "/api/projects", app=app, match_info=match_info or {})
    if body is not None:
        request.json = AsyncMock(return_value=body)
    if owner:
        request["user"] = "local-app"
        request["app"] = ""
    return request


@pytest.fixture
def project_app(tmp_path):
    app = web.Application()
    app["state"] = SimpleNamespace(owner_id="")
    app["project_registry"] = ProjectRegistry(
        tmp_path / "data" / "projects",
        registry_dir=tmp_path / "data" / "trust" / "project-registry",
    )
    app["project_capability_manager"] = ProjectCapabilityManager(
        app["project_registry"],
        agents_dir=tmp_path / "kiro" / "agents",
        skills_dir=tmp_path / "data" / "skills",
        mcp_path=tmp_path / "data" / "mcp.json",
        trust_dir=tmp_path / "data" / "trust" / "project-bundles",
    )
    return app


@pytest.mark.asyncio
async def test_project_list_returns_bundle_identity_sources_and_health(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    review_key = project_app["project_capability_manager"].status(manifest.id).review_key

    response = await api_projects_list(_request(project_app, owner=True))

    assert response.status == 200
    assert json.loads(response.body) == {
        "projects": [
            {
                "id": manifest.id,
                "name": "Payments Platform",
                "description": "",
                "editable": {"name": "Payments Platform", "description": ""},
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
                "revision": project_manifest_revision(bundle),
                "registrations": [
                    {
                        "origin": "local",
                        "path": str(bundle),
                        "syncable": False,
                    }
                ],
                "health": {"status": "healthy", "code": "project_healthy"},
                "sessions": [],
                "capabilities": {
                    "active": False,
                    "review_key": review_key,
                    "agents": 0,
                    "skills": 0,
                    "mcp_servers": 0,
                    "repos": 0,
                    "repositories": [],
                    "agent_names": [],
                    "mcp_server_details": [],
                },
            }
        ]
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "match_info"),
    [
        (api_projects_list, None),
        (api_project_get, {"id": "018f4f4a-760f-7a8b-a5d4-5a7e0f130d4e"}),
    ],
)
async def test_project_reads_are_owner_only_because_they_return_local_paths(
    project_app, handler, match_info
):
    response = await handler(_request(project_app, match_info=match_info))

    assert response.status == 403
    assert json.loads(response.body)["code"] == "owner_only"


@pytest.mark.asyncio
async def test_project_owner_operation_fails_closed_when_permission_audit_is_unavailable(
    project_app, monkeypatch
):
    def audit_failure(**_kwargs):
        raise OSError("audit unavailable")

    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(log_api_access=audit_failure),
    )

    response = await api_projects_list(_request(project_app, owner=True))

    assert response.status == 503
    assert json.loads(response.body)["code"] == "project_audit_unavailable"


@pytest.mark.asyncio
async def test_project_get_reports_a_missing_materialization_without_hiding_project(
    project_app, tmp_path
):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    (bundle / "project.yaml").unlink()

    response = await api_project_get(
        _request(project_app, match_info={"id": manifest.id}, owner=True)
    )

    assert response.status == 200
    payload = json.loads(response.body)
    assert payload["id"] == manifest.id
    assert payload["health"] == {
        "status": "unavailable",
        "code": "project_manifest_unavailable",
    }
    assert payload["sources"] == []
    assert payload["sessions"] == []


@pytest.mark.asyncio
async def test_manifest_identity_mismatch_cannot_redirect_project_removal(project_app, tmp_path):
    first_bundle = tmp_path / "first"
    second_bundle = tmp_path / "second"
    first = create_project_manifest(first_bundle, name="First Project")
    second = create_project_manifest(second_bundle, name="Second Project")
    registry = project_app["project_registry"]
    registry.add_local(first_bundle)
    registry.add_local(second_bundle)
    manifest_path = first_bundle / "project.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace(first.id, second.id),
        encoding="utf-8",
    )

    response = await api_projects_list(_request(project_app, owner=True))
    projects = json.loads(response.body)["projects"]
    first_payload = next(
        project for project in projects if project["registrations"][0]["path"] == str(first_bundle)
    )

    assert first_payload["id"] == first.id
    assert first_payload["health"] == {
        "status": "unavailable",
        "code": "project_manifest_identity_mismatch",
    }

    remove = await api_project_remove(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": first_payload["id"]},
            owner=True,
        )
    )

    assert remove.status == 200
    assert registry.get(second.id).id == second.id
    with pytest.raises(ProjectRegistryError):
        registry.get(first.id)


@pytest.mark.asyncio
async def test_project_list_includes_live_and_historical_sessions(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    log = ConversationLog(base_dir=tmp_path / "sessions")
    log.init()
    await asyncio.to_thread(log.append, "dashboard:old-chat", "user", "Earlier work")
    await asyncio.to_thread(
        log.update_metadata,
        "dashboard:old-chat",
        {"title": "Earlier payment work", "project_id": manifest.id},
    )
    await asyncio.to_thread(log.append, "dashboard:private-chat", "user", "Private work")
    await asyncio.to_thread(
        log.update_metadata,
        "dashboard:private-chat",
        {"project_id": manifest.id, "memory_mode": "incognito"},
    )
    live = _ChatSlot("live-chat", title="Live payment work")
    live.project_id = manifest.id
    live.messages.append({"role": "user", "content": "Continue"})
    private = _ChatSlot("private-live", memory_mode="temporary")
    private.project_id = manifest.id
    project_app["state"] = SimpleNamespace(
        owner_id="",
        conversation_log=log,
        _slots={live.key: live, private.key: private},
    )

    response = await api_projects_list(_request(project_app, owner=True))

    sessions = json.loads(response.body)["projects"][0]["sessions"]
    assert {session["key"] for session in sessions} == {"old-chat", "live-chat"}
    live_payload = next(session for session in sessions if session["key"] == "live-chat")
    assert live_payload["live"] is True
    assert live_payload["running"] is False


@pytest.mark.asyncio
async def test_project_list_snapshots_live_slots_before_worker_offload(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    event_loop_thread = threading.get_ident()

    class EventLoopOnlySlots(dict):
        def values(self):
            assert threading.get_ident() == event_loop_thread
            return super().values()

    project_app["state"]._slots = EventLoopOnlySlots()

    list_response = await api_projects_list(_request(project_app, owner=True))
    detail_response = await api_project_get(
        _request(project_app, match_info={"id": manifest.id}, owner=True)
    )

    assert list_response.status == 200
    assert detail_response.status == 200
    assert json.loads(list_response.body)["projects"][0]["id"] == manifest.id
    assert json.loads(detail_response.body)["id"] == manifest.id


@pytest.mark.asyncio
async def test_project_owner_authorization_is_audited(project_app, monkeypatch):
    events: list[dict[str, object]] = []
    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(log_api_access=lambda **event: events.append(event)),
    )

    response = await api_projects_list(_request(project_app, owner=True))

    assert response.status == 200
    assert events == [
        {
            "caller": "local-app",
            "operation": "project_list",
            "outcome": "allowed",
            "source": "dashboard",
            "resources": "owner_dashboard",
        }
    ]


@pytest.mark.asyncio
async def test_project_create_persists_a_local_bundle(project_app, tmp_path):
    bundle = tmp_path / "new-project"

    response = await api_project_create(
        _request(
            project_app,
            method="POST",
            body={"name": "New Project", "path": str(bundle)},
            owner=True,
        )
    )

    assert response.status == 201
    payload = json.loads(response.body)
    assert payload["name"] == "New Project"
    assert payload["registrations"] == [{"origin": "local", "path": str(bundle), "syncable": False}]
    assert (bundle / "project.yaml").exists()
    assert project_app["project_registry"].get(payload["id"]).name == "New Project"


@pytest.mark.asyncio
async def test_project_create_resolves_the_local_path_off_the_event_loop(
    project_app, tmp_path, monkeypatch
):
    event_loop_thread = threading.get_ident()
    bundle = tmp_path / "new-project"

    class GuardedPath:
        def expanduser(self):
            return self

        def resolve(self):
            assert threading.get_ident() != event_loop_thread
            return bundle.resolve()

    monkeypatch.setattr(handlers_project, "Path", lambda _path: GuardedPath())

    response = await api_project_create(
        _request(
            project_app,
            method="POST",
            body={"name": "New Project", "path": str(bundle)},
            owner=True,
        )
    )

    assert response.status == 201


@pytest.mark.asyncio
async def test_project_create_rejects_missing_fields_with_a_machine_code(project_app):
    response = await api_project_create(
        _request(project_app, method="POST", body={"name": "Incomplete"}, owner=True)
    )

    assert response.status == 400
    assert json.loads(response.body) == {
        "error": "name and path must be non-empty strings",
        "code": "project_invalid_request",
    }


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="secure manifest replacement is POSIX-only")
async def test_project_update_persists_the_complete_editable_manifest(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    current = json.loads(
        (
            await api_project_get(_request(project_app, match_info={"id": manifest.id}, owner=True))
        ).body
    )

    response = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": current["revision"],
                "name": "Checkout Platform",
                "description": "Checkout services.",
                "workspace_source": "checkout-web",
                "sources": [
                    {
                        "id": "checkout-web",
                        "type": "repo",
                        "url": "https://github.com/acme/checkout-web",
                        "default_branch": "trunk",
                    }
                ],
                "context": {
                    "agents": ["agents/*.json"],
                    "skills": ["skills/"],
                    "mcp": "mcp.json",
                },
            },
        )
    )

    assert response.status == 200
    payload = json.loads(response.body)
    assert payload["id"] == manifest.id
    assert payload["name"] == "Checkout Platform"
    assert payload["workspace_source"] == "checkout-web"
    assert payload["sources"] == [
        {
            "id": "checkout-web",
            "type": "repo",
            "url": "https://github.com/acme/checkout-web",
            "default_branch": "trunk",
        }
    ]
    assert payload["context"] == {
        "agents": ["agents/*.json"],
        "skills": ["skills"],
        "mcp": "mcp.json",
    }
    assert payload["revision"] != current["revision"]
    assert payload["capabilities"]["active"] is False
    assert project_app["project_registry"].get(manifest.id).name == "Checkout Platform"


@pytest.mark.asyncio
async def test_project_update_rejects_a_stale_revision_without_overwriting(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    current = json.loads(
        (
            await api_project_get(_request(project_app, match_info={"id": manifest.id}, owner=True))
        ).body
    )
    manifest_path = bundle / "project.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace(
            "name: Payments Platform", "name: Externally Edited"
        ),
        encoding="utf-8",
    )

    response = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": current["revision"],
                "name": "Stale Editor",
                "description": "",
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
            },
        )
    )

    assert response.status == 409
    assert json.loads(response.body)["code"] == "project_manifest_conflict"
    assert load_project_manifest(bundle).name == "Externally Edited"


@pytest.mark.asyncio
async def test_project_update_validates_before_deactivating_capabilities(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)
    current = json.loads(
        (
            await api_project_get(_request(project_app, match_info={"id": manifest.id}, owner=True))
        ).body
    )

    response = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": current["revision"],
                "name": "",
                "description": "",
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
            },
        )
    )

    assert response.status == 400
    assert manager.status(manifest.id).active is True


@pytest.mark.asyncio
async def test_project_update_refuses_to_edit_an_active_project(project_app, tmp_path):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)
    revision = project_manifest_revision(bundle)

    response = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": revision,
                "name": "Checkout Platform",
                "description": "",
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
            },
        )
    )

    assert response.status == 409
    assert json.loads(response.body)["code"] == "project_active_edit_forbidden"
    assert load_project_manifest(bundle).name == "Payments Platform"
    assert manager.status(manifest.id).active is True


@pytest.mark.asyncio
async def test_project_update_refuses_when_unreadable_activation_state_remains(
    project_app, tmp_path
):
    bundle = tmp_path / "payments"
    manifest = create_project_manifest(bundle, name="Payments Platform")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.trust_dir.mkdir(parents=True)
    manager._state_path(manifest.id).write_text("{", encoding="utf-8")

    response = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": project_manifest_revision(bundle),
                "name": "Checkout Platform",
                "description": "",
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
            },
        )
    )

    assert response.status == 409
    assert load_project_manifest(bundle).name == "Payments Platform"
    assert manager._state_path(manifest.id).exists()


def test_project_source_dashboard_payload_redacts_nested_credentials():
    exfiltration_payload = "A" * 250
    value = {
        "nested": [
            "AKIAIOSFODNN7EXAMPLE",
            f"https://example.invalid/collect?data={exfiltration_payload}",
        ]
    }

    rendered = json.dumps(handlers_project._redact_json_value(value))

    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert exfiltration_payload not in rendered


@pytest.mark.asyncio
async def test_project_payload_redacts_manifest_display_text(project_app, tmp_path):
    bundle = tmp_path / "redacted"
    manifest = create_project_manifest(bundle, name="AKIAIOSFODNN7EXAMPLE")
    manifest_path = bundle / "project.yaml"
    exfiltration_payload = "A" * 250
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace(
            "description: ''",
            f"description: https://example.invalid/collect?data={exfiltration_payload}",
        ),
        encoding="utf-8",
    )
    project_app["project_registry"].add_local(bundle)

    response = await api_project_get(
        _request(project_app, match_info={"id": manifest.id}, owner=True)
    )

    payload = json.loads(response.body)
    assert "AKIAIOSFODNN7EXAMPLE" not in payload["name"]
    assert exfiltration_payload not in payload["description"]
    assert payload["editable"]["name"] == "AKIAIOSFODNN7EXAMPLE"
    assert exfiltration_payload in payload["editable"]["description"]


def test_project_bundle_routes_do_not_replace_the_legacy_task_project_api() -> None:
    app = web.Application()

    connections.register(app)

    handlers = {
        (route.method, route.resource.canonical): route.handler for route in app.router.routes()
    }
    assert handlers[("GET", "/api/projects")] is handlers_project.api_task_projects_list
    assert handlers[("PUT", "/api/projects/{id}")] is handlers_project.api_task_project_update
    assert handlers[("GET", "/api/project-bundles")] is handlers_project.api_projects_list
    assert handlers[("PATCH", "/api/project-bundles/{id}")] is handlers_project.api_project_update
    assert not any(path.startswith("/api/taskrunner/projects") for _method, path in handlers)


def test_dashboard_project_services_use_the_production_keystone_layout(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "data"))
    app = web.Application()
    request = _request(app)

    registry = handlers_project._registry(request)
    manager = handlers_project._capabilities(request)

    assert manager.registry.projects_dir == registry.projects_dir
    assert manager.registry.registry_dir == registry.registry_dir
    assert registry.projects_dir == tmp_path / "data" / "projects"
    assert registry.registry_dir == tmp_path / "data" / "trust" / "project-registry"


def test_dashboard_does_not_construct_project_services_before_socket_bind() -> None:
    from kiro_crew.dashboard.server import start_dashboard

    before_bind = inspect.getsource(start_dashboard).split("await _start_site", maxsplit=1)[0]

    assert "_create_project_services" not in before_bind


@pytest.mark.asyncio
async def test_dashboard_project_services_initialize_off_loop_once_after_registration(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "data"))
    app = web.Application()
    connections.register(app)
    services = app[handlers_project.PROJECT_SERVICES_KEY]
    main_thread = threading.get_ident()
    service_threads: list[int] = []
    real_get = services.get

    def tracked_get():
        service_threads.append(threading.get_ident())
        return real_get()

    monkeypatch.setattr(services, "get", tracked_get)
    request = _request(app)
    assert not (tmp_path / "data" / "projects").exists()

    await handlers_project._warm_project_services(request)

    assert service_threads
    assert all(thread_id != main_thread for thread_id in service_threads)
    first_registry = handlers_project._registry(request)
    first_manager = handlers_project._capabilities(request)
    assert handlers_project._registry(request) is first_registry
    assert handlers_project._capabilities(request) is first_manager


@pytest.mark.asyncio
async def test_project_payload_revision_matches_the_displayed_snapshot(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "snapshot"
    manifest = create_project_manifest(bundle, name="First Name")
    project_app["project_registry"].add_local(bundle)
    real_snapshot = handlers_project.load_project_manifest_snapshot
    manifest_path = bundle / "project.yaml"

    def snapshot_then_replace(path):
        snapshot = real_snapshot(path)
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8").replace("First Name", "Second Name"),
            encoding="utf-8",
        )
        return snapshot

    monkeypatch.setattr(handlers_project, "load_project_manifest_snapshot", snapshot_then_replace)

    response = await api_project_get(
        _request(project_app, match_info={"id": manifest.id}, owner=True)
    )
    payload = json.loads(response.body)
    update = await api_project_update(
        _request(
            project_app,
            method="PATCH",
            match_info={"id": manifest.id},
            owner=True,
            body={
                "revision": payload["revision"],
                "name": "Editor Name",
                "description": "",
                "workspace_source": "self",
                "sources": [],
                "context": {"agents": [], "skills": [], "mcp": ""},
            },
        )
    )

    assert payload["name"] == "First Name"
    assert update.status == 409
    assert load_project_manifest(bundle).name == "Second Name"


@pytest.mark.asyncio
async def test_project_add_registers_an_existing_local_bundle(project_app, tmp_path):
    bundle = tmp_path / "existing"
    manifest = create_project_manifest(bundle, name="Existing Project")

    response = await handlers_project.api_project_add(
        _request(project_app, method="POST", body={"source": str(bundle)}, owner=True)
    )

    assert response.status == 201
    payload = json.loads(response.body)
    assert payload["id"] == manifest.id
    assert payload["name"] == "Existing Project"
    assert project_app["project_registry"].get(manifest.id).registrations[0].path == bundle


@pytest.mark.asyncio
async def test_project_add_redacts_manifest_errors(project_app, tmp_path, monkeypatch):
    bundle = tmp_path / "invalid"
    bundle.mkdir()
    credential = "AKIAIOSFODNN7EXAMPLE"
    monkeypatch.setattr(
        project_app["project_capability_manager"],
        "register_local",
        lambda _path: (_ for _ in ()).throw(ProjectManifestError(f"invalid: {credential}")),
    )

    response = await handlers_project.api_project_add(
        _request(project_app, method="POST", body={"source": str(bundle)}, owner=True)
    )

    payload = json.loads(response.body)
    assert response.status == 400
    assert payload["code"] == "project_add_failed"
    assert credential not in payload["error"]


@pytest.mark.asyncio
async def test_project_sync_explains_that_a_local_bundle_is_not_syncable(project_app, tmp_path):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)

    response = await handlers_project.api_project_sync(
        _request(project_app, method="POST", match_info={"id": manifest.id}, owner=True)
    )

    assert response.status == 409
    assert json.loads(response.body) == {
        "error": f"Project {manifest.id} has no managed Git clone",
        "code": "project_not_syncable",
    }


@pytest.mark.asyncio
async def test_project_activation_requires_the_dashboard_owner(project_app, tmp_path):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)

    response = await handlers_project.api_project_activate(
        _request(
            project_app,
            method="POST",
            match_info={"id": manifest.id},
            body={"expected_key": "untrusted"},
        )
    )

    assert response.status == 403
    assert json.loads(response.body)["code"] == "owner_only"


@pytest.mark.asyncio
async def test_project_activation_materializes_after_review(project_app, tmp_path, monkeypatch):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    (bundle / "agents").mkdir()
    (bundle / "agents" / "reviewer.json").write_text('{"name":"reviewer"}', encoding="utf-8")
    project_yaml = (bundle / "project.yaml").read_text(encoding="utf-8")
    (bundle / "project.yaml").write_text(
        project_yaml.replace(
            "context:\n  agents: []\n  skills: []\n",
            "context:\n  agents: [agents/*.json]\n  skills: []\n",
        ),
        encoding="utf-8",
    )
    project_app["project_registry"].add_local(bundle)
    review_key = project_app["project_capability_manager"].status(manifest.id).review_key
    audit = AsyncMock()
    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **kwargs: None,
            log_governance_decision=lambda **kwargs: None,
        ),
    )
    monkeypatch.setattr(handlers_project, "_rebuild_agent_config", audit)

    response = await handlers_project.api_project_activate(
        _request(
            project_app,
            method="POST",
            match_info={"id": manifest.id},
            body={"expected_key": review_key},
            owner=True,
        )
    )

    assert response.status == 200
    payload = json.loads(response.body)
    assert payload["active"] is True
    assert payload["agents"] == 1
    assert (tmp_path / "kiro" / "agents" / f"project--{manifest.id}--reviewer.json").is_file()
    audit.assert_awaited_once()


@pytest.mark.asyncio
async def test_project_remove_withdraws_capabilities_but_preserves_bundle(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    (bundle / "agents").mkdir()
    (bundle / "agents" / "reviewer.json").write_text('{"name":"reviewer"}', encoding="utf-8")
    project_yaml = (bundle / "project.yaml").read_text(encoding="utf-8")
    (bundle / "project.yaml").write_text(
        project_yaml.replace(
            "context:\n  agents: []\n  skills: []\n",
            "context:\n  agents: [agents/*.json]\n  skills: []\n",
        ),
        encoding="utf-8",
    )
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)
    derived_state = manager.registry.projects_dir / "state" / manifest.id / "sources" / "repo"
    derived_state.mkdir(parents=True)
    (derived_state / "cached.txt").write_text("derived", encoding="utf-8")
    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **kwargs: None,
            log_governance_decision=lambda **kwargs: None,
        ),
    )
    rebuild = AsyncMock()
    monkeypatch.setattr(handlers_project, "_rebuild_agent_config", rebuild)

    response = await api_project_remove(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 200
    assert json.loads(response.body) == {"ok": True, "id": manifest.id}
    assert project_app["project_registry"].list_projects() == ()
    assert (bundle / "project.yaml").is_file()
    assert not (manager.registry.projects_dir / "state" / manifest.id).exists()
    assert not (tmp_path / "kiro" / "agents" / f"project--{manifest.id}--reviewer.json").exists()
    rebuild.assert_awaited_once()


def test_project_unregister_removes_the_crew_owned_managed_clone(project_app):
    registry = project_app["project_registry"]
    staging_bundle = registry.projects_dir / "staging-bundle"
    manifest = create_project_manifest(staging_bundle, name="Managed Project")
    expected_bundle = registry.projects_dir / "managed" / manifest.id / "bundle"
    expected_bundle.parent.mkdir(parents=True)
    staging_bundle.rename(expected_bundle)
    registry.add_managed(expected_bundle, remote="https://example.test/project.git")

    removed = project_app["project_capability_manager"].unregister(manifest.id)

    assert removed.id == manifest.id
    assert not expected_bundle.parent.exists()


@pytest.mark.asyncio
async def test_project_remove_refuses_to_orphan_an_unreadable_activation(project_app, tmp_path):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.trust_dir.mkdir(parents=True)
    manager._state_path(manifest.id).write_text("{", encoding="utf-8")

    response = await api_project_remove(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 409
    assert json.loads(response.body)["code"] == "project_remove_failed"
    assert project_app["project_registry"].get(manifest.id).id == manifest.id
    assert manager._state_path(manifest.id).is_file()


@pytest.mark.asyncio
async def test_project_remove_recovers_an_unavailable_registered_bundle(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "unavailable"
    manifest = create_project_manifest(bundle, name="Unavailable Project")
    project_app["project_registry"].add_local(bundle)
    (bundle / "project.yaml").unlink()
    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **kwargs: None,
            log_governance_decision=lambda **kwargs: None,
        ),
    )
    monkeypatch.setattr(handlers_project, "_rebuild_agent_config", AsyncMock())

    response = await api_project_remove(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 200
    assert bundle.is_dir()
    assert project_app["project_registry"].list_projects() == ()


@pytest.mark.asyncio
async def test_project_remove_requires_the_dashboard_owner(project_app, tmp_path):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)

    response = await api_project_remove(
        _request(project_app, method="DELETE", match_info={"id": manifest.id})
    )

    assert response.status == 403
    assert json.loads(response.body)["code"] == "owner_only"
    assert project_app["project_registry"].get(manifest.id).id == manifest.id


@pytest.mark.asyncio
async def test_project_deactivate_refuses_when_the_critical_audit_fails(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)

    def audit_failure(**_kwargs):
        raise OSError("audit unavailable")

    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **kwargs: None,
            log_governance_decision=audit_failure,
        ),
    )

    response = await handlers_project.api_project_deactivate(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 409
    assert json.loads(response.body)["code"] == "project_deactivation_failed"
    assert manager.status(manifest.id).active is True


@pytest.mark.asyncio
async def test_project_deactivate_records_its_own_governance_operation(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)
    decisions = []
    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **_kwargs: None,
            log_governance_decision=lambda **kwargs: decisions.append(kwargs),
        ),
    )
    monkeypatch.setattr(handlers_project, "_rebuild_agent_config", AsyncMock())

    response = await handlers_project.api_project_deactivate(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 200
    assert decisions[0]["tool_name"] == "project_deactivate"


@pytest.mark.asyncio
async def test_project_remove_refuses_when_the_critical_audit_fails(
    project_app, tmp_path, monkeypatch
):
    bundle = tmp_path / "local"
    manifest = create_project_manifest(bundle, name="Local Project")
    project_app["project_registry"].add_local(bundle)
    manager = project_app["project_capability_manager"]
    manager.activate(manifest.id, expected_key=manager.status(manifest.id).review_key)

    def audit_failure(**_kwargs):
        raise OSError("audit unavailable")

    monkeypatch.setattr(
        handlers_project,
        "_sel",
        lambda: SimpleNamespace(
            log_api_access=lambda **kwargs: None,
            log_governance_decision=audit_failure,
        ),
    )

    response = await api_project_remove(
        _request(
            project_app,
            method="DELETE",
            match_info={"id": manifest.id},
            owner=True,
        )
    )

    assert response.status == 409
    assert json.loads(response.body)["code"] == "project_remove_failed"
    assert project_app["project_registry"].get(manifest.id).id == manifest.id
    assert manager.status(manifest.id).active is True
