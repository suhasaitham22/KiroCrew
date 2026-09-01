"""Session-array MCP wiring: agent spec -> session/new mcpServers array.

A backend in ``ACP_BACKENDS_SESSION_MCP_ARRAY`` (claude-agent-acp today) receives
its MCP servers ONLY through the ``session/new`` / ``session/load`` parameter, so
these tests pin the shape the adapter's schema requires (``env``/``headers`` always arrays, an explicit transport ``type``) and
the mounting rules the kiro agent spec expresses (``tools`` references, the
registry pointer, Crew's own control plane).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from kiro_crew import agent as agent_mod
from kiro_crew.acp import client as client_mod
from kiro_crew.acp import session_mcp
from kiro_crew.acp.client import AcpClient
from kiro_crew.acp.types import ACP_BACKEND_CLAUDE

_CORE = {"command": "/opt/kirocrew", "args": ["mcp-core"]}
_CRON = {"command": "/opt/kirocrew", "args": ["mcp-cron"]}


@pytest.fixture
def agents_dir(tmp_path, monkeypatch):
    """Point the agent-spec resolver at a temp agents directory."""
    d = tmp_path / "agents"
    d.mkdir()
    monkeypatch.setattr(agent_mod, "KIRO_AGENTS_DIR", d)
    # Materialization would try to REBUILD the managed default from bundled
    # defaults; these tests supply the spec themselves.
    monkeypatch.setattr(session_mcp, "ensure_agent_materialized", lambda _a: True)
    monkeypatch.setattr(
        session_mcp,
        "managed_mcp_spec_entry",
        lambda name: {"kirocrew-core": dict(_CORE), "kirocrew-cron": dict(_CRON)}.get(name),
    )
    # Registry mode reads the effective config; pinned off (the default for a
    # personal install) so the symmetric filter is deterministic here. The tests
    # that care flip it explicitly.
    monkeypatch.setattr(session_mcp, "_mcp_registry_mode", lambda: False)
    return d


def _write_spec(agents_dir: Path, *, servers: dict, tools: list | None) -> None:
    spec: dict = {"name": "kirocrew", "mcpServers": servers}
    if tools is not None:
        spec["tools"] = tools
    (agents_dir / "kirocrew.json").write_text(json.dumps(spec), encoding="utf-8")


def _by_name(elements: list[dict]) -> dict[str, dict]:
    return {e["name"]: e for e in elements}


class TestElementShape:
    def test_stdio_entry_carries_env_array_and_explicit_type(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"foo": {"command": "/bin/foo", "args": ["--x"], "env": {"K": "v"}}},
            tools=["@foo"],
        )
        foo = _by_name(session_mcp.session_mcp_servers("kirocrew"))["foo"]
        assert foo == {
            "name": "foo",
            "command": "/bin/foo",
            "args": ["--x"],
            # An array, not a mapping, and PRESENT even when empty: the adapter's
            # schema requires it and rejects the whole session/new otherwise.
            "env": [{"name": "K", "value": "v"}],
            "type": "stdio",
        }

    def test_stdio_entry_without_env_still_emits_the_array(self, agents_dir):
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo"])
        foo = _by_name(session_mcp.session_mcp_servers("kirocrew"))["foo"]
        assert foo["env"] == []
        assert foo["args"] == []

    def test_non_string_env_and_args_are_stringified(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"foo": {"command": "/bin/foo", "args": [7], "env": {"PORT": 8080}}},
            tools=["@foo"],
        )
        foo = _by_name(session_mcp.session_mcp_servers("kirocrew"))["foo"]
        assert foo["env"] == [{"name": "PORT", "value": "8080"}]
        assert foo["args"] == ["7"]

    def test_url_entry_defaults_to_http_with_headers_array(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"remote": {"url": "https://example.test/mcp", "headers": {"A": "b"}}},
            tools=["@remote"],
        )
        remote = _by_name(session_mcp.session_mcp_servers("kirocrew"))["remote"]
        assert remote == {
            "name": "remote",
            # Without an explicit type the adapter routes the entry to its stdio
            # branch and rejects it for having no command.
            "type": "http",
            "url": "https://example.test/mcp",
            "headers": [{"name": "A", "value": "b"}],
        }

    def test_url_entry_keeps_sse_transport(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"remote": {"url": "https://example.test/sse", "type": "sse"}},
            tools=["@remote"],
        )
        remote = _by_name(session_mcp.session_mcp_servers("kirocrew"))["remote"]
        assert remote["type"] == "sse"
        assert remote["headers"] == []

    def test_entry_with_no_transport_is_skipped(self, agents_dir):
        _write_spec(agents_dir, servers={"broken": {"args": ["--x"]}}, tools=["@broken"])
        assert "broken" not in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_kiro_only_keys_are_not_forwarded(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={
                "foo": {
                    "command": "/bin/foo",
                    "timeout": 120,
                    "disabledTools": ["x"],
                    "autoApprove": ["y"],
                }
            },
            tools=["@foo"],
        )
        foo = _by_name(session_mcp.session_mcp_servers("kirocrew"))["foo"]
        # autoApprove above all: Claude's equivalent means Claude never asks, so
        # the call would never reach the host gate.
        assert set(foo) == {"name", "command", "args", "env", "type"}


class TestMounting:
    def test_server_not_referenced_by_tools_is_withheld(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"granted": {"command": "/bin/a"}, "ungranted": {"command": "/bin/b"}},
            tools=["@granted"],
        )
        names = _by_name(session_mcp.session_mcp_servers("kirocrew"))
        assert "granted" in names
        assert "ungranted" not in names

    def test_tool_scoped_reference_mounts_the_server(self, agents_dir):
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo/only_this"])
        assert "foo" in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_wildcard_reference_mounts_everything(self, agents_dir):
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["*"])
        assert "foo" in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_spec_without_tools_mounts_every_declared_server(self, agents_dir):
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=None)
        assert "foo" in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_at_wildcard_is_not_a_grant_all(self, agents_dir):
        # kiro documents `*`, `@builtin`, `@server` and `@server/tool` for
        # `tools`; `@*` parses as a server literally named `*`, so it mounts
        # NOTHING on kiro-cli. Reading it as grant-all here would mount every
        # declared server on this backend alone.
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@*"])
        assert "foo" not in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_registry_pointer_is_withheld_outside_registry_mode(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"governed": {"command": "/bin/ignored", "type": "registry"}},
            tools=["@governed"],
        )
        assert "governed" not in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_the_registry_filter_is_symmetric(self, agents_dir, monkeypatch):
        """In registry mode the UNMARKED entry is the one kiro-cli drops.

        Mirroring only half of kiro-cli's symmetric filter would invert the
        administrator's policy on this backend: withholding exactly the
        catalogued servers while launching the local ones kiro-cli refuses.
        """
        _write_spec(
            agents_dir,
            servers={
                "catalogued": {"command": "/bin/catalogued", "type": "registry"},
                "local_only": {"command": "/bin/local"},
            },
            tools=["@catalogued", "@local_only"],
        )
        monkeypatch.setattr(session_mcp, "_mcp_registry_mode", lambda: True)
        names = _by_name(session_mcp.session_mcp_servers("kirocrew"))
        assert "catalogued" in names
        assert "local_only" not in names

    def test_a_stubbed_server_yields_to_its_broker_stub(self, agents_dir):
        """The caller appends the stub under the SAME name; two would collide.

        Either the raw entry shadows the stub and the session bypasses the broker,
        or both register and every pooled backend runs twice (#927).
        """
        _write_spec(
            agents_dir,
            servers={"pooled": {"command": "/bin/raw"}, "direct": {"command": "/bin/direct"}},
            tools=["@pooled", "@direct"],
        )
        names = _by_name(
            session_mcp.session_mcp_servers("kirocrew", stub_server_names=frozenset({"pooled"}))
        )
        assert "pooled" not in names
        assert "direct" in names

    def test_a_stubbed_control_plane_server_also_yields(self, agents_dir):
        # The control plane is re-derived AFTER the registry filter, so the stub
        # drop has to run after that re-add or a pooled kirocrew-core comes back.
        names = _by_name(
            session_mcp.session_mcp_servers(
                "kirocrew", stub_server_names=frozenset({"kirocrew-core"})
            )
        )
        assert "kirocrew-core" not in names
        assert "kirocrew-cron" in names

    def test_registry_type_matches_the_spec_writer(self):
        # A rename in agent.py must not silently stop this filter from matching.
        assert session_mcp._KIRO_REGISTRY_TYPE == agent_mod._MCP_REGISTRY_TYPE


class TestDenyRules:
    def test_disabled_tools_become_deny_rules(self, agents_dir):
        # disabledTools is a RESTRICTION: dropping it while forwarding the server
        # it narrows would widen the session's tool surface behind the user's back.
        _write_spec(
            agents_dir,
            servers={"srv": {"command": "/bin/srv", "disabledTools": ["danger", "worse"]}},
            tools=["@srv"],
        )
        assert session_mcp.session_mcp_deny_rules("kirocrew") == [
            "mcp__srv__danger",
            "mcp__srv__worse",
        ]

    def test_no_disabled_tools_means_no_rules(self, agents_dir):
        _write_spec(agents_dir, servers={"srv": {"command": "/bin/srv"}}, tools=["@srv"])
        assert session_mcp.session_mcp_deny_rules("kirocrew") == []

    def test_malformed_spec_yields_no_rules(self, agents_dir):
        (agents_dir / "kirocrew.json").write_text("{not json", encoding="utf-8")
        assert session_mcp.session_mcp_deny_rules("kirocrew") == []
        assert session_mcp.session_mcp_deny_rules(None) == []


class TestControlPlane:
    def test_loaded_when_no_spec_exists(self, agents_dir):
        names = _by_name(session_mcp.session_mcp_servers("kirocrew"))
        assert set(names) == {"kirocrew-core", "kirocrew-cron"}
        assert names["kirocrew-core"]["args"] == ["mcp-core"]

    def test_loaded_when_the_spec_is_malformed(self, agents_dir):
        (agents_dir / "kirocrew.json").write_text("{not json", encoding="utf-8")
        assert set(_by_name(session_mcp.session_mcp_servers("kirocrew"))) == {
            "kirocrew-core",
            "kirocrew-cron",
        }

    def test_stale_spec_command_is_refreshed_from_the_managed_source(self, agents_dir):
        _write_spec(
            agents_dir,
            servers={"kirocrew-core": {"command": "/gone/kirocrew", "args": ["mcp-core"]}},
            tools=["@kirocrew-core"],
        )
        core = _by_name(session_mcp.session_mcp_servers("kirocrew"))["kirocrew-core"]
        assert core["command"] == "/opt/kirocrew"

    def test_a_spec_that_drops_the_reference_still_drops_the_server(self, agents_dir):
        # The refresh must not become a re-grant: kiro-cli would not mount a
        # server its tools list does not name, and neither may claude.
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo"])
        assert "kirocrew-core" not in _by_name(session_mcp.session_mcp_servers("kirocrew"))

    def test_no_agent_means_control_plane_only(self, agents_dir):
        assert set(_by_name(session_mcp.session_mcp_servers(None))) == {
            "kirocrew-core",
            "kirocrew-cron",
        }


class TestClientSeam:
    def test_kiro_backend_passes_no_array(self, tmp_path, agents_dir):
        client = AcpClient(work_dir=tmp_path)
        # kiro-cli receives the same servers via --agent; a duplicate here would
        # shadow the spec's own entries.
        assert client._session_mcp_servers() == []

    def test_claude_backend_translates_the_spec(self, tmp_path, agents_dir):
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo"])
        client = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CLAUDE)
        assert "foo" in _by_name(client._session_mcp_servers())

    def test_the_capability_set_is_what_decides(self, tmp_path, agents_dir, monkeypatch):
        """Membership drives the seam, not the harness's identity.

        The point of the capability set is that the next adapter which reads no
        agent spec joins it and works, with no edit here. Widening the set to
        kiro must therefore be enough to make the array populate -- if this
        passes only for claude, an identity branch has crept back in.
        """
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo"])
        client = AcpClient(work_dir=tmp_path, agent="kirocrew")
        assert client._session_mcp_servers() == []
        monkeypatch.setattr(
            client_mod, "ACP_BACKENDS_SESSION_MCP_ARRAY", frozenset({client.backend})
        )
        assert "foo" in _by_name(client._session_mcp_servers())

    def test_the_seam_hands_down_the_pooled_stub_names(self, tmp_path, agents_dir, monkeypatch):
        # The client owns the overlay, so it is the only layer that can answer
        # which servers will ALSO arrive as broker stubs.
        _write_spec(
            agents_dir,
            servers={"pooled": {"command": "/bin/raw"}, "direct": {"command": "/bin/direct"}},
            tools=["@pooled", "@direct"],
        )
        monkeypatch.setattr(
            client_mod, "injection_server_names", lambda _o, _a: frozenset({"pooled"})
        )
        client = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CLAUDE)
        names = _by_name(client._session_mcp_servers())
        assert "pooled" not in names
        assert "direct" in names

    def test_an_unreadable_overlay_does_not_cost_the_session_its_servers(
        self, tmp_path, agents_dir, monkeypatch
    ):
        # Empty is the safe direction: re-declaring a stubbed server lets the
        # injection outrank it, while withholding one nothing else supplies is a
        # session with missing tools.
        _write_spec(agents_dir, servers={"foo": {"command": "/bin/foo"}}, tools=["@foo"])

        def _boom(_o, _a):
            raise RuntimeError("overlay unreadable")

        monkeypatch.setattr(client_mod, "injection_server_names", _boom)
        client = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CLAUDE)
        assert "foo" in _by_name(client._session_mcp_servers())


class TestLocalSettingsSeed:
    def _client(self, tmp_path, **kw):
        return AcpClient(work_dir=tmp_path, acp_backend=ACP_BACKEND_CLAUDE, **kw)

    def test_seed_writes_the_model_allowlist(self, tmp_path):
        from kiro_crew import model_registry

        client = self._client(tmp_path)
        client._write_claude_local_settings()
        data = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        # Without the allowlist the adapter can collapse a versioned [1m] id back
        # to the 200K window.
        assert data["availableModels"] == model_registry.available_models("claude_code")

    def test_no_permission_mode_leaves_the_adapter_default(self, tmp_path):
        client = self._client(tmp_path)
        client._write_claude_local_settings()
        data = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        assert "permissions" not in data

    def test_permission_mode_is_written_when_requested(self, tmp_path):
        client = self._client(tmp_path, permission_mode="default")
        client._write_claude_local_settings()
        data = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        assert data["permissions"]["defaultMode"] == "default"

    def test_resolved_model_written_but_auto_omitted(self, tmp_path):
        auto = self._client(tmp_path)
        auto._write_claude_local_settings()
        path = tmp_path / ".claude" / "settings.local.json"
        assert "model" not in json.loads(path.read_text())
        pinned = self._client(tmp_path, model="claude-sonnet-4-5")
        pinned._write_claude_local_settings()
        assert json.loads(path.read_text())["model"] == "claude-sonnet-4-5"

    def test_user_settings_are_merged_and_restored(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        original = json.dumps({"permissions": {"allow": ["Bash(ls)"]}, "env": {"X": "1"}}, indent=2)
        path.write_text(original, encoding="utf-8")

        client = self._client(tmp_path, permission_mode="default")
        client._write_claude_local_settings()
        seeded = json.loads(path.read_text())
        # The user's keys survive the seed...
        assert seeded["permissions"]["allow"] == ["Bash(ls)"]
        assert seeded["env"] == {"X": "1"}
        assert seeded["permissions"]["defaultMode"] == "default"

        client._reset_state()
        # ...and the file is the user's own again afterwards, so no permission
        # mode outlives the session that asked for it.
        assert path.read_text() == original

    def test_a_file_crew_created_is_removed_on_reset(self, tmp_path):
        client = self._client(tmp_path)
        client._write_claude_local_settings()
        path = tmp_path / ".claude" / "settings.local.json"
        assert path.exists()
        client._reset_state()
        assert not path.exists()

    def test_an_inherited_bypass_mode_is_stripped_for_the_session(self, tmp_path):
        """bypassPermissions is the one mode that takes every call out of the gate.

        The adapter short-circuits its canUseTool callback for it, so nothing
        reaches the deny floor, the sensitive-path check or the governance
        ceiling. The base code swept this whole file on every reset for exactly
        that reason; preserving the user's file instead must not also preserve
        this value for the window Crew drives the session.
        """
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        original = json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}, indent=2)
        path.write_text(original, encoding="utf-8")

        client = self._client(tmp_path)
        client._write_claude_local_settings()
        assert "defaultMode" not in json.loads(path.read_text()).get("permissions", {})

        client._reset_state()
        # The user's own file is not edited -- only the session was protected.
        assert path.read_text() == original

    def test_an_explicit_mode_still_wins_over_an_inherited_bypass(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"permissions": {"defaultMode": "bypassPermissions"}}', encoding="utf-8")
        client = self._client(tmp_path, permission_mode="default")
        client._write_claude_local_settings()
        assert json.loads(path.read_text())["permissions"]["defaultMode"] == "default"

    def test_disabled_tools_reach_the_settings_deny_list(self, tmp_path, agents_dir):
        _write_spec(
            agents_dir,
            servers={"srv": {"command": "/bin/srv", "disabledTools": ["danger"]}},
            tools=["@srv"],
        )
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        # A deny rule the user wrote themselves must survive the merge.
        path.write_text('{"permissions": {"deny": ["Bash(rm)"]}}', encoding="utf-8")
        client = self._client(tmp_path, agent="kirocrew")
        client._write_claude_local_settings()
        assert json.loads(path.read_text())["permissions"]["deny"] == [
            "Bash(rm)",
            "mcp__srv__danger",
        ]

    def test_reset_stands_aside_while_another_session_still_holds_the_file(self, tmp_path):
        """Two claude sessions can share one work_dir (every keyless client does).

        Without the ownership check the first to reset deletes the file the
        second's adapter is configured from.
        """
        path = tmp_path / ".claude" / "settings.local.json"
        first = self._client(tmp_path)
        first._write_claude_local_settings()
        second = self._client(tmp_path, model="claude-sonnet-4-5")
        second._write_claude_local_settings()

        first._reset_state()
        # The second session's file is untouched: it owns the undo now.
        assert json.loads(path.read_text())["model"] == "claude-sonnet-4-5"
        second._reset_state()
        assert not path.exists()

    def test_the_last_session_out_restores_the_users_own_file(self, tmp_path):
        """The second claimant must not mistake the first one's seed for the original.

        A per-client snapshot got this wrong: the second session read the file
        AFTER the first had seeded it, so its reset wrote Crew's own settings
        back as if the user had authored them, leaving nothing that would ever
        remove them.
        """
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        original = json.dumps({"env": {"X": "1"}}, indent=2)
        path.write_text(original, encoding="utf-8")

        first = self._client(tmp_path)
        first._write_claude_local_settings()
        second = self._client(tmp_path, model="claude-sonnet-4-5")
        second._write_claude_local_settings()

        first._reset_state()
        assert "availableModels" in json.loads(path.read_text())
        second._reset_state()
        assert path.read_text() == original

    def test_a_user_edit_during_the_session_is_not_overwritten(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        client = self._client(tmp_path)
        client._write_claude_local_settings()
        path.write_text('{"env": {"MINE": "1"}}', encoding="utf-8")
        client._reset_state()
        assert path.read_text() == '{"env": {"MINE": "1"}}'

    def test_reset_without_a_seed_leaves_a_foreign_file_alone(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"permissions": {"allow": []}}', encoding="utf-8")
        client = self._client(tmp_path)
        client._reset_state()
        # Never seeded, so nothing here belongs to Crew to clean up.
        assert path.exists()

    def test_malformed_user_settings_do_not_block_the_seed(self, tmp_path):
        path = tmp_path / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        path.write_text("{not json", encoding="utf-8")
        client = self._client(tmp_path)
        client._write_claude_local_settings()
        assert "availableModels" in json.loads(path.read_text())
        client._reset_state()
        assert path.read_text() == "{not json"

    def test_seed_failure_does_not_break_the_spawn_path(self, tmp_path):
        client = self._client(tmp_path)
        with patch("kiro_crew.acp.client.atomic_write", side_effect=OSError("read-only")):
            with pytest.raises(OSError):
                client._write_claude_local_settings()
        # The caller (_spawn) swallows OSError; what matters is that the snapshot
        # was still taken, so reset does not leave a half-written file behind.
        assert client._claude_settings_captured is True
