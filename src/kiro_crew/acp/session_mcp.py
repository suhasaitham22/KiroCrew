"""Kiro agent spec -> the ACP ``session/new`` ``mcpServers`` array.

For a harness in :data:`~kiro_crew.acp_backends.ACP_BACKENDS_SESSION_MCP_ARRAY`,
the ``session/new`` / ``session/load`` ``mcpServers`` parameter is where MCP
servers come from and the only place: claude-agent-acp, its one member today,
does not read ``~/.kiro/agents/<name>.json``. kiro-cli reaches the same servers
through ``--agent``, which is why that backend passes no array at all. Without
the translation here such a session runs with ZERO Kiro Crew tools -- the harness
itself works (prompts, streaming, permissions) but ``send_message``,
``spawn_run``, ``cron_add`` and every user-installed server are simply absent.

Nothing here is Anthropic-specific by design: the module is keyed on the
capability, not on the harness, so the next adapter that reads no agent spec
joins the set rather than growing a second translator.

The agent spec stays the single source of truth; there is no second,
claude-shaped registry to keep in sync. It is read per spawn, so installing or
toggling an MCP server takes effect on the NEXT session with no gateway restart.
Nothing here raises: a missing or malformed spec degrades to Crew's own control
plane, never to a failed spawn.

Shape notes -- these are claude-agent-acp's zod schema rather than anything in
the ACP spec at large:

* ``env`` (stdio) and ``headers`` (http/sse) are REQUIRED arrays of
  ``{"name", "value"}`` objects. Omitting either fails ``session/new`` outright
  with ``-32602 Invalid params (expected array, received undefined)``, so they
  are always emitted -- empty when there is nothing to carry.
* A url-bearing entry is routed by ``type``. Without one the adapter takes the
  stdio branch and rejects the entry for having no ``command``, so the transport
  is always spelled out.
* kiro-cli-only keys (``timeout``, ``disabledTools``, ``autoApprove``) cannot
  ride along in an element. ``disabledTools`` is a RESTRICTION, so dropping it
  outright would widen the tool surface; it comes back as a
  ``permissions.deny`` rule instead (see :func:`session_mcp_deny_rules`).
  ``autoApprove`` is dropped deliberately, not for want of a mapping:
  Claude's nearest equivalent is a ``permissions.allow`` entry, and a
  pre-approved tool is one Claude never asks about -- so the call never reaches
  the host ``canUseTool`` gate that carries the deny floor, the sensitive-path
  check and the governance ceiling. Every MCP call on this backend is gated.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection
from typing import Any

from kiro_crew.agent import (
    _mcp_registry_mode,
    agent_spec_path,
    ensure_agent_materialized,
    managed_mcp_spec_entry,
)
from kiro_crew.agent_discovery import _read_agent_spec

logger = logging.getLogger(__name__)

# Crew's own control plane. Re-derived from the managed source of truth on every
# spawn so a stale hand-edited command in the spec cannot cost a claude session
# the tools it needs to report back to its channel at all. Both are always-on
# (no gate, not opt_in), so ``managed_mcp_spec_entry`` returns them unless the
# install is broken.
_CONTROL_PLANE_SERVERS = ("kirocrew-core", "kirocrew-cron")

# kiro-cli's enterprise-governance discriminator, mirrored rather than imported
# (``agent._MCP_REGISTRY_TYPE`` is private; a ratchet test pins the two equal).
_KIRO_REGISTRY_TYPE = "registry"

# ``tools`` entries that grant every MCP server rather than naming one. Only the
# bare ``*`` -- kiro's configuration reference documents ``*``, ``@builtin``,
# ``@server`` and ``@server/tool`` for ``tools`` and reserves globs for
# ``allowedTools``, and this repo's own reader (``connections.tool_aliases``)
# parses ``@*`` as a server LITERALLY named ``*``. Treating ``@*`` as grant-all
# here would mount every declared server on this backend while kiro-cli mounted
# none of them.
_GRANT_ALL_TOOL_REFS = frozenset({"*"})


def _acp_pairs(raw: Any) -> list[dict[str, str]]:
    """A kiro-agent-JSON ``env``/``headers`` mapping in ACP's array-of-pairs form.

    Values are stringified because the adapter's schema types them as strings
    while the agent spec is hand-editable JSON, where a port number or a boolean
    is an easy thing to write.
    """
    if not isinstance(raw, dict):
        return []
    return [{"name": str(k), "value": str(v)} for k, v in raw.items()]


def acp_server_element(name: str, spec: Any) -> dict[str, Any] | None:
    """One ``mcpServers`` entry as a claude-agent-acp array element.

    ``None`` when the entry declares no usable transport -- neither a ``url`` nor
    a ``command``. Skipping is the right outcome there: an element the adapter
    rejects fails the whole ``session/new``, taking every other server with it.
    """
    if not isinstance(spec, dict):
        return None
    url = spec.get("url")
    if isinstance(url, str) and url:
        # Only ``sse`` is distinguished; anything else (including a missing
        # ``type``) is streamable HTTP, which is the adapter's own default and
        # the shape every modern remote server speaks.
        stype = "sse" if spec.get("type") == "sse" else "http"
        return {
            "name": name,
            "type": stype,
            "url": url,
            "headers": _acp_pairs(spec.get("headers")),
        }
    command = spec.get("command")
    if not isinstance(command, str) or not command:
        logger.debug("session MCP: skipping %r -- entry declares no command and no url", name)
        return None
    args = [
        a if isinstance(a, str) else json.dumps(a, sort_keys=True, default=str)
        for a in (spec.get("args") or [])
    ]
    return {
        "name": name,
        "command": command,
        "args": args,
        "env": _acp_pairs(spec.get("env")),
        "type": "stdio",
    }


def _tools_grant(tools: list[Any], name: str) -> bool:
    """True when a spec's ``tools`` list mounts MCP server *name*.

    kiro-cli loads a server only when ``tools`` references it (``@server`` or
    ``@server/tool``), so an ``mcpServers`` entry with no reference is declared
    but never mounted. The claude array has no such indirection -- everything in
    it is mounted -- so the reference is applied here instead. Without this, an
    entry the user deliberately left unreferenced (the shape every ``opt_in``
    grant uses, and what a narrowed-by-hand spec looks like) would come alive the
    moment the session happened to run on claude.
    """
    ref = f"@{name}"
    prefix = f"{ref}/"
    for item in tools:
        if not isinstance(item, str):
            continue
        if item in _GRANT_ALL_TOOL_REFS or item == ref or item.startswith(prefix):
            return True
    return False


def _agent_spec_for(agent: str) -> dict[str, Any] | None:
    """The materialized kiro spec for *agent*, or ``None`` when unreadable.

    Materializes first: a source checkout that skipped setup has no spec on disk
    at all, and the claude spawn path -- unlike kiro-cli's ``--agent`` one -- has
    no other reason to write it. Best-effort and never raises.

    Reads through ``agent_discovery._read_agent_spec``, the module's documented
    ONE reader, rather than parsing the file here: the agents directory is
    user-writable and shared with other tools, so the guards it applies are the
    point -- a symlink whose resolved target is sensitive
    (``kirocrew.json -> ~/.aws/credentials``) is refused and audited, an oversized
    file is refused at the size cap instead of being read into memory during a
    spawn, and non-UTF-8 bytes or non-object JSON come back as ``None``. The
    labels name THIS surface so a refusal is attributed to the session-MCP
    translation rather than to an unrelated agent listing (#6722); ``source`` is
    ``"unknown"`` because a session is started from every channel Crew has.
    """
    ensure_agent_materialized(agent)
    try:
        path = agent_spec_path(agent)
    except ValueError:
        # Two specs declare this name, so which one is live is undefined. No
        # answer is the honest one; the control plane still loads below.
        logger.warning("session MCP: ambiguous agent spec for %r", agent, exc_info=True)
        return None
    if path is None:
        logger.info(
            "session MCP: no spec on disk for agent %r; loading Crew's control plane only", agent
        )
        return None
    return _read_agent_spec(path, operation="session_mcp_servers", source="unknown")


def session_mcp_deny_rules(agent: str | None) -> list[str]:
    """Claude ``permissions.deny`` rules re-applying the spec's per-TOOL narrowing.

    ``disabledTools`` is a kiro-cli-only key, so it cannot ride along in the
    array element -- but it is a RESTRICTION, and dropping a restriction while
    forwarding the server that carries it widens the session's tool surface
    behind the user's back. The dashboard writes that key when someone turns an
    individual tool off, and the repo already treats losing it as a defect
    elsewhere ("dropping ``disabledTools`` on a save would silently widen the
    agent's tool surface"). Claude has no per-server allowlist, but it does have
    ``permissions.deny``, which is evaluated ahead of every allow rule and of the
    host callback, so the disabled tool is refused rather than merely asked
    about.

    Returned as rules for the settings writer rather than applied here: this
    module owns the array, ``settings.local.json`` belongs to the client. Ordered
    and de-duplicated so a re-seed produces a byte-identical file.

    Note the asymmetry this does NOT close: a ``tools`` reference of the
    ``@server/tool`` form grants ONE tool on kiro-cli, while the array mounts the
    whole server here, and the set of tools to deny is not knowable without
    connecting to the server. Those extra tools still reach the host permission
    gate; they are a wider surface, not an ungated one.
    """
    spec = _agent_spec_for(agent) if agent else None
    if spec is None:
        return []
    raw = spec.get("mcpServers")
    if not isinstance(raw, dict):
        return []
    rules: set[str] = set()
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        disabled = entry.get("disabledTools")
        if not isinstance(disabled, list):
            continue
        for tool in disabled:
            if isinstance(tool, str) and tool:
                rules.add(f"mcp__{name}__{tool}")
    return sorted(rules)


def _registry_mode() -> bool:
    """Whether the operator declared this install registry-governed.

    Wrapped so a config-plane failure degrades to the ungoverned reading (the
    default) instead of costing the session its MCP surface; ``agent``'s own
    helper already swallows most of that, and this is the belt to its braces.
    """
    try:
        return _mcp_registry_mode()
    except Exception:  # pragma: no cover - defensive; the helper is fail-soft
        logger.warning("session MCP: could not read registry mode", exc_info=True)
        return False


def session_mcp_servers(
    agent: str | None,
    *,
    stub_server_names: Collection[str] = (),
) -> list[dict[str, Any]]:
    """The ACP ``mcpServers`` array for a session running as *agent*.

    Called only for a backend in ``ACP_BACKENDS_SESSION_MCP_ARRAY``; every other
    harness reads the same spec itself and gets an empty array.

    *stub_server_names* are the servers that will ALSO arrive in this array as
    MCP-gateway broker stubs, which the caller appends after this list. A stub
    carries the SAME name as the agent-spec entry it wraps (it is a rewrite of
    that entry), so emitting both would put two elements with one ``name`` into
    a single array: either the raw entry shadows the stub and the session
    bypasses the broker, or both register and every pooled backend runs twice --
    the #927 regression ``injection_server_names`` exists to detect. The KAS spec
    projection resolves the same set for the same reason; the caller owns the
    overlay, so it resolves the set and passes it down.

    Blocking (reads the agent spec), so callers run it off the event loop.
    Deterministically ordered by server name, which keeps the array comparable
    across a session/new and the session/load that resumes it.
    """
    servers: dict[str, Any] = {}
    tools: Any = None
    spec = _agent_spec_for(agent) if agent else None
    if spec is not None:
        raw = spec.get("mcpServers")
        if isinstance(raw, dict):
            servers = {str(k): v for k, v in raw.items()}
        tools = spec.get("tools")

    # kiro-cli's registry filter is SYMMETRIC (see ``agent._mcp_registry_mode``):
    # in registry mode it resolves the entries that carry ``type: "registry"``
    # against the admin's catalog and silently DROPS every entry that does not;
    # outside registry mode the marked entries are the dropped ones. Mirroring
    # only one half would invert the administrator's policy on this backend --
    # withholding exactly the catalogued servers while launching the local ones
    # kiro-cli refuses. ``command``/``args`` are retained on a marked entry
    # precisely so a non-registry consumer can still run it (doctor's handshake
    # probe does the same), which is what makes the governed half translatable
    # at all; the residual difference is that a catalog override of the command
    # cannot be applied here, since only kiro-cli talks to the catalog.
    registry_mode = _registry_mode()
    for name, entry in list(servers.items()):
        marked = isinstance(entry, dict) and entry.get("type") == _KIRO_REGISTRY_TYPE
        if marked is not registry_mode:
            logger.info(
                "session MCP: withholding server %r -- registry mode is %s and the entry is %s"
                " the registry marker, so kiro-cli drops it too",
                name,
                "on" if registry_mode else "off",
                "missing" if registry_mode else "carrying",
            )
            servers.pop(name)

    for name in _CONTROL_PLANE_SERVERS:
        managed = managed_mcp_spec_entry(name)
        if managed is not None:
            servers[name] = managed

    for name in stub_server_names:
        if servers.pop(str(name), None) is not None:
            logger.debug(
                "session MCP: yielding %r to its broker stub, which the caller appends", name
            )

    if isinstance(tools, list):
        servers = {n: e for n, e in servers.items() if _tools_grant(tools, n)}

    out: list[dict[str, Any]] = []
    for name in sorted(servers):
        element = acp_server_element(name, servers[name])
        if element is not None:
            out.append(element)
    return out
