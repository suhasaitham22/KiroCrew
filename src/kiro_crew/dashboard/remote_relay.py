"""Run a local session's turn on a connected peer crew and mirror it back.

The shape of the thing
----------------------
A slot bound with ``executor == "remote"`` lives entirely in the LOCAL product —
local sidebar row, local transcript, local history and search, local theme — but
its turns are executed by a peer gateway reached over an already-open instance
tunnel. This module is the seam: it POSTs the turn to the peer, reads the peer's
SSE stream, and replays it locally so that every existing frontend consumer
(``chatSlice``, ``useWebSocket``) sees exactly the frames a local turn produces
and needs no branch for "this session is remote".

Two channels arrive interleaved on the one stream:

* **transcript rows** — what the peer appended to its own window
  (``user``/``assistant``/``chunk``/``thinking``/``error``/…). These are replayed
  as local ``slot.append`` calls, which is what makes the local transcript a true
  mirror and gets the conversation into local history for free.
* **mirrored WebSocket frames** — everything a turn says about itself that is not
  a transcript row (``tool_call``, ``tool_result``, ``chat_segment``,
  ``chat_done`` …), carried in band because the peer was asked for them with
  ``?relay=1``. See :mod:`kiro_crew.dashboard.remote_mirror`. These are
  re-broadcast locally with the slot key rewritten to the LOCAL key.

Why the peer runs in SSE mode
-----------------------------
The peer's WebSocket transport would require proxying ``/api/ws`` — a
long-lived, differently-authenticated, differently-framed channel that the
instance proxy does not carry. Its SSE transport is a plain HTTP response the
existing tunnel already streams chunk by chunk, and the peer runs the turn
detached from the request either way, so nothing is lost by choosing it.

What is deliberately NOT here
-----------------------------
Resume-attach. If the local gateway restarts mid-turn, the peer keeps running
(that is the upside of the split) but this relay's reader is gone and the local
transcript stops at the last row it saw. Rejoining needs the peer's in-flight
tail, which is a separate concern from dispatch; the turn is not lost on the peer
and the next local send re-synchronises the visible conversation.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator

import kiro_crew
from kiro_crew.dashboard.remote_mirror import MIRROR_CLS_PREFIX

if TYPE_CHECKING:  # pragma: no cover - typing only
    from kiro_crew.dashboard.state import DashboardState, _ChatSlot

logger = logging.getLogger(__name__)

#: Ceiling on one un-terminated SSE record while the relay waits for the blank
#: line that ends it. A well-behaved peer emits records far below this (a chunk
#: is a token delta; the largest honest record is a finalized assistant message).
#: The cap exists so a peer that never sends the terminator cannot grow the
#: buffer without bound — the relay refuses the stream instead.
_MAX_SSE_RECORD_BYTES = 8 * 1024 * 1024

#: Ceiling on a peer's reply to a small control request (open a slot, stop a
#: turn). These answer with one flat JSON object, so anything larger is a broken
#: or hostile peer and is refused rather than decoded.
_MAX_PEER_SLOT_REPLY_BYTES = 64 * 1024

#: Transcript roles the relay must NOT replay locally.
#:
#: ``user`` — the local side already appended the user's own message before
#: dispatching, so replaying the peer's copy would show it twice.
#: ``done`` — the SSE terminator's sentinel role; the stream's ``[DONE]`` is what
#: ends the turn, and appending a row for it would put a phantom row in history.
_SKIP_ROLES = frozenset({"user", "done"})


class RemoteTurnError(Exception):
    """The peer could not be asked to run the turn.

    Carries a user-facing message only. The peer's credential, the tunnel port
    and any exception detail beyond its type stay in the log — the transcript is
    a surface the user reads and copies out of.
    """


async def ensure_version_parity(mgr: Any, instance_id: str) -> None:
    """Raise :class:`RemoteTurnError` unless the peer runs THIS exact build.

    Remote execution is fenced by version equality, not compatibility. The two
    ends exchange a frame vocabulary that carries no version of its own, so a
    peer one release ahead can emit a frame this relay silently drops, and a peer
    one release behind can lack a route this relay depends on — both surface to
    the user as a session that mostly works, which is worse than one that
    plainly refuses.

    An *unknown* peer version is a mismatch, not a pass: a peer too old to serve
    ``/api/version`` cannot be proven equal, so it is refused with an actionable
    message rather than optimistically attempted.
    """
    ok, value = await mgr.peer_version(instance_id)
    local = kiro_crew.__version__
    if not ok:
        if value == "capability_peer_too_old":
            raise RemoteTurnError(
                f"This crew is running an older Kiro Crew than this machine "
                f"({local}) and cannot report its version. Update it to {local} "
                f"to run sessions on it."
            )
        raise RemoteTurnError(
            "Could not confirm this crew's Kiro Crew version, so the session was "
            "not dispatched to it. Reconnect the crew and try again."
        )
    if value != local:
        raise RemoteTurnError(
            f"This crew runs Kiro Crew {value} but this machine runs {local}. "
            f"A session only runs on a crew at the identical version — update "
            f"whichever end is behind."
        )


def iter_sse_records(buffer: bytearray, chunk: bytes) -> Iterator[bytes]:
    """Feed *chunk* into *buffer* and yield each complete SSE record.

    Split on the blank line that terminates a record rather than on single
    newlines: a record is ``data: <json>\\n\\n`` and the JSON payload can itself
    contain escaped newlines, so a line-oriented reader would cut records in
    half. *buffer* is mutated in place and retains the trailing partial record
    between calls.

    Raises :class:`RemoteTurnError` when the buffer passes
    :data:`_MAX_SSE_RECORD_BYTES` without a terminator.
    """
    buffer.extend(chunk)
    while True:
        boundary = buffer.find(b"\n\n")
        if boundary < 0:
            if len(buffer) > _MAX_SSE_RECORD_BYTES:
                raise RemoteTurnError("The crew sent a malformed response stream.")
            return
        record = bytes(buffer[:boundary])
        del buffer[: boundary + 2]
        if record:
            yield record


def parse_sse_record(record: bytes) -> dict[str, Any] | None:
    """The row carried by one SSE record, ``None`` for anything not a row.

    Returns ``None`` for the keepalive comment (``: keepalive``), for a record
    with no ``data:`` line, and for undecodable JSON — a garbled record is
    dropped rather than allowed to end an otherwise healthy turn. The terminator
    is reported as the sentinel ``{"__done__": True}`` so the caller can act on
    it without re-parsing.
    """
    for raw_line in record.split(b"\n"):
        line = raw_line.strip()
        if not line.startswith(b"data:"):
            continue  # ": keepalive", or a field the SSE spec allows and we ignore
        payload = line[len(b"data:") :].strip()
        if payload == b"[DONE]":
            return {"__done__": True}
        try:
            decoded = json.loads(payload)
        except ValueError:
            logger.debug("Relay dropped an undecodable SSE record")
            return None
        return decoded if isinstance(decoded, dict) else None
    return None


def _finalize_streamed_segment(slot: "_ChatSlot") -> None:
    """Drop the trailing run of ``chunk`` rows and release them from the queue.

    Mirrors what the peer's own ``_flush_segment`` did to its window just before
    it appended the finalized assistant message: the streamed deltas are replaced
    by the single finished message, so keeping them locally would render the
    answer twice. Releasing the pending copies matters as much as the window
    rewrite — ``append`` put the SAME dict in both, so dropping only the window
    rows would leak every token of the segment in the queue.
    """
    boundary = len(slot.messages)
    for index in range(len(slot.messages) - 1, -1, -1):
        if slot.messages[index].get("role") == "chunk":
            boundary = index
        else:
            break
    if boundary < len(slot.messages):
        slot.messages = slot.messages[:boundary]
    slot.release_pending_chunks()


def _replay_mirrored_frame(
    state: "DashboardState", slot: "_ChatSlot", event: str, encoded: str
) -> None:
    """Re-broadcast one mirrored peer frame under the LOCAL slot key.

    The peer's frames name the peer's slot. Rewriting the identifier is the whole
    translation: every other field is already in the local frontend's vocabulary,
    which is what lets a remote-bound session reuse the unmodified consumption
    path instead of forking it.
    """
    try:
        data = json.loads(encoded)
    except ValueError:
        logger.debug("Relay dropped an undecodable %s frame", event)
        return
    if not isinstance(data, dict):
        return
    if "slot" in data:
        data["slot"] = slot.key
    if "key" in data:  # slot_title / session_summary carry `key`, not `slot`
        data["key"] = slot.key
    state.broadcast_ws(event, data)


class _ChunkSequencer:
    """Local ``seq`` numbers for relayed chunks.

    The peer's own sequence is not reusable: it counts that peer's turn, while
    the local frontend orders chunks within the LOCAL slot and a second relayed
    turn would restart the peer's count mid-conversation.
    """

    def __init__(self) -> None:
        self._seq = 0

    def next(self) -> int:
        self._seq += 1
        return self._seq


def _apply_row(
    state: "DashboardState",
    slot: "_ChatSlot",
    row: dict[str, Any],
    sequencer: _ChunkSequencer,
) -> None:
    """Replay one peer row into the local slot."""
    role = row.get("type") or ""
    if not isinstance(role, str) or not role:
        return
    content = row.get("content", "")
    if not isinstance(content, str):
        content = json.dumps(content)

    if role.startswith(MIRROR_CLS_PREFIX):
        _replay_mirrored_frame(state, slot, role[len(MIRROR_CLS_PREFIX) :], content)
        return
    if role in _SKIP_ROLES:
        return

    cls = row.get("cls", "")
    cls = cls if isinstance(cls, str) else ""
    meta = row.get("meta")
    meta = meta if isinstance(meta, dict) else None

    if role == "chunk":
        slot.append("chunk", content, "chunk")
        state.broadcast_ws(
            "chat_chunk", {"slot": slot.key, "content": content, "seq": sequencer.next()}
        )
        return
    if role == "thinking":
        slot.append("thinking", content, cls or "thinking")
        state.broadcast_ws("chat_thinking", {"slot": slot.key, "content": content})
        return

    # Every other role is an ordinary transcript row. ``append`` emits the
    # ``chat_message`` frame itself, so there is nothing to broadcast here — and
    # nothing to special-case for a local SSE reader either, which drains the
    # appended row from the queue exactly as it would for a local turn.
    if role == "assistant":
        _finalize_streamed_segment(slot)
    slot.append(role, content, cls, meta=meta)


async def _require_manager(state: "DashboardState") -> Any:
    """The instance manager, or a refusal explaining that peers are unavailable."""
    mgr = getattr(state, "instances_manager", None)
    if mgr is None:
        raise RemoteTurnError("Remote crews are not available on this gateway.")
    return mgr


async def create_peer_slot(state: "DashboardState", instance_id: str) -> str:
    """Create the slot on *instance_id* that will execute a local session's turns.

    Returns the PEER's slot key. That key is only meaningful inside a request
    routed back through the same instance — it is not a local session key and
    must never be handed to a local lookup.

    No ``agent`` is sent. The peer has its own crew roster, its own default, and
    its own project layout; naming this machine's default would either fail there
    or silently bind a different crew than the name implies. Letting the peer
    choose is the whole point of the session running on it.
    """
    mgr = await _require_manager(state)
    await ensure_version_parity(mgr, instance_id)
    try:
        async with mgr.proxy_request(
            instance_id,
            "POST",
            "api/chat/slots",
            data=b"{}",
            content_type="application/json",
        ) as upstream:
            if not 200 <= upstream.status < 300:
                raise RemoteTurnError(
                    f"The crew refused to open a session (HTTP {upstream.status})."
                )
            raw = await upstream.content.read(_MAX_PEER_SLOT_REPLY_BYTES + 1)
    except RemoteTurnError:
        raise
    except Exception as e:
        logger.info("Peer slot create on %s failed (%s)", instance_id, type(e).__name__)
        raise RemoteTurnError(
            "Could not reach that crew to open a session. Reconnect it and try again."
        ) from None
    if len(raw) > _MAX_PEER_SLOT_REPLY_BYTES:
        raise RemoteTurnError("The crew returned an oversized reply when opening a session.")
    try:
        payload = json.loads(raw)
    except ValueError:
        raise RemoteTurnError("The crew returned a malformed reply when opening a session.")
    key = payload.get("key") if isinstance(payload, dict) else None
    if not isinstance(key, str) or not key:
        raise RemoteTurnError("The crew opened a session but did not name it.")
    return key


async def forward_peer_stop(state: "DashboardState", slot: "_ChatSlot", force: bool) -> bool:
    """Ask the peer to stop the turn it is running for *slot*.

    Returns whether the peer accepted. Stopping has to travel: the turn is not
    running in this process, so the local cooperative-then-hard escalation has
    nothing to cancel and a local-only stop would leave the peer generating into
    a stream the user believes they interrupted.
    """
    if not slot.is_remote:
        return False
    try:
        mgr = await _require_manager(state)
        async with mgr.proxy_request(
            slot.instance_id,
            "POST",
            f"api/chat/slots/{slot.remote_slot}/stop",
            params={"force": "true"} if force else None,
            data=b"{}",
            content_type="application/json",
        ) as upstream:
            await upstream.content.read(_MAX_PEER_SLOT_REPLY_BYTES + 1)
            return 200 <= upstream.status < 300
    except Exception as e:
        logger.info(
            "Peer stop for slot %s on %s failed (%s)",
            slot.key,
            slot.instance_id,
            type(e).__name__,
        )
        return False


async def relay_remote_turn(
    state: "DashboardState",
    slot: "_ChatSlot",
    message: str,
    *,
    chunks: AsyncIterator[bytes] | None = None,
) -> None:
    """Run one turn for *slot* on its bound peer, replaying the result locally.

    *chunks* exists for tests: pass an async byte iterator to drive the replay
    without a tunnel. In production it is ``None`` and the stream comes from the
    instance manager's proxy.

    Errors reach the user as an ``error`` transcript row and a ``chat_done``, the
    same shape a failed local turn takes, so the composer unblocks and the
    session stays usable rather than appearing to hang.
    """
    sequencer = _ChunkSequencer()
    try:
        if chunks is None:
            chunks = _peer_turn_chunks(state, slot, message)
        buffer = bytearray()
        async for chunk in chunks:
            for record in iter_sse_records(buffer, chunk):
                row = parse_sse_record(record)
                if row is None:
                    continue
                if row.get("__done__"):
                    return
                _apply_row(state, slot, row, sequencer)
    except RemoteTurnError as e:
        slot.append("error", str(e), "msg msg-err")
    except Exception:
        logger.warning("Relayed turn failed for slot %s", slot.key, exc_info=True)
        slot.append(
            "error",
            "The crew running this session stopped responding. The turn may still "
            "be running there.",
            "msg msg-err",
        )
    finally:
        # Unconditional: the composer is unblocked by ``chat_done``, so skipping
        # it on the error paths would leave the session looking permanently busy.
        state.broadcast_ws("chat_done", {"slot": slot.key})


async def _peer_turn_chunks(
    state: "DashboardState", slot: "_ChatSlot", message: str
) -> AsyncIterator[bytes]:
    """Stream the peer's SSE response for one turn, chunk by chunk."""
    mgr = await _require_manager(state)
    await ensure_version_parity(mgr, slot.instance_id)
    body = json.dumps({"message": message, "slot": slot.remote_slot}).encode()
    # ``relay=1`` asks the peer to mirror its WebSocket frames onto this stream;
    # without it the reply carries the prose and none of the tool activity.
    async with mgr.proxy_request(
        slot.instance_id,
        "POST",
        "api/chat",
        params={"relay": "1"},
        data=body,
        content_type="application/json",
    ) as upstream:
        if not 200 <= upstream.status < 300:
            raise RemoteTurnError(
                f"The crew refused the turn (HTTP {upstream.status}). "
                f"It may have restarted — reconnect it and try again."
            )
        async for chunk in upstream.content.iter_any():
            yield chunk
