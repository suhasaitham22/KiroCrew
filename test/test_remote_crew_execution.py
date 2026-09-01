"""Remote-crew execution binding: a local session whose turns run on a peer.

Covers the three layers the feature is made of, in the order a turn traverses
them: the ``_ChatSlot`` binding and its round-trip through history metadata, the
in-band mirror that lets an SSE stream carry a WebSocket turn's full vocabulary,
and the relay that replays a peer's stream into the local slot.

The relay tests drive :func:`relay_remote_turn` with a hand-written byte stream
rather than a tunnel: the peer's wire format is the contract under test, and a
fake iterator pins it exactly while keeping the test free of aiohttp, SSH and a
second gateway.
"""

from __future__ import annotations

import json
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from chat_test_helpers import _make_state

import kiro_crew
from kiro_crew.dashboard import remote_mirror
from kiro_crew.dashboard.remote_relay import (
    RemoteTurnError,
    ensure_version_parity,
    iter_sse_records,
    parse_sse_record,
    relay_remote_turn,
)
from kiro_crew.dashboard.state import _ChatSlot

#: Every async test here needs the loop; the repo runs pytest-asyncio in strict
#: mode, so the marker is explicit rather than inferred from the coroutine.
pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _clean_mirror():
    """No test may leak a mirror registration into the next one."""
    remote_mirror.reset_for_tests()
    yield
    remote_mirror.reset_for_tests()


def _remote_slot(key: str = "chat-1") -> _ChatSlot:
    slot = _ChatSlot(key)
    slot.executor = "remote"
    slot.instance_id = "nobita"
    slot.remote_slot = "peer-chat-9"
    return slot


async def _stream(*records: bytes) -> AsyncIterator[bytes]:
    for record in records:
        yield record


def _sse(row: dict) -> bytes:
    return f"data: {json.dumps(row)}\n\n".encode()


# ── The binding ────────────────────────────────────────────────────────────────


class TestRemoteBinding:
    def test_a_fresh_slot_runs_locally(self):
        assert _ChatSlot("chat-1").executor == "local"
        assert _ChatSlot("chat-1").is_remote is False

    @pytest.mark.parametrize("missing", ["instance_id", "remote_slot"])
    def test_a_half_present_binding_is_not_remote(self, missing):
        """A marker without its target must NOT read as a remote slot.

        This is the fail-closed direction that matters: if ``is_remote`` said
        True the dispatch would try a peer it cannot name, and if the *marker*
        alone were ignored the turn would silently run on THIS machine — work the
        user asked a named crew to do. Neither is acceptable, so the property is
        False and ``api_chat`` refuses on the marker instead.
        """
        slot = _remote_slot()
        setattr(slot, missing, "")
        assert slot.is_remote is False
        assert slot.executor == "remote"  # the marker is preserved for the refusal

    def test_the_binding_is_projected_on_every_slot(self):
        local = _ChatSlot("chat-1").to_dict()
        assert local["executor"] == "local"
        assert local["instance_id"] == ""
        remote = _remote_slot().to_dict()
        assert remote["executor"] == "remote"
        assert remote["instance_id"] == "nobita"
        assert remote["remote_slot"] == "peer-chat-9"


# ── The in-band mirror ─────────────────────────────────────────────────────────


class TestRelayMirror:
    def test_frames_are_not_mirrored_until_a_reader_attaches(self, tmp_path):
        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        state.broadcast_ws("tool_call", {"slot": slot.key, "tool": "fs_read"})
        assert slot._pending == []

    def test_an_attached_reader_receives_mirrored_frames(self, tmp_path):
        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        owned = remote_mirror.attach(slot.key)
        try:
            state.broadcast_ws("tool_call", {"slot": slot.key, "tool": "fs_read"})
        finally:
            remote_mirror.detach(slot.key, owned)
        assert len(slot._pending) == 1
        row = slot._pending[0]
        assert row["cls"] == "relay:tool_call"
        assert json.loads(row["content"])["tool"] == "fs_read"

    @pytest.mark.parametrize("event", sorted(remote_mirror.MIRROR_SKIP_EVENTS))
    def test_already_in_band_frames_are_never_mirrored(self, tmp_path, event):
        """The denylist is what stops every chunk arriving twice.

        Each of these frame types has a transcript row or its own wire frame
        already on the SSE stream, so mirroring them would double the content.
        """
        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        owned = remote_mirror.attach(slot.key)
        try:
            state.broadcast_ws(event, {"slot": slot.key, "content": "x"})
        finally:
            remote_mirror.detach(slot.key, owned)
        assert slot._pending == []

    def test_a_frame_for_another_slot_is_not_mirrored(self, tmp_path):
        state = _make_state(tmp_path)
        watched = state.get_or_create_slot("chat-1")
        other = state.get_or_create_slot("chat-2")
        owned = remote_mirror.attach(watched.key)
        try:
            state.broadcast_ws("tool_call", {"slot": other.key, "tool": "fs_read"})
        finally:
            remote_mirror.detach(watched.key, owned)
        assert watched._pending == []
        assert other._pending == []

    def test_a_second_reader_cannot_truncate_the_first(self, tmp_path):
        """Overlapping relay readers on one slot must not cut each other off."""
        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        first = remote_mirror.attach(slot.key)
        second = remote_mirror.attach(slot.key)
        assert first is True and second is False
        remote_mirror.detach(slot.key, second)  # the non-owner leaves
        assert remote_mirror.is_mirrored(slot.key) is True
        remote_mirror.detach(slot.key, first)
        assert remote_mirror.is_mirrored(slot.key) is False


# ── SSE framing ────────────────────────────────────────────────────────────────


class TestSseFraming:
    def test_records_split_on_the_blank_line_not_the_newline(self):
        """A JSON payload may contain an escaped newline; splitting on \\n cuts it."""
        buffer = bytearray()
        payload = json.dumps({"type": "chunk", "content": "line one\nline two"})
        records = list(iter_sse_records(buffer, f"data: {payload}\n\n".encode()))
        assert len(records) == 1
        assert parse_sse_record(records[0])["content"] == "line one\nline two"

    def test_a_record_split_across_chunks_is_reassembled(self):
        buffer = bytearray()
        assert list(iter_sse_records(buffer, b'data: {"type": "chunk", "cont')) == []
        records = list(iter_sse_records(buffer, b'ent": "hi"}\n\n'))
        assert [parse_sse_record(r)["content"] for r in records] == ["hi"]

    def test_the_terminator_is_reported_as_a_sentinel(self):
        assert parse_sse_record(b"data: [DONE]") == {"__done__": True}

    def test_a_keepalive_comment_is_not_a_row(self):
        assert parse_sse_record(b": keepalive") is None

    def test_an_undecodable_record_is_dropped_not_raised(self):
        assert parse_sse_record(b"data: {not json") is None

    def test_an_unterminated_record_is_refused_rather_than_buffered_forever(self):
        buffer = bytearray()
        with pytest.raises(RemoteTurnError):
            list(iter_sse_records(buffer, b"data: " + b"x" * (8 * 1024 * 1024 + 16)))


# ── The version gate ───────────────────────────────────────────────────────────


class TestVersionParity:
    async def test_an_equal_version_passes(self):
        mgr = MagicMock()
        mgr.peer_version = AsyncMock(return_value=(True, kiro_crew.__version__))
        await ensure_version_parity(mgr, "nobita")  # does not raise

    async def test_a_different_version_is_refused_naming_both_sides(self):
        mgr = MagicMock()
        mgr.peer_version = AsyncMock(return_value=(True, "0.5.9"))
        with pytest.raises(RemoteTurnError) as excinfo:
            await ensure_version_parity(mgr, "nobita")
        assert "0.5.9" in str(excinfo.value)
        assert kiro_crew.__version__ in str(excinfo.value)

    async def test_an_unknown_version_is_a_mismatch_not_a_pass(self):
        """A peer too old to report its version cannot be proven equal.

        The optimistic reading — attempt it and see — is what the gate exists to
        prevent: the two ends exchange an unversioned frame vocabulary, so a skew
        surfaces as a session that half works.
        """
        mgr = MagicMock()
        mgr.peer_version = AsyncMock(return_value=(False, "capability_peer_too_old"))
        with pytest.raises(RemoteTurnError) as excinfo:
            await ensure_version_parity(mgr, "nobita")
        assert "older Kiro Crew" in str(excinfo.value)


# ── The relay ──────────────────────────────────────────────────────────────────


class TestRelayReplay:
    async def test_chunks_replay_as_local_chat_chunk_frames(self, tmp_path):
        state = _make_state(tmp_path)
        state.broadcast_ws = MagicMock()
        slot = _remote_slot()
        await relay_remote_turn(
            state,
            slot,
            "hi",
            chunks=_stream(
                _sse({"type": "chunk", "content": "He", "cls": "chunk"}),
                _sse({"type": "chunk", "content": "llo", "cls": "chunk"}),
                b"data: [DONE]\n\n",
            ),
        )
        chunk_calls = [c for c in state.broadcast_ws.call_args_list if c.args[0] == "chat_chunk"]
        assert [c.args[1]["content"] for c in chunk_calls] == ["He", "llo"]
        # Local sequence numbers, not the peer's: the frontend orders within the
        # LOCAL slot, and a second relayed turn would restart the peer's count.
        assert [c.args[1]["seq"] for c in chunk_calls] == [1, 2]
        assert all(c.args[1]["slot"] == slot.key for c in chunk_calls)

    async def test_a_mirrored_frame_is_rebroadcast_under_the_local_key(self, tmp_path):
        state = _make_state(tmp_path)
        state.broadcast_ws = MagicMock()
        slot = _remote_slot()
        await relay_remote_turn(
            state,
            slot,
            "hi",
            chunks=_stream(
                _sse(
                    {
                        "type": "relay:tool_call",
                        "cls": "relay:tool_call",
                        "content": json.dumps(
                            {"slot": "peer-chat-9", "tool": "fs_read", "tool_call_id": "t1"}
                        ),
                    }
                ),
                b"data: [DONE]\n\n",
            ),
        )
        tool_calls = [c for c in state.broadcast_ws.call_args_list if c.args[0] == "tool_call"]
        assert len(tool_calls) == 1
        # Rewriting the slot identifier is the whole translation — this is what
        # lets the unmodified frontend consumption path render a peer's turn.
        assert tool_calls[0].args[1]["slot"] == slot.key
        assert tool_calls[0].args[1]["tool"] == "fs_read"

    async def test_the_peers_user_row_is_not_replayed(self, tmp_path):
        """The local side already appended the user's message before dispatch."""
        state = _make_state(tmp_path)
        slot = _remote_slot()
        await relay_remote_turn(
            state,
            slot,
            "hi",
            chunks=_stream(
                _sse({"type": "user", "content": "hi", "cls": "msg msg-u"}),
                b"data: [DONE]\n\n",
            ),
        )
        assert [m["role"] for m in slot.messages] == []

    async def test_the_finalized_assistant_row_replaces_its_chunks(self, tmp_path):
        """Keeping both would render the answer twice, once streamed once final."""
        state = _make_state(tmp_path)
        slot = _remote_slot()
        await relay_remote_turn(
            state,
            slot,
            "hi",
            chunks=_stream(
                _sse({"type": "chunk", "content": "He", "cls": "chunk"}),
                _sse({"type": "chunk", "content": "llo", "cls": "chunk"}),
                _sse({"type": "assistant", "content": "Hello", "cls": "msg msg-a"}),
                b"data: [DONE]\n\n",
            ),
        )
        assert [(m["role"], m["content"]) for m in slot.messages] == [("assistant", "Hello")]
        # The window rewrite is only half the release: append put the SAME dict
        # in the pending queue, so a leak there would strand every token.
        assert [r for r in slot._pending if r.get("role") == "chunk"] == []

    async def test_a_turn_always_ends_with_chat_done(self, tmp_path):
        """Without it the composer stays blocked and the session looks hung."""
        state = _make_state(tmp_path)
        state.broadcast_ws = MagicMock()
        slot = _remote_slot()
        await relay_remote_turn(state, slot, "hi", chunks=_stream(b"data: [DONE]\n\n"))
        assert [c.args[0] for c in state.broadcast_ws.call_args_list][-1] == "chat_done"

    async def test_a_failing_stream_yields_an_error_row_and_still_finishes(self, tmp_path):
        state = _make_state(tmp_path)
        state.broadcast_ws = MagicMock()
        slot = _remote_slot()

        async def _boom() -> AsyncIterator[bytes]:
            yield _sse({"type": "chunk", "content": "par", "cls": "chunk"})
            raise ConnectionResetError("tunnel died")

        await relay_remote_turn(state, slot, "hi", chunks=_boom())
        assert slot.messages[-1]["role"] == "error"
        assert [c.args[0] for c in state.broadcast_ws.call_args_list][-1] == "chat_done"


# ── Metadata round-trip ────────────────────────────────────────────────────────


class TestBindingPersistence:
    def test_the_binding_survives_a_save_and_rehydrate(self, tmp_path):
        from kiro_crew.dashboard.chat_persistence import (
            _rehydrate_slot_from_history,
            _save_slot_to_history,
        )

        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        slot.executor = "remote"
        slot.instance_id = "nobita"
        slot.remote_slot = "peer-chat-9"
        slot.append("assistant", "hello", "msg msg-a")
        _save_slot_to_history(state, slot, force=True)

        # Drop the in-memory slot so the rehydrate reads from disk rather than
        # returning the live object it would otherwise find in the registry.
        del state._slots["chat-1"]
        restored = _rehydrate_slot_from_history(state, "chat-1")
        assert restored is not None
        assert restored.executor == "remote"
        assert restored.instance_id == "nobita"
        assert restored.remote_slot == "peer-chat-9"
        assert restored.is_remote is True

    def test_the_empty_window_merge_persists_a_complete_binding(self, tmp_path):
        """The window is empty for the whole gap before the first relayed row.

        A peer-bound newborn has no messages until the relay appends one, so the
        empty-window metadata merge is the only writer its binding sees. If that
        path skips the three fields, a restart inside that gap brings the session
        back as an ordinary local one and the next turn runs here instead of on
        the crew the user picked.
        """
        from kiro_crew.dashboard.chat_persistence import _save_slot_to_history

        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        slot.executor = "remote"
        slot.instance_id = "nobita"
        slot.remote_slot = "peer-chat-9"
        # Materialize the metadata line first: the merge only ever updates an
        # existing record, so a slot that never had one has nothing to reconcile.
        slot.append("assistant", "hello", "msg msg-a")
        _save_slot_to_history(state, slot, force=True)

        slot.messages.clear()
        _save_slot_to_history(state, slot, force=True)

        meta = state.conversation_log.get_metadata("dashboard:chat-1")
        assert meta.get("executor") == "remote"
        assert meta.get("instance_id") == "nobita"
        assert meta.get("remote_slot") == "peer-chat-9"

    def test_the_empty_window_merge_writes_no_half_binding(self, tmp_path):
        """A marker with no target refuses every send, and says nothing useful.

        Coming back local is the recoverable reading (see the rehydrate test
        below), so the merge must not be the writer that creates the shape
        rehydrate then has to repair.
        """
        from kiro_crew.dashboard.chat_persistence import _save_slot_to_history

        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        slot.executor = "remote"
        slot.instance_id = "nobita"  # no remote_slot: the peer open never landed
        slot.append("assistant", "hello", "msg msg-a")
        _save_slot_to_history(state, slot, force=True)

        slot.messages.clear()
        _save_slot_to_history(state, slot, force=True)

        meta = state.conversation_log.get_metadata("dashboard:chat-1")
        assert "executor" not in meta
        assert "instance_id" not in meta

    def test_an_incomplete_stored_binding_comes_back_local(self, tmp_path):
        """A truncated write or a hand-edit must not resurrect a dead session.

        A slot carrying the marker with no target refuses every send, and with no
        way for the user to tell why. Coming back as an ordinary local session is
        the recoverable reading.
        """
        from kiro_crew.dashboard.chat_persistence import (
            _rehydrate_slot_from_history,
            _save_slot_to_history,
        )

        state = _make_state(tmp_path)
        slot = state.get_or_create_slot("chat-1")
        slot.append("assistant", "hello", "msg msg-a")
        _save_slot_to_history(state, slot, force=True)
        path = state.conversation_log._path("dashboard:chat-1")
        lines = path.read_text().splitlines()
        meta = json.loads(lines[0])
        meta["executor"] = "remote"  # marker only, no instance_id / remote_slot
        lines[0] = json.dumps(meta)
        path.write_text("\n".join(lines) + "\n")

        del state._slots["chat-1"]
        restored = _rehydrate_slot_from_history(state, "chat-1")
        assert restored is not None
        assert restored.executor == "local"
        assert restored.is_remote is False
