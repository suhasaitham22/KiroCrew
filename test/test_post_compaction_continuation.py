"""Post-compaction continuation: the fix for a chat that hangs after "Compacting...".

Three layers are covered, in the order the signal travels:

1. ``parse_claude_compaction_notice`` -- the ACP-layer translation of the
   claude-agent-acp adapter's plain-text compaction notices into the same
   ``EVENT_COMPACTION_STATUS`` vocabulary kiro-cli and KAS already produce. The
   adapter emits them as ordinary ``agent_message_chunk`` text, indistinguishable
   from model prose to any ACP client, so exact-literal matching is the whole
   contract and drift in either direction is what these tests pin.
2. ``AcpClient._settle_claude_compaction`` -- an AUTOMATIC mid-turn compaction
   sends the ``started`` notice and then no terminal at all (the adapter emits
   "Compacting completed." only from the SDK's ``compact_result`` status, which
   is the MANUAL ``/compact`` signal; the automatic path takes ``compact_boundary``
   and emits only a usage update). Without a synthesized terminal the compacting
   UI state never closes and the context meter never resets.
3. ``should_continue_after_compaction`` -- the dashboard's decision to inject one
   continuation. Every gate here exists to stop a synthetic prompt from
   overriding something the user did, so each is tested for the NEGATIVE.
"""

from __future__ import annotations

import pytest

from kiro_crew.acp._dispatch import parse_claude_compaction_notice
from kiro_crew.acp.client import AcpClient
from kiro_crew.acp.types import EVENT_COMPACTION_STATUS, AcpPromptStats
from kiro_crew.acp_backends import ACP_BACKEND_CLAUDE, ACP_BACKEND_KIRO
from kiro_crew.dashboard.chat_utils import (
    _COMPACTION_CONTINUE_MSG,
    should_continue_after_compaction,
)
from kiro_crew.dashboard.state import COMPACTION_RECOVERY_PREFIX

# --------------------------------------------------------------------------- #
# 1. ACP-layer notice translation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("chunk", "expected"),
    [
        # The three literals the shipped adapter emits, verbatim.
        ("Compacting...", ("started", "")),
        ("Compacting completed.", ("completed", "")),
        ("Compacting failed.", ("failed", "")),
        ("Compacting failed: context too large", ("failed", "context too large")),
        # The adapter prefixes both terminals with a blank line so they separate
        # from whatever streamed before. Matching must survive that, which is why
        # the parser strips before comparing rather than comparing raw.
        ("\n\nCompacting completed.", ("completed", "")),
        ("\n\nCompacting failed: backend unreachable", ("failed", "backend unreachable")),
        # Trailing whitespace from chunk-boundary reassembly.
        ("Compacting...  ", ("started", "")),
    ],
)
def test_adapter_notices_are_classified(chunk: str, expected: tuple[str, str]) -> None:
    assert parse_claude_compaction_notice(chunk) == expected


@pytest.mark.parametrize(
    "chunk",
    [
        "",
        "   ",
        # Model prose that merely mentions compaction must NOT be swallowed: the
        # notice is dropped from the transcript once matched, so a loose match
        # would silently delete real assistant output. This is the reason the
        # parser is exact-literal rather than a `^compacting\b` regex.
        "Compacting the context is something I can do with /compact.",
        "I am compacting...",
        "Compacting... let me explain what that means.",
        # kiro-cli's own streamed text, which travels a different path
        # (_kiro.dev/compaction/status) and must not be claimed here.
        "Compacting conversation...",
    ],
)
def test_non_notices_are_not_classified(chunk: str) -> None:
    assert parse_claude_compaction_notice(chunk) is None


def test_started_and_completed_are_distinguishable() -> None:
    """The bug was a `started` with no terminal; the two must never collapse."""
    started = parse_claude_compaction_notice("Compacting...")
    completed = parse_claude_compaction_notice("Compacting completed.")
    assert started is not None and completed is not None
    assert started[0] != completed[0]


# --------------------------------------------------------------------------- #
# 2. The synthesized terminal for an automatic compaction
# --------------------------------------------------------------------------- #


def _bare_client(*, claude: bool = True) -> AcpClient:
    """An AcpClient with only the attributes the compaction helpers touch.

    Constructed without ``__init__`` on purpose: the real one spawns a backend
    process, and these two helpers are pure state transitions over four fields.
    """
    client = AcpClient.__new__(AcpClient)
    # `_is_claude` is a read-only property over `backend`; set the field it reads
    # rather than shadowing the property, so the test exercises the real seam.
    client._acp_backend = ACP_BACKEND_CLAUDE if claude else ACP_BACKEND_KIRO
    client._claude_compaction_pending = False
    client._compaction_failed_at = None
    client.last_prompt_stats = AcpPromptStats()
    return client


def test_started_then_settle_synthesizes_completed() -> None:
    """The reported bug: `started` arrives, no terminal ever does."""
    client = _bare_client()
    started = client._claude_compaction_event("Compacting...")
    assert started is not None
    assert (started.kind, started.text) == (EVENT_COMPACTION_STATUS, "started")
    assert client._claude_compaction_pending

    settled = client._settle_claude_compaction()
    assert settled is not None
    assert (settled.kind, settled.text) == (EVENT_COMPACTION_STATUS, "completed")
    assert not client._claude_compaction_pending
    # The context counts from before the summary are stale now; leaving them
    # would show a meter reading for a window that no longer exists.
    assert client.last_prompt_stats.context_pct_unknown


def test_settle_is_a_no_op_without_a_pending_compaction() -> None:
    """Runs at EVERY turn terminal, so the common case must emit nothing."""
    assert _bare_client()._settle_claude_compaction() is None


def test_explicit_completed_disarms_the_settle() -> None:
    """A MANUAL /compact does send its terminal; the synthesis must not double it."""
    client = _bare_client()
    client._claude_compaction_event("Compacting...")
    completed = client._claude_compaction_event("\n\nCompacting completed.")
    assert completed is not None and completed.text == "completed"
    assert client._settle_claude_compaction() is None


def test_failure_arms_the_post_failure_budget_and_disarms_the_settle() -> None:
    client = _bare_client()
    client._claude_compaction_event("Compacting...")
    failed = client._claude_compaction_event("\n\nCompacting failed: too large")
    assert failed is not None
    assert failed.text == "failed"
    assert failed.title == "too large"
    assert client._compaction_failed_at is not None
    # A failed compaction is not a completed one -- synthesizing `completed`
    # after it would tell every consumer the summary landed when it did not.
    assert client._settle_claude_compaction() is None


def test_other_backends_are_never_reinterpreted() -> None:
    """Only the Claude adapter is a known producer of these literals.

    A kiro-cli/KAS session that happened to stream the same words is ordinary
    assistant text, and reclassifying it would DELETE that text from the
    transcript (the caller drops the chunk once an event comes back).
    """
    client = _bare_client(claude=False)
    assert client._claude_compaction_event("Compacting...") is None
    assert not client._claude_compaction_pending


# --------------------------------------------------------------------------- #
# 3. The dashboard's continuation decision
# --------------------------------------------------------------------------- #

#: The arguments for a turn that SHOULD be continued: context was compacted
#: mid-turn, the compaction settled, and the turn then ended clean with nothing
#: to show for it -- the exact shape of the reported hang.
_FIRES: dict[str, object] = {
    "compaction_started": True,
    "compaction_settled": True,
    "user_requested_compaction": False,
    "final_segment_text": "",
    "stop_reason": "end_turn",
    "end_turn_reason": "end_turn",
    "prompt_depth": 0,
    "compaction_continue_retries": 0,
    "is_cancelled": False,
    "refusal_reasons": [],
}


def test_fires_on_the_reported_shape() -> None:
    assert should_continue_after_compaction(**_FIRES)  # type: ignore[arg-type]


def test_fires_even_when_the_turn_made_tool_calls() -> None:
    """Deliberately NOT gated on a zero-tool-call turn.

    The promise-only sibling gates on ``turn_tool_calls == 0`` because its
    trigger is a PROSE GUESS about intent, and a completed side-effecting tool
    plus trailing promise-shaped text would let a continuation reissue the
    action. Compaction is a hard backend fact instead -- and the turns that
    overflow the context window are precisely the long tool-heavy ones, so
    adopting that gate would have excluded the whole population this recovers.
    The continuation prompt carries the "do NOT re-run any tool or step that
    already completed" instruction for the same hazard.
    """
    assert should_continue_after_compaction(**_FIRES)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "why"),
    [
        # No compaction happened -> this is some other empty-turn failure mode,
        # and the empty-response ladder owns it.
        ("compaction_started", False, "no compaction this turn"),
        # Started but never settled: the turn died mid-compaction, so the
        # conversation state is unknown and a resume could double-drive it.
        ("compaction_settled", False, "compaction never settled"),
        # An explicit /compact IS the whole request. It ended exactly as asked;
        # there is nothing pending to continue, and injecting a prompt would
        # start work the user never asked for.
        ("user_requested_compaction", True, "user asked only to compact"),
        # The turn DID answer after compacting -- it self-healed (kiro-cli does
        # exactly this). Continuing would double-prompt.
        ("final_segment_text", "Here is the answer.", "turn produced a final answer"),
        # Not a clean end_turn: an error/max-turns terminal has its own handling.
        ("stop_reason", "max_turn_requests", "non-end_turn terminal"),
        # A Stop press during compaction can surface as a plain end_turn.
        ("is_cancelled", True, "user cancelled"),
        ("refusal_reasons", ["blocked"], "turn ended on a refusal"),
        # Nested prompt: the outer turn owns recovery.
        ("prompt_depth", 1, "nested prompt"),
        # One-shot already spent this cycle -- the bound that stops a
        # continuation which overflows again from recovering forever.
        ("compaction_continue_retries", 1, "one-shot already spent"),
    ],
)
def test_does_not_fire(field: str, value: object, why: str) -> None:
    args = {**_FIRES, field: value}
    assert not should_continue_after_compaction(**args), f"should not fire: {why}"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "why"),
    [
        ("in_stage_execution", True, "stage loop advances before the resume lands"),
        ("stop_in_progress", True, "a Stop is resolving"),
        ("stop_generation_unchanged", False, "a Stop pressed and resolved this turn"),
        ("queue_empty", False, "a user follow-up is queued and must win"),
        ("no_pending_steers", False, "a mid-turn steer must not be overridden"),
    ],
)
def test_user_intent_gates_block(field: str, value: object, why: str) -> None:
    """Same gates every sibling recovery path uses, for the same reason.

    A synthetic continuation must never jump ahead of, or override, something the
    person did. These default to the permissive value so a caller that forgets one
    still recovers; the point of the test is that passing the blocking value works.
    """
    args = {**_FIRES, field: value}
    assert not should_continue_after_compaction(**args), f"should not fire: {why}"  # type: ignore[arg-type]


def test_whitespace_only_final_segment_still_fires() -> None:
    """A turn whose only output is a stray newline showed the user nothing."""
    args = {**_FIRES, "final_segment_text": "  \n\n  "}
    assert should_continue_after_compaction(**args)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The injected prompt
# --------------------------------------------------------------------------- #


def test_continuation_prompt_shape() -> None:
    """The marker must lead (RecoveryCard matches on it) and a body must follow."""
    marker, body = _COMPACTION_CONTINUE_MSG.split("\n", 1)
    assert marker == COMPACTION_RECOVERY_PREFIX
    assert body.strip()
    # The two instructions that keep the resume from redoing finished work, which
    # is the failure the empty-response ladder's original-prompt replay would have
    # caused had this branch not been ordered ahead of it.
    assert "Do NOT restart" in body
    assert "already completed" in body
