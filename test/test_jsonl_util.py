"""Tests for the shared JSONL rotation helper (``jsonl_util.rotate_jsonl_at``).

The helper owns ONLY the rotate-by-rename step its call sites share (the MCP
stub's fallback log, the subagents' slow-command log, member activity logs);
each site keeps its own append and error contract. These tests pin the
helper's contract directly; the per-site behavior stays pinned by each site's
own rotation tests.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path

import pytest

import kiro_crew
from kiro_crew import platform_compat
from kiro_crew.image_artifacts import MAX_IMAGE_BYTES_PER_MESSAGE
from kiro_crew.jsonl_util import (
    RECORD_CAP,
    OversizedRecord,
    UndecodableRecord,
    UnreadableRecord,
    bounded_raw_records,
    bounded_records,
    rotate_jsonl_at,
    strict_raw_records,
    strict_records,
)

CAP = 100  # bytes — small enough to cross with one write


class TestRotateAtCap:
    def test_rotates_once_the_cap_is_reached(self, tmp_path):
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * CAP)
        rotate_jsonl_at(live, CAP)
        rotated = tmp_path / "log.jsonl.1"
        assert rotated.exists(), "previous generation not kept"
        assert rotated.stat().st_size == CAP
        assert not live.exists(), "live file must restart empty via the caller's append"

    def test_does_not_rotate_under_the_cap(self, tmp_path):
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * (CAP - 1))
        rotate_jsonl_at(live, CAP)
        assert not (tmp_path / "log.jsonl.1").exists()
        assert live.stat().st_size == CAP - 1

    def test_keeps_exactly_one_generation(self, tmp_path):
        """A second rotation replaces ``.1`` — total disk stays ~2x the cap."""
        live = tmp_path / "log.jsonl"
        rotated = tmp_path / "log.jsonl.1"
        live.write_bytes(b"a" * CAP)
        rotate_jsonl_at(live, CAP)
        live.write_bytes(b"b" * CAP)
        rotate_jsonl_at(live, CAP)
        assert rotated.read_bytes() == b"b" * CAP
        assert not live.exists()


class TestBestEffort:
    """NEVER raises: any failure degrades to not rotating, so the caller's
    append still lands the record. Failures are induced with REAL ``OSError``s
    (a directory squatting on the target path) — no stdlib patching, which
    would leak process-wide to concurrent renamers."""

    def test_missing_live_file_is_a_no_op(self, tmp_path):
        rotate_jsonl_at(tmp_path / "absent.jsonl", CAP)  # must not raise
        assert not (tmp_path / "absent.jsonl.1").exists()

    def test_rename_failure_does_not_raise(self, tmp_path):
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * (CAP + 10))
        (tmp_path / "log.jsonl.1").mkdir()
        rotate_jsonl_at(live, CAP)  # must not raise
        assert (tmp_path / "log.jsonl.1").is_dir()
        assert live.exists(), "a failed rotation must leave the live file appendable"

    def test_lock_open_failure_does_not_raise(self, tmp_path):
        """An unopenable lock file (fd exhaustion, restrictive dir ACL) must
        degrade to not rotating — fd/disk exhaustion is a leading cause of the
        incidents these logs diagnose, so that is exactly when the caller's
        append must still be reachable."""
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * (CAP + 10))
        (tmp_path / "log.jsonl.lock").mkdir()
        rotate_jsonl_at(live, CAP)  # must not raise
        assert not (tmp_path / "log.jsonl.1").exists()
        assert live.exists()

    def test_unusable_path_value_does_not_raise(self, tmp_path):
        """The contract covers ``ValueError`` too (e.g. an embedded NUL, which
        ``os.open`` rejects as a value, not an OS failure) — the call sites'
        own handlers narrow to ``OSError``, so the promise must hold here."""
        rotate_jsonl_at(tmp_path / "log\x00name.jsonl", CAP)  # must not raise


class TestTryLock:
    def test_held_lock_skips_rotation_without_blocking(self, tmp_path):
        """A caller that loses the try-lock skips rotating and never waits —
        a blocking acquire would stall the caller's event loop for the
        duration of another writer's rotation."""
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * (CAP + 10))
        lock_fd = os.open(tmp_path / "log.jsonl.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            assert platform_compat.try_acquire_lock(lock_fd, exclusive=True)
            done = threading.Event()

            def rotate() -> None:
                rotate_jsonl_at(live, CAP)
                done.set()

            t = threading.Thread(target=rotate, daemon=True)
            t.start()
            t.join(timeout=10)
            assert done.is_set(), "rotation blocked on a held try-lock"
            assert not (tmp_path / "log.jsonl.1").exists()
        finally:
            platform_compat.release_lock(lock_fd)
            os.close(lock_fd)

    def test_lock_is_released_after_rotation(self, tmp_path):
        """The winner releases the lock: a second writer can rotate next."""
        live = tmp_path / "log.jsonl"
        live.write_bytes(b"x" * CAP)
        rotate_jsonl_at(live, CAP)
        lock_fd = os.open(tmp_path / "log.jsonl.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            assert platform_compat.try_acquire_lock(lock_fd, exclusive=True)
        finally:
            platform_compat.release_lock(lock_fd)
            os.close(lock_fd)


class TestBoundedRecordReaders:
    """Contract of the shared record readers (``#6345``).

    ``for line in handle`` asks for bytes up to the next newline, so one
    crafted newline-free line is a single allocation the size of the whole
    file. Every tree these readers touch is agent-writable. The four
    functions are two postures (skip / abort) x two forms (decoded / raw).
    """

    @staticmethod
    def _write(tmp_path, *records: bytes):
        path = tmp_path / "log.jsonl"
        path.write_bytes(b"".join(records))
        return path

    def test_whole_records_round_trip(self, tmp_path):
        path = self._write(tmp_path, b'{"a":1}\n', b'{"a":2}\n')
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=RECORD_CAP)) == ['{"a":1}\n', '{"a":2}\n']

    def test_record_exactly_at_cap_survives(self, tmp_path):
        """The cap is INCLUSIVE: a cap-length record plus its terminator is fine."""
        body = b"y" * 200
        path = self._write(tmp_path, body + b"\n", b'{"a":2}\n')
        with open(path, "rb") as fh:
            got = list(bounded_records(fh, path, cap=200))
        assert len(got) == 2, "a record exactly at the cap must not be refused"
        assert got[0] == body.decode() + "\n"

    def test_record_one_byte_over_cap_is_skipped(self, tmp_path):
        path = self._write(tmp_path, b"y" * 201 + b"\n", b'{"a":2}\n')
        with open(path, "rb") as fh:
            got = list(bounded_records(fh, path, cap=200))
        assert got == ['{"a":2}\n'], "one byte past the cap is already over it"

    def test_drain_resumes_at_the_next_record(self, tmp_path):
        """An over-cap record many caps long is drained; following records still parse."""
        path = self._write(tmp_path, b"y" * 1400 + b"\n", b'{"a":2}\n', b'{"a":3}\n')
        with open(path, "rb") as fh:
            got = list(bounded_records(fh, path, cap=200))
        assert got == ['{"a":2}\n', '{"a":3}\n']

    def test_over_cap_record_cannot_forge_a_record_from_its_tail(self, tmp_path):
        """The drain's real job.

        The whole file is ONE line: junk longer than the cap, then what looks
        like a complete record. Without the drain the next bounded read starts
        inside the skipped record and yields the forged tail as if it were a
        record of its own.
        """
        path = self._write(tmp_path, b"y" * 250 + b'{"forged":true}\n')
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=200)) == []

    def test_unterminated_final_record_still_parses(self, tmp_path):
        """A crash mid-append leaves no trailing newline; a within-cap tail counts."""
        path = self._write(tmp_path, b'{"a":1}\n', b'{"a":2}')
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=200)) == ['{"a":1}\n', '{"a":2}']

    def test_unterminated_final_record_exactly_at_cap_survives(self, tmp_path):
        """The inclusive boundary where it is actually decidable.

        A cap-length record WITH its terminator returns ``cap + 1`` bytes ending
        on the newline, so the terminator check alone accepts it however the
        length comparison is spelled. Only an unterminated cap-length record
        distinguishes ``> cap`` from ``>= cap``, so this is the case that pins
        the cap as inclusive rather than exclusive.
        """
        path = self._write(tmp_path, b"y" * 200)
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=200)) == ["y" * 200]

    def test_cap_counts_bytes_not_characters(self, tmp_path):
        """A character cap is not a memory bound: one astral code point is 4 bytes of str."""
        record = ("\U0001f600" * 60).encode()  # 60 code points, 240 bytes
        assert len(record) == 240
        path = self._write(tmp_path, record + b"\n")
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=200)) == [], (
                "a 240-byte record must be refused by a 200-BYTE cap even though "
                "it is only 60 characters"
            )

    def test_exotic_line_boundary_stays_one_record(self, tmp_path):
        """U+2028 is legal raw inside a JSON string and must not split a record."""
        path = self._write(tmp_path, '{"m":"a\u2028b"}\n'.encode())
        with open(path, "rb") as fh:
            got = list(bounded_records(fh, path, cap=200))
        assert len(got) == 1 and json.loads(got[0])["m"] == "a\u2028b"

    def test_crlf_terminated_record_still_parses(self, tmp_path):
        """Binary reads drop universal-newline translation; callers strip the record."""
        path = self._write(tmp_path, b'{"a":1}\r\n')
        with open(path, "rb") as fh:
            got = list(bounded_records(fh, path, cap=200))
        assert json.loads(got[0].strip()) == {"a": 1}

    def test_handle_is_never_read_without_a_limit(self, tmp_path):
        """The allocation bound itself: every read carries a limit, and no iteration."""
        path = self._write(tmp_path, b'{"a":1}\n', b'{"a":2}\n')
        seen: list[int | None] = []

        class Spy:
            def __init__(self, inner):
                self._inner = inner

            def readline(self, limit=None):
                seen.append(limit)
                return self._inner.readline() if limit is None else self._inner.readline(limit)

            def __iter__(self):  # pragma: no cover - must never be reached
                raise AssertionError("the handle was iterated, so one record is unbounded")

        with open(path, "rb") as fh:
            list(bounded_records(Spy(fh), path, cap=200))
        assert seen, "no read was issued"
        assert all(lim is not None and lim <= 201 for lim in seen), seen

    def test_skip_reader_logs_once_and_keeps_going(self, tmp_path, caplog):
        path = self._write(tmp_path, b"y" * 300 + b"\n", b'{"a":2}\n', b"y" * 300 + b"\n")
        with caplog.at_level(logging.DEBUG, logger="kiro_crew.jsonl_util"):
            with open(path, "rb") as fh:
                got = list(bounded_records(fh, path, cap=200, label="probe"))
        assert got == ['{"a":2}\n']
        lines = [r for r in caplog.records if "skipped" in r.getMessage()]
        assert len(lines) == 1, "one aggregated line per read, not one per record"
        assert "2 record(s)" in lines[0].getMessage()

    def test_strict_reader_raises_instead_of_skipping(self, tmp_path):
        path = self._write(tmp_path, b'{"a":1}\n', b"y" * 300 + b"\n", b'{"a":3}\n')
        got: list[str] = []
        with open(path, "rb") as fh:
            with pytest.raises(OversizedRecord):
                for line in strict_records(fh, path, cap=200):
                    got.append(line)
        assert got == ['{"a":1}\n'], "records before the over-cap one are still yielded"

    def test_strict_reader_does_not_drain_the_hostile_tail(self, tmp_path):
        """Aborting must not first walk a multi-GB line to its end.

        Proven by position: the handle stops within one read of the cap rather
        than at EOF, so the reader never paid for the rest of the record.
        """
        path = self._write(tmp_path, b"y" * 5000 + b"\n")
        with open(path, "rb") as fh:
            with pytest.raises(OversizedRecord):
                list(strict_records(fh, path, cap=200))
            assert fh.tell() <= 201 * 2, f"drained to {fh.tell()} of {path.stat().st_size}"

    def test_raw_readers_yield_undecoded_bytes(self, tmp_path):
        """A byte no codec can decode survives the raw readers verbatim."""
        path = self._write(tmp_path, b'{"a":"\xff"}\n')
        with open(path, "rb") as fh:
            assert list(bounded_raw_records(fh, path, cap=200)) == [b'{"a":"\xff"}\n']
        with open(path, "rb") as fh:
            assert list(strict_raw_records(fh, path, cap=200)) == [b'{"a":"\xff"}\n']
        # The decoding form is lossy for that byte, which is why the two
        # verbatim-copy / bytes-prefilter callers use the raw form.
        with open(path, "rb") as fh:
            assert list(bounded_records(fh, path, cap=200)) == ['{"a":"\ufffd"}\n']

    def test_raw_readers_apply_the_same_cap(self, tmp_path):
        path = self._write(tmp_path, b"y" * 300 + b"\n", b'{"a":2}\n')
        with open(path, "rb") as fh:
            assert list(bounded_raw_records(fh, path, cap=200)) == [b'{"a":2}\n']
        with open(path, "rb") as fh:
            with pytest.raises(OversizedRecord):
                list(strict_raw_records(fh, path, cap=200))

    def test_a_bare_cr_ends_a_record(self, tmp_path):
        """Boundaries are universal, as the text-mode reads these replaced were.

        Splitting only on LF would glue the pair into one line that parses as
        neither record -- a lost count for a skip caller, but a lost prior
        entry for a dedupe probe and a silently unmerged restore.
        """
        path = self._write(tmp_path, b'{"a":1}\r{"a":2}\n')
        for reader in (bounded_records, strict_records):
            with open(path, "rb") as fh:
                got = [json.loads(x.strip()) for x in reader(fh, path, cap=200)]
            assert got == [{"a": 1}, {"a": 2}], reader.__name__

    def test_crlf_is_one_terminator_not_two_records(self, tmp_path):
        path = self._write(tmp_path, b'{"a":1}\r\n{"a":2}\r\n')
        with open(path, "rb") as fh:
            got = [json.loads(x.strip()) for x in strict_records(fh, path, cap=200)]
        assert got == [{"a": 1}, {"a": 2}], "CRLF must not yield a blank record between them"

    def test_a_crlf_split_across_two_reads_stays_one_terminator(self, tmp_path):
        """The reason a trailing CR is not treated as a boundary until more bytes arrive.

        With a cap of 8 the first read ends exactly on the CR of a CRLF. Calling
        it a boundary there would invent a record end and leave the following LF
        looking like an empty record.
        """
        path = self._write(tmp_path, b'{"a":1}\r\n{"a":2}\r\n')
        with open(path, "rb") as fh:
            got = [x for x in bounded_records(fh, path, cap=8)]
        assert [json.loads(x.strip()) for x in got] == [{"a": 1}, {"a": 2}]
        assert all(x.strip() for x in got), f"a blank record was invented: {got!r}"

    def test_a_file_ending_in_a_bare_cr_yields_one_final_record(self, tmp_path):
        path = self._write(tmp_path, b'{"a":1}\r')
        with open(path, "rb") as fh:
            got = list(strict_records(fh, path, cap=200))
        assert [json.loads(x.strip()) for x in got] == [{"a": 1}]

    def test_cap_is_judged_per_record_not_per_read(self, tmp_path):
        """A single read may hold several CR-delimited records, each within the cap.

        Judging the read instead of the record would refuse all of them.
        """
        one = b'{"a":1}'
        path = self._write(tmp_path, b"\r".join([one] * 6) + b"\n")
        assert len(one) * 6 + 6 > 20
        with open(path, "rb") as fh:
            got = list(strict_records(fh, path, cap=20))
        assert len(got) == 6, f"expected 6 within-cap records, got {len(got)}"

    def test_strict_reader_refuses_invalid_utf8_rather_than_replacing_it(self, tmp_path):
        """The abort caller PERSISTS what it read, so a U+FFFD would be written back."""
        path = self._write(tmp_path, b'{"a":"\xff"}\n')
        with open(path, "rb") as fh:
            with pytest.raises(UndecodableRecord):
                list(strict_records(fh, path, cap=200))
        # The raw strict reader has nothing to decode, so it still delivers the
        # bytes verbatim -- which is why the verbatim-copy caller uses it.
        with open(path, "rb") as fh:
            assert list(strict_raw_records(fh, path, cap=200)) == [b'{"a":"\xff"}\n']

    def test_every_strict_refusal_is_one_catchable_class(self, tmp_path):
        """Callers fail closed on one except clause, so a new refusal cannot leak."""
        for body in (b"y" * 300 + b"\n", b'{"a":"\xff"}\n'):
            path = self._write(tmp_path, body)
            with open(path, "rb") as fh:
                with pytest.raises(UnreadableRecord):
                    list(strict_records(fh, path, cap=200))
        assert issubclass(OversizedRecord, UnreadableRecord)
        assert issubclass(UndecodableRecord, UnreadableRecord)

    def test_shared_cap_clears_the_largest_legitimate_record(self):
        """The cap is derived, not picked: it must clear a base64 image turn.

        ``MAX_IMAGE_BYTES_PER_MESSAGE`` base64-expands by 4/3, and the largest
        record measured on a live install was 77,920,032 bytes.
        """
        assert RECORD_CAP > MAX_IMAGE_BYTES_PER_MESSAGE * 4 // 3
        assert RECORD_CAP > 77_920_032


# Sites that iterate a file handle directly and are DELIBERATELY left alone,
# each with the reason. The scanner below asserts this list is exhaustive FOR
# THE SHAPE IT DETECTS -- `for <var> in <handle>:` -- so a converted reader
# cannot regress and a new handle-iterating one cannot land unnoticed.
#
# It does NOT detect every unbounded read over these trees, and the claim is
# deliberately no broader than the shape. A whole-file reader spelled
# `path.read_text().splitlines()` has the same harm and is invisible here;
# `learn.py`, the auto_improvement spine's ledger/archive, and the meetings
# store each hold one, and `learn.py`'s feeds a `_write_all` rewrite, which is
# the read-feeds-rewrite pattern this module classifies abort-required. Those
# are a different reader shape than #6345 enumerates and are left for a
# follow-up rather than swept in here; raised by the First Principles lane on
# PR #7651.
#
# Kernel-synthesised pseudo-files: an agent cannot write a multi-GB newline-free
# line into /proc, and the line lengths are fixed by the kernel.
_KERNEL_PSEUDO_FILE_READERS = {
    ("dashboard/handlers_system.py", "/proc/meminfo"),
    ("dashboard/handlers_system.py", "/proc/net/dev"),
    ("platform_compat.py", "/proc/meminfo"),
    ("platform_compat.py", "/proc/locks"),
    ("platform_compat.py", "/proc/<pid>/status"),
    ("acp/runtime.py", "/proc/<pid>/status"),
    ("sandbox.py", "/proc/<pid>/mountinfo"),
}
# Fenced from agent file tools by security._CREW_SECRET_LEAVES, so it is outside
# this issue's "agent-writable" premise. It is the tamper-evident audit chain, so
# if it is ever bounded the posture must be abort/count, never skip.
_FENCED_READERS = {"sel.py"}

_ALLOWED_UNBOUNDED_FILES = {path for path, _ in _KERNEL_PSEUDO_FILE_READERS} | _FENCED_READERS


class TestNoUnboundedHandleIteration:
    """Make the #6345 audit executable rather than a claim in a PR body.

    ``for line in handle`` over an agent-writable tree is an unbounded
    allocation. This scans the whole package for THAT SHAPE and requires every
    instance to be either converted to a bounded reader or listed above with a
    reason. Reads spelled another way -- notably whole-file
    ``read_text().splitlines()`` -- carry the same harm and are outside what
    this detects; see the note on the excused list.
    """

    def test_every_handle_iteration_is_bounded_or_excused(self):
        src = Path(kiro_crew.__file__).parent
        # Detect by the handle-name vocabulary this codebase uses, not by a
        # fixed window after the `with`: sel.py binds its handle several lines
        # earlier (`handle = self._reader_handle(...)`, then `with handle:`),
        # which a distance-based match misses. A file is only considered if it
        # opens something at all, so a loop over a list that happens to be
        # called `f` in a file with no I/O is not flagged.
        handle_names = r"(?:fh|fh2|f|f2|fp|fobj|handle|infile|log_f|logf|src_f|dst_f|stream)"
        offenders: list[str] = []
        for py in sorted(src.rglob("*.py")):
            rel = py.relative_to(src).as_posix()
            try:
                text = py.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):  # pragma: no cover
                continue
            if not re.search(r"\b(?:open|fdopen|_reader_handle|_no_follow)\(", text):
                continue
            for num, line in enumerate(text.splitlines(), 1):
                loop = re.match(rf"\s*for\s+\w+\s+in\s+({handle_names})\s*:\s*$", line)
                if loop:
                    offenders.append(f"{rel}:{num}: for ... in {loop.group(1)}")
        unexcused = [o for o in offenders if o.split(":")[0] not in _ALLOWED_UNBOUNDED_FILES]
        assert not unexcused, (
            "unbounded handle iteration over a possibly agent-writable tree — route it "
            "through jsonl_util.bounded_records (read-only, degradable) or "
            "jsonl_util.strict_records (feeds a rewrite or a durable decision), or add it "
            "to the excused list with a reason:\n  " + "\n  ".join(unexcused)
        )

    def test_the_scanner_actually_detects_the_pattern(self):
        """Guard the guard: a scanner that matches nothing would pass silently.

        The excused sites are real instances of the shape, so finding them
        proves the detector still works even when nothing is unexcused.
        """
        src = Path(kiro_crew.__file__).parent
        handle_names = r"(?:fh|fh2|f|f2|fp|fobj|handle|infile|log_f|logf|src_f|dst_f|stream)"
        found = {
            py.relative_to(src).as_posix()
            for py in src.rglob("*.py")
            for line in py.read_text(encoding="utf-8", errors="replace").splitlines()
            if re.match(rf"\s*for\s+\w+\s+in\s+{handle_names}\s*:\s*$", line)
        }
        missed = _ALLOWED_UNBOUNDED_FILES - found
        assert not missed, f"scanner no longer detects the shape in: {sorted(missed)}"

    def test_the_excused_list_is_not_stale(self):
        """A listed file must still exist, so the list cannot rot into a lie."""
        src = Path(kiro_crew.__file__).parent
        for rel in sorted(_ALLOWED_UNBOUNDED_FILES):
            assert (src / rel).is_file(), f"excused reader {rel} no longer exists"
