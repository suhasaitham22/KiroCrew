"""Regression tests for the descriptor-pinned dashboard write migration.

Covers the steering create/update/delete blocking transactions and the file-write
blocking transaction after their move onto ``pinned_fs``:

* create/delete address the leaf relative to a pinned parent descriptor and keep
  their error tokens (``exists``/``writefailed``/``notfound``/``deletefailed``);
* update and file-write route their ``atomic_write`` through the pinned-parent
  mode while preserving the ACL carry, byte-exactness (``newline=""``) and mode;
* the by-name floor still produces the same results when the capability probe is
  forced False (the Windows path).

NOT EXECUTED IN THE INTEGRATIONS_ONLY SANDBOX. Importing the dashboard handler
modules pulls ``aiohttp`` (uninstallable offline, pip 403) and the ``croniter`` /
``snowballstemmer`` chain, so these run in CI only.

CI invocation:

    python -m pytest test/test_dashboard_pinned_write_migration.py
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import kiro_crew.dashboard.handlers.files as files_mod
import kiro_crew.dashboard.handlers.steering as steering_mod
from kiro_crew.dashboard.handlers.files import _file_write_blocking
from kiro_crew.dashboard.handlers.steering import (
    _create_file_blocking,
    _delete_file_blocking,
    _update_file_blocking,
)


def _needs_openat() -> None:
    if not steering_mod._DIR_FD_SUPPORTED:  # pragma: no cover - CI runs POSIX
        pytest.skip("platform without openat")


# ── steering create ──


def test_steering_create_writes_byte_exact(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "rules.md"
    body = "line one\nline two\n"
    err, _display = _create_file_blocking(target, body)
    assert err is None
    assert target.read_bytes() == body.encode("utf-8")
    # 0o600 mode preserved on the pinned path.
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_steering_create_refuses_existing_with_exists_token(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "rules.md"
    assert _create_file_blocking(target, "first")[0] is None
    err, _ = _create_file_blocking(target, "second")
    assert err == "exists"
    assert target.read_text(encoding="utf-8") == "first"


def test_steering_create_by_name_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(steering_mod, "_DIR_FD_SUPPORTED", False)
    target = tmp_path / "steering" / "rules.md"
    err, _ = _create_file_blocking(target, "body")
    assert err is None
    assert target.read_text(encoding="utf-8") == "body"


# ── steering delete ──


def test_steering_delete_removes_file(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "rules.md"
    _create_file_blocking(target, "x")
    assert _delete_file_blocking(target) is None
    assert not target.exists()


def test_steering_delete_missing_returns_notfound(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "missing.md"
    (tmp_path / "steering").mkdir(parents=True)
    assert _delete_file_blocking(target) == "notfound"


# ── steering update ──


def test_steering_update_replaces_and_preserves_mode(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "rules.md"
    _create_file_blocking(target, "before")
    os.chmod(target, 0o640)
    assert _update_file_blocking(target, "after") is None
    assert target.read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_steering_update_missing_returns_notfound(tmp_path):
    target = tmp_path / "steering" / "gone.md"
    (tmp_path / "steering").mkdir(parents=True)
    assert _update_file_blocking(target, "x") == "notfound"


def test_steering_update_carries_acl(tmp_path, monkeypatch):
    _needs_openat()
    if not all(hasattr(os, a) for a in ("listxattr", "getxattr", "setxattr")):
        pytest.skip("platform without xattr syscalls")
    target = tmp_path / "steering" / "rules.md"
    _create_file_blocking(target, "before")

    monkeypatch.setattr(os, "listxattr", lambda *a, **k: ["system.posix_acl_access"], raising=False)
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: b"acl", raising=False)
    recorded: list[tuple[str, bytes]] = []
    monkeypatch.setattr(
        os,
        "setxattr",
        lambda fd, attr, value, *a, **k: recorded.append((attr, value)),
        raising=False,
    )
    assert _update_file_blocking(target, "after") is None
    monkeypatch.undo()
    assert ("system.posix_acl_access", b"acl") in recorded


def test_steering_update_byte_exact_no_crlf(tmp_path):
    _needs_openat()
    target = tmp_path / "steering" / "rules.md"
    _create_file_blocking(target, "seed")
    body = "a\nb\n"
    assert _update_file_blocking(target, body) is None
    assert target.read_bytes() == body.encode("utf-8")


# ── file-write ──


def test_file_write_replaces_and_preserves_mode(tmp_path):
    _needs_openat()
    target = tmp_path / "doc.md"
    target.write_text("before", encoding="utf-8")
    os.chmod(target, 0o644)
    assert _file_write_blocking(str(target), "after") is None
    assert target.read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_file_write_carries_acl(tmp_path, monkeypatch):
    _needs_openat()
    if not all(hasattr(os, a) for a in ("listxattr", "getxattr", "setxattr")):
        pytest.skip("platform without xattr syscalls")
    target = tmp_path / "doc.md"
    target.write_text("before", encoding="utf-8")

    monkeypatch.setattr(os, "listxattr", lambda *a, **k: ["system.posix_acl_access"], raising=False)
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: b"acl", raising=False)
    recorded: list[tuple[str, bytes]] = []
    monkeypatch.setattr(
        os,
        "setxattr",
        lambda fd, attr, value, *a, **k: recorded.append((attr, value)),
        raising=False,
    )
    assert _file_write_blocking(str(target), "after") is None
    monkeypatch.undo()
    assert ("system.posix_acl_access", b"acl") in recorded


def test_file_write_by_name_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(files_mod.pinned_fs, "supports_pinned_walk", lambda: False)
    target = tmp_path / "doc.md"
    target.write_text("before", encoding="utf-8")
    assert _file_write_blocking(str(target), "after") is None
    assert target.read_text(encoding="utf-8") == "after"
