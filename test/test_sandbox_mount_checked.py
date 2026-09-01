"""Every mount in the namespace launcher refuses to exec when it fails.

Each ``mount(2)`` in the launcher IS a security control: three hide credential
paths, one pins mount propagation so the hiding cannot escape, and a pair exposes
the governance cache read-only (bind, then remount MS_RDONLY -- the remount is
what withholds the write, since MS_RDONLY is ignored on the initial bind).
Discarding the return value made them all fail OPEN -- the path stayed visible, or
stayed WRITABLE, and the agent ran anyway -- and nothing downstream noticed, because there is no post-mount
emptiness check, the launcher has no logger, and the pre-exec hardlink scan only
fires when a credential happens to carry an extra link.

These tests run the mount region lifted VERBATIM out of the shipped launcher, so
they cannot drift away from what actually executes in the child. ``_libc`` is a
stand-in whose ``mount`` returns a chosen rc, which is the only way to exercise
the failure path at all: this test process cannot create a user namespace (a
nested ``unshare`` is seccomp-denied inside an agent sandbox), and even outside
one a real EPERM would need an LSM mount rule the test cannot install.

Every behavioural assertion below has its own break-arm in
``test_break_arms_falsify_each_assertion``: a mutation applied to the shipped
source, chosen to move that assertion's own value. One arm for the whole file
would be inert for any assertion whose expected value happens to coincide with
the mutant's output.
"""

from __future__ import annotations

import errno
import os
import runpy
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from kiro_crew.sandbox import _build_launcher_script

# Every test here builds the shipped launcher, and ``_build_launcher_script`` calls
# POSIX-only ``os.getuid``/``os.getgid`` (the namespace launcher is Linux-only), so
# all of them raise AttributeError on Windows. Guarded rather than listed in
# ``test/windows-expected-failures.txt``: that list is a burn-down backlog of gaps to
# close, and a POSIX-only launcher is a permanent platform boundary. The sibling
# launcher suites take the same route -- see ``test_sandbox_argv.py`` (#2041).
pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="_build_launcher_script uses POSIX-only os.getuid (#2041)",
)

#: Module-level helper: from its ``def`` to the first template substitution.
_HELPER_START = "def _mount_or_die("
_HELPER_END = "REAL_UID = "
#: The propagation mount, on its own -- the tmpfs-source picker sits between it
#: and the hiding loops and is deliberately not exercised here (it probes the
#: host's /run/user and /dev/shm; ``_tmpfs_src`` is injected instead so every
#: temp artifact lands under pytest's tmp_path).
_PROP_START = "        # Private mount propagation"
_PROP_END = "        # Pick a tmpfs-backed source dir"
#: The three hiding mounts: credential dirs, sensitive files, ~/.ssh.
_HIDE_START = "        # Bind-mount empty dirs over credential paths"
_HIDE_END = "        # Scrub sensitive env vars"

#: What the extracted region must contain. Without this a marker rename would
#: shrink a slice and leave every assertion below vacuously green against a
#: fragment that no longer holds the guard. Deliberately STRUCTURAL, not the
#: guard EXPRESSION: pinning a call's exact text here would make the break-arm
#: that reverts that call fail on the landmark instead of on its assertion, and
#: the call form is already pinned once, on purpose, by
#: ``test_every_tier_routes_all_four_mounts_through_the_guard``.
_LANDMARKS = (
    "# Private mount propagation",  # the propagation site
    "for d in SENSITIVE_DIRS:",  # the credential-dir loop
    "for d in READONLY_DIRS:",  # the read-only exposure loop
    "for f in SENSITIVE_FILES:",  # the sensitive-file loop
    "if HIDE_SSH and os.path.isdir(SSH_DIR):",  # the .ssh block
    "sandbox: BLOCKED",  # the refusal
)


class _FakeLibc:
    """``_libc``, with a ``mount`` that fails on a chosen call.

    ``fail_at`` is 1-based over the calls this region makes, in source order:
    1 = propagation, 2 = first credential dir, 3 = read-only bind, 4 = read-only
    remount, 5 = first sensitive file, 6 = ~/.ssh. ``None`` means every mount
    succeeds.
    """

    def __init__(self, *, fail_at: int | None, err: int = errno.EPERM) -> None:
        self.fail_at = fail_at
        self.err = err
        self.calls: list[tuple[object, object, int]] = []

    def mount(self, source, target, fstype, flags, data):  # noqa: ANN001
        self.calls.append((source, target, flags))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            import ctypes

            ctypes.set_errno(self.err)
            return -1
        return 0


def _region(script: str) -> str:
    """Helper + propagation site + hiding loops, lifted out of *script*.

    Sliced from the START OF THE LINE, not from the marker: ``dedent`` measures
    the common prefix across all lines, so a first line already stripped of its
    indent leaves the rest indented and the block will not parse.
    """

    def cut(start_marker: str, end_marker: str) -> str:
        a = script.rindex("\n", 0, script.index(start_marker)) + 1
        b = script.rindex("\n", 0, script.index(end_marker, a)) + 1
        return script[a:b]

    helper = cut(_HELPER_START, _HELPER_END)
    body = textwrap.dedent(cut(_PROP_START, _PROP_END)) + textwrap.dedent(
        cut(_HIDE_START, _HIDE_END)
    )
    region = helper + "\n" + body
    missing = [m for m in _LANDMARKS if m not in region]
    assert not missing, f"the extracted mount region is missing {missing}"
    return region


def _run(
    tmp_path: Path,
    *,
    fail_at: int | None,
    err: int = errno.EPERM,
    script: str | None = None,
    extra_sensitive_files: "list[str] | None" = None,
    sensitive_file_placeholders: "dict[str, str] | None" = None,
    keystone_files: "list[str] | None" = None,
    extra_sensitive_dirs: "list[str] | None" = None,
    trust_root_dirs: "list[str] | None" = None,
    extra_readonly_dirs: "list[str] | None" = None,
) -> tuple[_FakeLibc, str | None]:
    """Run the mount region. Returns ``(fake_libc, refusal_message_or_None)``.

    Via ``runpy.run_path`` on the extracted region rather than ``exec`` of its
    text: equivalent here -- both run the shipped source with an injected
    namespace -- but ``exec`` trips the SAST gate's ``exec-detected`` rule, and a
    suppression comment would be this repo's first, spent on a false positive.
    """
    import ctypes

    home = tmp_path / "home"
    aws = home / ".aws"
    aws.mkdir(parents=True)
    (aws / "credentials").write_text("[default]\n")
    ssh = home / ".ssh"
    ssh.mkdir()
    (ssh / "known_hosts").write_text("example.com ssh-rsa AAAA\n")
    lone = home / ".netrc"
    lone.write_text("machine example.com\n")
    # The governance cache: exposed read-only rather than hidden, so it is the one
    # target whose rule is a REAL bind of itself plus a sealing remount.
    cache = home / ".kiro" / "crew" / "policy_cache"
    cache.mkdir(parents=True)
    (cache / "policy.json").write_text("{}\n")
    src_dir = tmp_path / "tmpfs"
    src_dir.mkdir()

    libc = _FakeLibc(fail_at=fail_at, err=err)
    ns = {
        "_libc": libc,
        "_MS_BIND": 4096,
        "_MS_REC": 16384,
        "_MS_PRIVATE": 1 << 18,
        "_MS_RDONLY": 1,
        "_MS_REMOUNT": 32,
        "ctypes": ctypes,
        "os": os,
        "sys": sys,
        "tempfile": tempfile,
        "_tmpfs_src": str(src_dir),
        # Defined by the launcher alongside _tmpfs_src, before this region: the
        # pid-bearing prefix tagging every bind-mount source for the janitor.
        "_src_prefix": "kirocrew_sb_%d_" % os.getpid(),
        "expose_data": {},
        "EXPOSE_FILES": [],
        "SENSITIVE_DIRS": [str(aws)] + (extra_sensitive_dirs or []),
        "TRUST_ROOT_DIRS": trust_root_dirs or [],
        "READONLY_DIRS": [str(cache)] + (extra_readonly_dirs or []),
        "SENSITIVE_FILES": [str(lone)] + (extra_sensitive_files or []),
        "SENSITIVE_FILE_PLACEHOLDERS": sensitive_file_placeholders or {},
        "KEYSTONE_FILES": keystone_files or [],
        "SSH_DIR": str(ssh),
        "SSH_KNOWN_HOSTS": str(ssh / "known_hosts"),
        "HIDE_SSH": True,
    }
    region_file = tmp_path / "region.py"
    region_file.write_text(_region(script or _build_launcher_script("strict")))
    try:
        runpy.run_path(str(region_file), init_globals=ns)
    except SystemExit as exc:
        return libc, str(exc.code)
    return libc, None


# --------------------------------------------------------------------------
# Behavioural assertions
# --------------------------------------------------------------------------


def test_an_absent_registered_keystone_file_is_materialized_then_mounted(
    tmp_path: Path,
) -> None:
    """GPT review: `mount(2)` needs an existing target, so a keystone file this
    box never configured got no hiding mount at all -- run through the REAL,
    verbatim-extracted region (not a hand-copy) so this cannot drift from what
    the shipped launcher actually executes. A registered-but-ABSENT file must be
    materialized with its placeholder content and THEN mounted over, exactly
    like an already-existing sensitive file is.
    """
    absent = tmp_path / "home" / "computer_use.json"
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_files=[str(absent)],
        sensitive_file_placeholders={str(absent): "{}"},
    )
    assert refusal is None
    assert absent.read_text() == "{}"
    # propagation + credential dir + read-only bind + its seal + 2 files + ssh
    assert len(libc.calls) == 7
    mounted_targets = [call[1] for call in libc.calls]
    assert str(absent).encode() in mounted_targets


def test_a_symlinked_sensitive_file_refuses_the_spawn(tmp_path: Path) -> None:
    """GPT review: `isfile()` follows a symlink and reports True for one
    pointing at a real file, so the shipped loop would happily bind-mount
    THROUGH it -- hiding the CONTENT the link points to while leaving the
    link's own directory-entry slot exactly as replaceable as ever. Run
    through the REAL, verbatim-extracted region so this cannot drift from what
    the shipped launcher actually executes: a symlinked keystone file must
    refuse the spawn, the same fail-closed answer a symlinked container
    directory already gets.
    """
    real_policy = tmp_path / "home" / "real_security_policy.json"
    real_policy.parent.mkdir(parents=True, exist_ok=True)
    real_policy.write_text('{"version": 1}')
    symlinked = tmp_path / "home" / "security_policy.json"
    symlinked.symlink_to(real_policy)
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_files=[str(symlinked)],
        keystone_files=[str(symlinked)],
    )
    assert refusal is not None
    assert "sandbox: BLOCKED" in refusal
    assert "symlink" in refusal
    assert str(symlinked) in refusal
    # No mount was attempted for the symlinked file or anything after it in
    # the loop -- the refusal fires before the mount call, not alongside it.
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked).encode() not in mounted_targets


def test_a_symlinked_trust_root_directory_refuses_the_spawn(tmp_path: Path) -> None:
    """GPT review: `os.path.isdir()` follows a symlink and reports True for one
    pointing at a real directory, so the shipped loop would happily bind-mount
    THROUGH it -- hiding the CONTENT the link points to for the session while
    leaving the link's own directory-entry slot exactly as replaceable as
    ever, same as the file case above and the container's own `UNRENAMABLE_DIRS`
    check this mirrors. Run through the REAL, verbatim-extracted region: a
    symlinked entry HIDDEN via `SENSITIVE_DIRS` and named in `TRUST_ROOT_DIRS`
    (`policy_cache`/`voice-runtime`-shaped -- `profiles/` moved to the
    `READONLY_DIRS`-sealed disposition in #7439, covered by the sibling test
    below) must refuse the spawn rather than silently protect the wrong
    directory.
    """
    # A synthetic stand-in path, not the real ``.kiro/crew/policy_cache`` --
    # ``_run`` already materializes a REAL directory at that exact path for
    # its own READONLY_DIRS fixture, so reusing it here would collide.
    real_target = tmp_path / "home" / "real_trust_root"
    real_target.mkdir(parents=True, exist_ok=True)
    symlinked = tmp_path / "home" / ".kiro" / "crew" / "voice-runtime"
    symlinked.parent.mkdir(parents=True, exist_ok=True)
    symlinked.symlink_to(real_target, target_is_directory=True)
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_dirs=[str(symlinked)],
        trust_root_dirs=[str(symlinked)],
    )
    assert refusal is not None
    assert "sandbox: BLOCKED" in refusal
    assert "symlink" in refusal
    assert str(symlinked) in refusal
    # No mount was attempted for the symlinked directory or anything after it
    # in the loop -- the refusal fires before the mount call, not alongside it.
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked).encode() not in mounted_targets


def test_a_symlinked_readonly_ceiling_refuses_the_spawn(tmp_path: Path) -> None:
    """#7439 moved `profiles/` (and the other governance ceilings) from
    `SENSITIVE_DIRS` (hidden) to `READONLY_DIRS` (sealed read-only via a
    bind-over-self plus an `MS_RDONLY` remount), so `_is_profiles_dir` no
    longer sees it in `hidden_dirs` and the `TRUST_ROOT_DIRS` check above
    stops firing for it -- but the shipped `READONLY_DIRS` loop merged in
    from #7439 guards on `os.path.exists`, which follows a symlink exactly
    the way `os.path.isdir` does. A symlinked `profiles/` would bind-and-seal
    the link's TARGET for the session while its own directory-entry slot
    stayed replaceable, reopening the identical bypass the `SENSITIVE_DIRS`
    check above closes -- just relocated to the loop `profiles/` actually
    flows through now. Every `READONLY_DIRS` entry is one of Crew's own
    generated trust roots (a ceiling file, the governance cache, the
    launcher's own parent), never a credential path an operator would
    legitimately symlink, so this refusal is unconditional across the whole
    list rather than scoped like `TRUST_ROOT_DIRS`.
    """
    real_profiles = tmp_path / "home" / "real_profiles"
    real_profiles.mkdir(parents=True, exist_ok=True)
    symlinked = tmp_path / "home" / ".kiro" / "crew" / "profiles"
    symlinked.parent.mkdir(parents=True, exist_ok=True)
    symlinked.symlink_to(real_profiles, target_is_directory=True)
    libc, refusal = _run(tmp_path, fail_at=None, extra_readonly_dirs=[str(symlinked)])
    assert refusal is not None
    assert "sandbox: BLOCKED" in refusal
    assert "symlink" in refusal
    assert str(symlinked) in refusal
    # No mount was attempted for the symlinked path or anything after it in
    # the loop -- the refusal fires before the mount call, not alongside it.
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked).encode() not in mounted_targets


def test_an_ordinary_readonly_ceiling_still_seals_normally(tmp_path: Path) -> None:
    """The property that must NOT regress: the new `READONLY_DIRS` islink
    check must not touch an ORDINARY, non-symlinked ceiling -- the governance
    cache fixture `_run` already seals by default."""
    libc, refusal = _run(tmp_path, fail_at=None)
    assert refusal is None
    mounted_targets = [call[1] for call in libc.calls]
    cache_target = str(tmp_path / "home" / ".kiro" / "crew" / "policy_cache").encode()
    assert mounted_targets.count(cache_target) == 2  # bind, then the RDONLY remount


def test_a_symlinked_non_trust_root_directory_binds_through_instead_of_refusing(
    tmp_path: Path,
) -> None:
    """The property that must NOT regress: the new check is scoped to
    `TRUST_ROOT_DIRS` only. `SENSITIVE_DIRS` also carries ordinary credential
    directories (`.aws`, `.gnupg`, `.docker`, ...), and those are legitimately
    symlinked by dotfile managers (stow, chezmoi) -- `_is_profiles_dir`'s own
    docstring already declines to widen this to every dir-list entry for
    exactly that reason. A symlinked credential directory NOT in
    `TRUST_ROOT_DIRS` must keep the pre-existing behavior (bind-mount through
    the link, hiding its target's content) rather than abort the spawn.
    """
    real_dir = tmp_path / "home" / "real_gnupg"
    real_dir.mkdir(parents=True, exist_ok=True)
    symlinked_dir = tmp_path / "home" / ".gnupg"
    symlinked_dir.symlink_to(real_dir, target_is_directory=True)
    libc, refusal = _run(tmp_path, fail_at=None, extra_sensitive_dirs=[str(symlinked_dir)])
    assert refusal is None
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked_dir).encode() in mounted_targets


def test_a_symlinked_directory_entry_in_the_same_list_is_unaffected(
    tmp_path: Path,
) -> None:
    """The property that must NOT regress: `SENSITIVE_FILES` also carries
    DIRECTORY entries folded in from `hidden_dirs`, and a symlinked directory
    (real, unrelated dotfile-management setups symlink `~/.aws`/`~/.ssh`) must
    not trip this FILE-scoped refusal -- `isfile()` is already False for a
    directory regardless of symlink status, which is what keeps it out."""
    real_dir = tmp_path / "home" / "real_dir"
    real_dir.mkdir(parents=True, exist_ok=True)
    symlinked_dir = tmp_path / "home" / "symlinked_dir"
    symlinked_dir.symlink_to(real_dir, target_is_directory=True)
    libc, refusal = _run(tmp_path, fail_at=None, extra_sensitive_files=[str(symlinked_dir)])
    assert refusal is None
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked_dir).encode() not in mounted_targets


def test_a_dangling_symlink_refuses_the_spawn(tmp_path: Path) -> None:
    """GPT review: `isfile()` answers False for a DANGLING symlink -- one whose
    target (here, the target's own PARENT directory) does not exist -- exactly
    as it does for a genuinely absent path. That let a dangling symlink at a
    registered keystone-file location fall through BOTH the absent-file
    placeholder loop (its own `open(target, "x")` silently no-ops on ANY
    symlink, dangling or not: POSIX `O_CREAT|O_EXCL` against a symlink always
    fails EEXIST, caught there) AND the symlink refusal (`isfile()` is False),
    leaving the link -- and whatever a later write makes it point at --
    completely unprotected. Registered WITH a placeholder (`computer_use.json`,
    GPT's own exact PoC), since that is the shape that used to reach the
    placeholder loop's silent no-op before ever reaching the refusal.
    """
    dangling = tmp_path / "home" / "computer_use.json"
    dangling.parent.mkdir(parents=True, exist_ok=True)
    dangling.symlink_to(tmp_path / "missing_parent" / "evil.json")
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_files=[str(dangling)],
        sensitive_file_placeholders={str(dangling): "{}"},
        keystone_files=[str(dangling)],
    )
    assert refusal is not None
    assert "sandbox: BLOCKED" in refusal
    assert "symlink" in refusal
    assert str(dangling) in refusal
    # No placeholder was written through the dangling link, and no mount was
    # attempted for it either -- the refusal fires before either happens.
    assert not (tmp_path / "missing_parent").exists()
    mounted_targets = [call[1] for call in libc.calls]
    assert str(dangling).encode() not in mounted_targets


def test_a_symlinked_non_keystone_credential_file_binds_through_instead_of_refusing(
    tmp_path: Path,
) -> None:
    """Opus review: the symlink refusal above is scoped to `KEYSTONE_FILES`
    only. `SENSITIVE_FILES` also carries `_CC_FILES` entries (`.npmrc`,
    `.pypirc`, `.netrc`, `.git-credentials`) in `cc`/`strict` mode, and those
    are legitimately symlinked by dotfile managers (stow, chezmoi) -- the
    Seatbelt profile's own comment already states this posture on purpose:
    credential files "keep read-deny only... turning that into a hard
    failure is a separate decision from closing the ceiling." An unscoped
    refusal aborted every sandboxed spawn for an operator with a symlinked
    `.npmrc`, where the pre-existing behavior (bind-mount through the link,
    hiding its CONTENT) was correct and intended."""
    real_npmrc = tmp_path / "home" / "real_npmrc"
    real_npmrc.parent.mkdir(parents=True, exist_ok=True)
    real_npmrc.write_text("registry=https://example.com\n")
    symlinked = tmp_path / "home" / ".npmrc"
    symlinked.symlink_to(real_npmrc)
    libc, refusal = _run(tmp_path, fail_at=None, extra_sensitive_files=[str(symlinked)])
    assert refusal is None
    mounted_targets = [call[1] for call in libc.calls]
    assert str(symlinked).encode() in mounted_targets


def test_an_absent_unregistered_file_gets_no_mount_same_as_before(
    tmp_path: Path,
) -> None:
    """The property that must NOT regress: a file with no registered placeholder
    keeps the pre-existing behavior exactly -- absent, not materialized, no
    mount attempted for it."""
    absent = tmp_path / "home" / "security_policy.json"
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_files=[str(absent)],
        sensitive_file_placeholders={},
    )
    assert refusal is None
    assert not absent.exists()
    mounted_targets = [call[1] for call in libc.calls]
    assert str(absent).encode() not in mounted_targets
    # Unaffected: same 6 calls as the plain happy path, the extra file
    # contributed nothing since it was never registered.
    assert len(libc.calls) == 6


def test_an_already_existing_registered_file_is_left_untouched(tmp_path: Path) -> None:
    """A file that already holds real content must not be clobbered by the
    exclusive-create materialize step -- it is simply mounted over, same as
    always."""
    existing = tmp_path / "home" / "denied_commands.json"
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_text('{"disable_all": true}')
    libc, refusal = _run(
        tmp_path,
        fail_at=None,
        extra_sensitive_files=[str(existing)],
        sensitive_file_placeholders={str(existing): "{}"},
    )
    assert refusal is None
    assert existing.read_text() == '{"disable_all": true}'
    mounted_targets = [call[1] for call in libc.calls]
    assert str(existing).encode() in mounted_targets


def test_all_mounts_succeeding_lets_the_exec_proceed(tmp_path: Path) -> None:
    """The guard must not turn a healthy spawn into a refusal.

    Break-arm: ``happy_path`` (helper's ``!= 0`` flipped to ``== 0``).
    """
    libc, refusal = _run(tmp_path, fail_at=None)
    assert refusal is None
    # propagation + credential dir + read-only bind + its sealing remount + file + ssh
    assert len(libc.calls) == 6


@pytest.mark.parametrize(
    ("fail_at", "expect_in_message"),
    [
        (1, "propagation"),
        (2, "credential directory"),
        (3, "exposing read-only path"),
        (4, "sealing read-only path"),
        (5, "sensitive file"),
        (6, "ssh key directory"),
    ],
    ids=[
        "propagation",
        "credential-dir",
        "readonly-bind",
        "readonly-seal",
        "sensitive-file",
        "ssh-dir",
    ],
)
def test_a_failed_mount_refuses_to_exec(
    tmp_path: Path, fail_at: int, expect_in_message: str
) -> None:
    """Each of the six sites refuses, and says which control failed.

    ``readonly-seal`` is the one whose failure is least visibly a security
    failure and most needs the refusal: the bind succeeded, so the directory is
    THERE and readable, and only the remount that withholds write did not land.
    Proceeding would hand the child exactly the write access the pair exists to
    deny, with nothing observably wrong.

    Break-arms: ``site1`` .. ``site6`` -- each restores the pre-fix unchecked
    ``_libc.mount(...)`` call at that one site, so exactly the matching
    parametrisation stops refusing.
    """
    libc, refusal = _run(tmp_path, fail_at=fail_at)
    assert refusal is not None, f"site {fail_at} let the spawn proceed"
    assert "sandbox: BLOCKED" in refusal
    assert expect_in_message in refusal
    # Stops AT the failure: no mount is attempted after the one that failed.
    assert len(libc.calls) == fail_at


def test_the_refusal_names_the_hidden_path(tmp_path: Path) -> None:
    """An operator needs the path, not just 'a mount failed'.

    Break-arm: ``drop_path`` (the dirs site's label made a constant).
    """
    libc, refusal = _run(tmp_path, fail_at=2)
    assert refusal is not None
    target = libc.calls[-1][1].decode()
    assert target in refusal


def test_the_refusal_carries_the_errno(tmp_path: Path) -> None:
    """errno is the only thing that distinguishes an LSM denial from ENOMEM.

    Break-arm: ``drop_errno`` (errno removed from the helper's message).
    """
    _libc_unused, refusal = _run(tmp_path, fail_at=2, err=errno.ENOMEM)
    assert refusal is not None
    assert str(errno.ENOMEM) in refusal
    assert os.strerror(errno.ENOMEM) in refusal


def test_the_refusal_names_the_deliberate_opt_out(tmp_path: Path) -> None:
    """Refusing is only defensible if the message says how to opt out.

    Break-arm: ``drop_optout`` (the sandbox_level sentence removed).
    """
    _libc_unused, refusal = _run(tmp_path, fail_at=1)
    assert refusal is not None
    assert "sandbox_level" in refusal


def test_every_tier_routes_all_seven_mounts_through_the_guard() -> None:
    """No tier may keep a raw, unchecked ``_libc.mount`` call site.

    Break-arm: ``reintroduce_raw`` (one site reverted to the raw call).
    """
    for level in ("strict", "cc", "standard"):
        script = _build_launcher_script(level)
        raw = [
            line
            for line in script.splitlines()
            # the helper's own call is the one legitimate raw use
            if "_libc.mount(" in line and "source, target, None, flags, None" not in line
        ]
        assert raw == [], f"{level}: unchecked mount call(s): {raw}"
        # 1 def + 7 call sites: /, per-dir credential masks, the two READONLY_DIRS
        # steps, per-file masks, .ssh, and the data-home container self-bind.
        assert script.count("_mount_or_die(") == 8


# --------------------------------------------------------------------------
# Break-arms: one mutation per assertion above
# --------------------------------------------------------------------------

#: ``name -> (mutation applied to the shipped script, what it must break)``.
#: Each mutation is chosen to move ONE assertion's own value; a single arm would
#: be inert for any assertion whose expected value coincided with the mutant's.
_ARMS: dict[str, tuple[str, str]] = {
    "site1": (
        '_mount_or_die(None, b"/", _MS_REC | _MS_PRIVATE,\n'
        '                      "making mount propagation private on /")',
        '_libc.mount(None, b"/", None, _MS_REC | _MS_PRIVATE, None)',
    ),
    "site2": (
        "_mount_or_die(per_dir_empty, target, _MS_BIND,\n"
        '                              "hiding credential directory %s" % d)',
        "_libc.mount(per_dir_empty, target, None, _MS_BIND, None)",
    ),
    "site3": (
        "_mount_or_die(target, target, _MS_BIND,\n"
        '                              "exposing read-only path %s" % d)',
        "_libc.mount(target, target, None, _MS_BIND, None)",
    ),
    "site4": (
        "_mount_or_die(target, target,\n"
        "                              _MS_REMOUNT | _MS_BIND | _MS_RDONLY,\n"
        '                              "sealing read-only path %s" % d)',
        "_libc.mount(target, target, None, _MS_REMOUNT | _MS_BIND | _MS_RDONLY, None)",
    ),
    "site5": (
        "_mount_or_die(empty_path.encode(), target, _MS_BIND,\n"
        '                              "hiding sensitive file %s" % f)',
        "_libc.mount(empty_path.encode(), target, None, _MS_BIND, None)",
    ),
    "site6": (
        "_mount_or_die(ssh_tmp, SSH_DIR.encode(), _MS_BIND,\n"
        '                          "hiding ssh key directory %s" % SSH_DIR)',
        "_libc.mount(ssh_tmp, SSH_DIR.encode(), None, _MS_BIND, None)",
    ),
    "happy_path": (
        "if _libc.mount(source, target, None, flags, None) != 0:",
        "if _libc.mount(source, target, None, flags, None) == 0:",
    ),
    "drop_errno": (
        '"sandbox: BLOCKED -- %s failed: errno %d (%s). The sandbox could not "',
        '"sandbox: BLOCKED -- %s failed. The sandbox could not "',
    ),
    "drop_path": (
        '"hiding credential directory %s" % d',
        '"hiding a credential directory"',
    ),
    "drop_optout": (
        '"visible. Lower sandbox_level to run without it deliberately."',
        '"visible."',
    ),
}


def _mutate(arm: str) -> str:
    old, new = _ARMS[arm]
    script = _build_launcher_script("strict")
    assert script.count(old) == 1, f"arm {arm}: anchor not unique ({script.count(old)})"
    return script.replace(old, new)


@pytest.mark.parametrize("arm", sorted(_ARMS))
def test_break_arms_falsify_each_assertion(tmp_path: Path, arm: str) -> None:
    """Each arm must break its assertion -- proof the assertion has power."""
    script = _mutate(arm)

    if arm == "drop_errno":
        # `errno %d` gone: the errno assertion can no longer hold. The message
        # is now malformed (%-args outnumber the placeholders), so a TypeError
        # here is the same evidence as a missing number.
        try:
            _unused, refusal = _run(tmp_path, fail_at=2, err=errno.ENOMEM, script=script)
        except TypeError:
            return
        assert refusal is None or str(errno.ENOMEM) not in refusal
        return

    if arm == "drop_path":
        libc, refusal = _run(tmp_path, fail_at=2, script=script)
        assert refusal is not None
        assert libc.calls[-1][1].decode() not in refusal
        return

    if arm == "drop_optout":
        _unused, refusal = _run(tmp_path, fail_at=1, script=script)
        assert refusal is not None
        assert "sandbox_level" not in refusal
        return

    if arm == "happy_path":
        # The guard now fires on SUCCESS, so an all-succeeding run refuses.
        _unused, refusal = _run(tmp_path, fail_at=None, script=script)
        assert refusal is not None
        return

    # site1..site6: that one site is unchecked again, so it proceeds silently.
    site = int(arm[-1])
    _unused, refusal = _run(tmp_path, fail_at=site, script=script)
    assert refusal is None, f"arm {arm} still refused: {refusal}"


def test_break_arm_reintroduce_raw_is_caught_by_the_tier_sweep() -> None:
    """The no-raw-call-sites sweep must fail when a raw call comes back."""
    script = _mutate("site2")
    raw = [
        line
        for line in script.splitlines()
        if "_libc.mount(" in line and "source, target, None, flags, None" not in line
    ]
    assert raw, "the sweep would not have noticed a reintroduced raw mount"
