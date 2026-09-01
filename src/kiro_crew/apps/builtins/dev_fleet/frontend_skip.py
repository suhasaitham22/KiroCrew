"""Runtime decision: may a backend-only Pull+Build skip the frontend half?

A sync that changes nothing under ``website/`` pays the frontend half's whole cost
to reproduce what is already on disk: the real ``npm ci --prefix website`` (which
deletes and reinstalls the checkout's own tree from an unchanged lockfile) and the
full ``npm run build`` + dist stage (which re-emits a byte-identical bundle). This
module answers whether those two may be skipped, and it is deliberately its own
file for three reasons:

* **It runs at RUNTIME, inside the generated sync runner.** The only evidence a
  sync changes nothing under ``website/`` is a diff against the fetched base
  ref, and that ref (``refs/kirocrew/sync-base-<pid>``) does not exist on disk
  until the sync's own ``fetch`` step has run. The step list is assembled BEFORE
  fetch, so the decision cannot be made at assembly time; it is made here, in
  the runner, after fetch.

  The OTHER side of that diff is a commit OID the caller captures before the run
  starts, NOT ``HEAD``. The runner only reaches the frontend steps after the
  ``git merge --ff-only <ref>`` step has fast-forwarded HEAD onto the very ref
  being compared, so a diff naming ``HEAD`` would compare the ref with itself
  and read empty on EVERY successful sync -- a vacuous gate that would skip the
  build for a sync full of ``website/`` changes. See ``base`` below.

* **A populated tree is not evidence enough.** ``npm ci`` is also what REPAIRS a
  partially populated tree, so "node_modules is non-empty" is not enough to
  skip it -- an interrupted earlier install would then never be healed. This
  module verifies the on-disk tree against the incoming lockfile: npm writes a
  hidden lockfile at ``node_modules/.package-lock.json`` recording exactly what
  it last installed the tree from, so the incoming ``package-lock.json`` matching
  the working tree's, and the hidden lockfile describing a tree that lockfile
  specifies, is strong evidence the tree already IS the one ``npm ci`` would
  produce.

  The hidden lockfile leg is a STRUCTURAL comparison, never a byte or hash
  comparison of the two files, because npm does not write them to be equal: the
  hidden lockfile omits the root ``""`` entry (the project's own manifest, which
  is not something installed under ``node_modules``) and lists only the
  platform-eligible builds of a platform-specific optional dependency. Hashing
  them against each other therefore rejects every real install and never skips
  anything -- see :func:`_tree_satisfies_lockfile`.

  It does NOT lean on ``npm ci --dry-run``: as :mod:`npm_preflight` documents,
  a dry run never fetches and passes lockfiles a real install would fail, so it
  is the wrong tool for asserting a tree is complete.

  It ALSO requires a usable built ``dist`` to already exist. The build+stage
  step's job is to populate ``src/kiro_crew/static/dist``, and before this
  change it ran on every stock Pull+Build -- repairing an absent dist as a side
  effect. ``node_modules`` and the built bundle are independent artifacts, so
  the tree can match the lockfile while the dist is missing; skipping the build
  without confirming a bundle is on disk would leave the dashboard with no
  assets. So the skip also gates on ``dist/index.html`` presence -- the same
  marker ``frontend.py`` resolves the runtime bundle by -- and, because
  ``frontend._stage_dist`` deliberately PRESERVES the previous bundle when a
  build or stage fails, on that staged bundle being the output of the last build
  rather than merely something (see :func:`staged_dist_matches_build_output`).

* **Skipping is CONSERVATIVE.** When any evidence is weak, missing, or
  unobtainable without the network, this returns "do not skip" and the sync
  runs ``npm ci`` exactly as it does today. Skipping is only ever the answer on
  strong, positive evidence, because the failure mode of a wrong skip (a stale
  or partial tree served as if fresh) is worse than the cost it saves.

This module imports ONLY the standard library. The sync runner is a stdlib-only
``python -c`` program that must not import ``kiro_crew`` (that would drag in the
package ``__init__`` chain, which imports croniter and the rest of the runtime),
so this helper is snapshotted at import and executed BY PATH the same way
``dep_sync`` and ``npm_preflight`` are -- see ``server._sync_start_locked``.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess  # nosec B404 - reading git is this module's purpose
from pathlib import Path

#: The checkout subdirectory holding the frontend half, matching
#: :mod:`npm_preflight`'s ``_FRONTEND_SUBDIR``.
_FRONTEND_SUBDIR = "website"

#: The lockfile the tree must match, both in the working tree and in the ref.
_LOCKFILE = "package-lock.json"

#: npm's OWN record of what it last installed ``node_modules`` from. npm writes
#: this hidden lockfile into the tree at the end of every ``npm ci``/``npm
#: install``, so a tree it describes AND the incoming ``package-lock.json``
#: specifies is evidence the on-disk tree already IS what ``npm ci`` would
#: reproduce -- far stronger than "the directory is non-empty", which cannot tell
#: a complete tree from one an interrupted install left half-written. It is
#: compared structurally, never byte-wise: see :func:`_tree_satisfies_lockfile`.
_HIDDEN_LOCKFILE = os.path.join("node_modules", ".package-lock.json")

#: The root entry of a ``package-lock.json`` ``packages`` map: the project's OWN
#: manifest (its ``dependencies``/``devDependencies`` ranges), not a package
#: installed under ``node_modules``. The hidden lockfile records only the latter,
#: so it never carries this key -- which is why the two files are never equal and
#: why this one is excluded from the comparison instead of compared.
_ROOT_PACKAGE_KEY = ""

#: The two top-level fields the comparison pins. ``lockfileVersion`` is what makes
#: the ``packages`` maps comparable at all (a tree installed by an npm that wrote
#: a different format is not something this can reason about), and ``name`` is what
#: keeps a ``node_modules`` belonging to a DIFFERENT project (a link into a shared
#: store) from reading as this one's.
#:
#: ``version`` and ``requires`` are deliberately NOT pinned. Neither carries
#: evidence the ``packages`` map does not already carry -- the root version does
#: not change what gets installed, and ``requires`` is a fixed legacy literal --
#: while every field pinned here is one more way for a future npm to make the two
#: files diverge and silently switch the skip off for good, which is the exact
#: failure this comparison replaced.
_LOCK_IDENTITY_KEYS = ("lockfileVersion", "name")

#: The SERVED frontend bundle, relative to the repo root: the build+stage step's
#: whole job is to populate this directory (``<repo>/src/kiro_crew/static/dist``)
#: so the gateway can serve the SPA. On a packaged install it is a real directory
#: shipped in the wheel; on a source-tree run it is a symlink to
#: ``website/dist``. Either way ``frontend.py`` resolves the runtime bundle from
#: here and treats ``index.html`` as the marker of a usable dist -- see
#: ``frontend.ensure_dev_dist_symlink`` / ``_resolve_website_dist``. Because
#: ``Path`` stat calls follow symlinks, one ``index.html`` probe on this path
#: covers BOTH layouts.
_STATIC_DIST = os.path.join("src", "kiro_crew", "static", "dist")

#: The resolution marker ``frontend.py`` requires before it will serve a bundle;
#: an absent ``index.html`` is exactly what makes it fall back to the "not built"
#: guidance page.
_DIST_INDEX = "index.html"

#: Where ``npm run build`` writes the bundle, relative to the repo root. Vite's
#: ``emptyOutDir`` clears it before writing, and ``frontend._stage_dist`` copies
#: it verbatim into :data:`_STATIC_DIST`, so it is the provenance record the
#: served bundle is checked against -- see
#: :func:`staged_dist_matches_build_output`.
_BUILD_OUTPUT_DIST = os.path.join(_FRONTEND_SUBDIR, "dist")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_satisfies_lockfile(lock: bytes, hidden: bytes) -> bool:
    """Does npm's hidden lockfile describe a tree *lock* specifies?

    *lock* is a ``package-lock.json``; *hidden* is the ``.package-lock.json`` npm
    writes inside ``node_modules`` recording what it last installed there.

    These two files are NOT byte-comparable, and no npm has ever written them to
    be. Comparing them by hash rejects every real install, which makes the skip
    unreachable and the whole optimization a no-op nothing goes red over -- "did
    not skip" is the safe direction. Two divergences are structural:

      * ``package-lock.json`` carries a root ``""`` entry, the project's own
        manifest; the hidden lockfile records only what is installed under
        ``node_modules``, so it has no such entry;
      * a lockfile lists EVERY platform's build of a platform-specific optional
        dependency while an install materializes only the host-eligible ones. On
        this repo's ``website/`` lockfile that is 25 of 1029 entries (the
        rolldown/esbuild native bindings).

    So this asserts the containment npm does guarantee, in both directions:

      1. every package the tree claims to hold is one *lock* specifies, at the
         SAME entry (resolved version, integrity, flags). This is what excludes a
         tree installed from a DIFFERENT lockfile -- the case a byte comparison
         was reaching for.
      2. every package *lock* specifies is either installed or flagged
         ``optional``. This is what excludes the partially-installed tree
         ``npm ci`` exists to repair, and it makes an ``--omit=dev`` tree read as
         unverifiable (dev entries are not optional).

    An ``optional`` entry is waved through without re-deriving npm's ``os``/``cpu``
    eligibility rules. Reimplementing that matcher is a larger new failure surface
    than the risk it removes, and the risk is bounded: the two frontend steps are
    coupled, so a verdict that skips the install skips the BUILD too, and nothing
    consumes a missing native binary on a run that does not build.

    Every other divergence -- an unparseable file, a differing
    ``lockfileVersion``, a workspace link, an entry the lockfile does not list --
    returns ``False``, so the sync installs exactly as it does today.
    """
    try:
        # A non-UTF-8 file raises UnicodeDecodeError and malformed JSON raises
        # JSONDecodeError; both are ValueError subclasses, and both mean the same
        # thing here -- this is not evidence, so do not skip.
        want = json.loads(lock)
        have = json.loads(hidden)
    except ValueError:
        return False
    if not isinstance(want, dict) or not isinstance(have, dict):
        return False
    if any(want.get(key) != have.get(key) for key in _LOCK_IDENTITY_KEYS):
        return False
    want_pkgs = want.get("packages")
    have_pkgs = have.get("packages")
    if not isinstance(want_pkgs, dict) or not isinstance(have_pkgs, dict):
        return False
    for path, entry in have_pkgs.items():
        if path not in want_pkgs or want_pkgs[path] != entry:
            return False
    for path, entry in want_pkgs.items():
        if path == _ROOT_PACKAGE_KEY or path in have_pkgs:
            continue
        if not (isinstance(entry, dict) and entry.get("optional") is True):
            return False
    return True


def _git_show(git: str, repo: str, ref: str, rel: str) -> bytes | None:
    """Return ``<ref>:<rel>`` bytes, or ``None`` if it cannot be read.

    Reads out of the fetched ref rather than the working tree -- the same move
    :mod:`npm_preflight` makes -- so the answer is about the revision the sync is
    about to land, not whatever happens to be checked out. Any failure (git
    missing, ref absent, path not in the ref, timeout) collapses to ``None``,
    which the caller treats as "evidence unobtainable -> do not skip".
    """
    try:
        proc = subprocess.run(  # nosec B603 - argv list, no shell
            [git, "-C", repo, "show", f"{ref}:{rel}"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _read_bytes(path: Path) -> bytes | None:
    """Return *path* bytes, or ``None`` on any read failure."""
    try:
        return path.read_bytes()
    except OSError:
        return None


def website_diff_is_empty(git: str, repo: str, base: str, ref: str) -> bool | None:
    """Does the incoming sync change nothing under ``website/``?

    *base* is the commit the sync's ``git merge --ff-only <ref>`` starts FROM,
    resolved by the caller BEFORE the run began, so ``base..ref`` is exactly the
    merge's ``website/`` delta.

    It must not be spelled ``HEAD``. This runs inside the sync runner, and the
    runner only reaches the frontend steps after the merge step has already
    fast-forwarded HEAD onto *ref* -- so ``git diff HEAD <ref>`` would compare
    *ref* with itself, read empty on every successful sync, and turn this gate
    into an unconditional "skip" that elides the build for a sync whose whole
    content is a ``website/`` change.

    ``True`` when the diff is empty, ``False`` when it lists anything, ``None``
    when git could not be run at all (unobtainable evidence, which the caller
    treats as "do not skip").
    """
    try:
        proc = subprocess.run(  # nosec B603 - argv list, no shell
            [git, "-C", repo, "diff", "--name-only", base, ref, "--", _FRONTEND_SUBDIR],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return not proc.stdout.strip()


def node_modules_matches_lockfile(git: str, repo: str, ref: str) -> bool:
    """Does the on-disk ``node_modules`` verifiably satisfy the incoming lockfile?

    STRONGER than "node_modules is non-empty", because ``npm ci`` is also
    what repairs a partially populated tree -- skipping it safely requires the
    tree to be VERIFIED, not merely present. Two legs, both required, and they
    are deliberately different KINDS of comparison:

      1. The incoming ref's ``package-lock.json`` == the working tree's
         ``package-lock.json``, byte for byte. Two files of the same format, so a
         hash is exactly right. When ``website/`` is unchanged this holds by
         definition, but checking it directly means this function is correct even
         if a caller ever invokes it without the diff gate: it will not skip
         against a tree built from a different lockfile.
      2. ``node_modules``'s hidden ``.package-lock.json`` describes a tree the
         incoming lockfile SPECIFIES -- a structural comparison, because npm
         never writes the two files to be equal (no root ``""`` entry, and only
         host-eligible builds of platform-specific optional deps). Hashing them
         against each other rejects every real install, so the skip would never
         fire at all; see :func:`_tree_satisfies_lockfile` for the containment
         npm does guarantee. This leg is what proves the tree matches the
         lockfile rather than merely coexisting with it, and what excludes the
         partial-install case ``npm ci`` exists to repair.

    Any missing or unreadable input returns ``False`` (conservative: no strong
    evidence means do not skip). It NEVER returns ``None``: an unobtainable input
    here is simply weak evidence, indistinguishable in consequence from a
    mismatch -- either way, do not skip.
    """
    incoming = _git_show(git, repo, ref, f"{_FRONTEND_SUBDIR}/{_LOCKFILE}")
    if not incoming:
        return False
    root = Path(repo) / _FRONTEND_SUBDIR
    worktree_lock = _read_bytes(root / _LOCKFILE)
    if worktree_lock is None:
        return False
    if _sha256(worktree_lock) != _sha256(incoming):
        return False
    hidden_lock = _read_bytes(root / _HIDDEN_LOCKFILE)
    if hidden_lock is None:
        # No hidden lockfile means either node_modules is absent or it was not
        # installed by a modern npm ci/install -- in both cases the tree is not
        # verifiably the lockfile's, so npm ci must run.
        return False
    return _tree_satisfies_lockfile(incoming, hidden_lock)


def built_dist_is_present(repo: str) -> bool:
    """Is a USABLE built frontend bundle already on disk?

    The build+stage step exists to produce ``<repo>/src/kiro_crew/static/dist``,
    the directory the gateway serves the SPA from. Skipping that step is only
    safe when a usable bundle is ALREADY staged there -- otherwise a backend-only
    sync on a checkout whose dist was never built (or whose stage was interrupted)
    would ``continue`` past the build and leave the dashboard with no assets,
    where every prior stock Pull+Build rebuilt it as a side effect.

    The lockfile evidence in :func:`node_modules_matches_lockfile` does NOT cover
    this: ``node_modules`` and the built dist are INDEPENDENT artifacts, so the
    tree can match the lockfile while ``static/dist`` is absent. Dist freshness
    (stale CONTENT) rides on the diff-empty condition -- a sync that changes
    nothing under ``website/`` would rebuild a byte-identical bundle -- but dist
    PRESENCE does not, so it needs its own gate.

    We mirror how ``frontend.py`` resolves the runtime bundle: it treats
    ``static/dist/index.html`` as the marker of a usable dist (see
    ``ensure_dev_dist_symlink`` / ``_resolve_website_dist``), and its ``Path``
    probes follow symlinks, so this one ``index.html`` check covers both the
    packaged real directory and the source-tree symlink to ``website/dist``. We
    do NOT re-implement its deeper asset-completeness scan here: this gate is a
    CONSERVATIVE presence floor, and ``build_and_stage`` remains the safety net
    that produces a complete bundle whenever this returns ``False`` and the
    build runs. Any read failure collapses to ``False`` (do not skip -> build).
    """
    try:
        index = Path(repo) / _STATIC_DIST / _DIST_INDEX
        return index.is_file()
    except OSError:
        return False


def staged_dist_matches_build_output(repo: str) -> bool:
    """Was the SERVED bundle produced by the last frontend build in this checkout?

    :func:`built_dist_is_present` proves only that *a* bundle is staged, and that
    is not enough to cover the one staleness the sync creates ITSELF.
    ``frontend._stage_dist`` deliberately PRESERVES the previously served bundle
    when a build or a stage fails, so a sync that merged ``website/`` changes and
    then failed at the build+stage step leaves the merge landed and the served
    bundle older than the source it is served against. The step that used to
    repair that was the NEXT Pull+Build's build -- and without this gate that
    retry is precisely the shape the skip fires on, because the failed sync's
    merge already landed, so the retry's own ``base..ref`` diff is empty.

    The evidence is already on disk and needs no new state file. ``npm run build``
    writes ``website/dist`` (emptying it first), and staging is a ``copytree`` of
    that directory into ``static/dist``, so after a build and stage that BOTH
    succeeded the two ``index.html`` files are byte-identical. Vite names bundle
    chunks by content hash and lists them in ``index.html``, so a build from
    different ``website/`` sources yields a different one. Hence:

      * the build failed -> ``website/dist`` was emptied and never rewritten, so
        there is no build output to match -> ``False``;
      * the build succeeded and the stage failed -> ``website/dist`` holds the new
        bundle while ``static/dist`` still holds the old one -> ``False``;
      * both succeeded -> byte-identical -> ``True``.

    An out-of-band ``npm run build`` that never staged (a developer's own build, a
    peer flow observed mid-rebuild) also reads as ``False``, which is the
    conservative answer: it costs one rebuild, never a stale bundle served as
    fresh. Same for a checkout whose ``website/dist`` was cleaned away -- the
    served bundle's provenance is then unknowable, so the build runs.

    On a source-tree install where ``static/dist`` is still the symlink
    :func:`frontend.ensure_dev_dist_symlink` created, both reads resolve to the
    same file and the comparison holds trivially -- correctly so: there the served
    bytes ARE the build output. Any unreadable side returns ``False``.
    """
    root = Path(repo)
    staged = _read_bytes(root / _STATIC_DIST / _DIST_INDEX)
    if staged is None:
        return False
    built = _read_bytes(root / _BUILD_OUTPUT_DIST / _DIST_INDEX)
    if built is None:
        return False
    return _sha256(staged) == _sha256(built)


def may_skip_frontend(git: str, repo: str, base: str, ref: str) -> bool:
    """The one decision the runner consults: skip BOTH frontend steps?

    The two steps -- ``npm ci`` and ``npm run build`` + stage -- are COUPLED on
    purpose: they share one cause (no ``website/`` change), and skipping the
    build without the install (or vice versa) has no coherent meaning. A build
    over a reinstalled tree and a build over the existing tree produce the same
    bundle only when the tree already matches the lockfile, which is exactly the
    condition checked here. So one evidence check gates both; see
    ``server._sync_start_locked`` where the two steps carry the same skip marker.

    Returns ``True`` only on STRONG evidence of ALL FOUR conditions:

      * the sync's merge (``base..ref``) changes nothing under ``website/``, AND
      * the on-disk ``node_modules`` verifiably satisfies the incoming lockfile,
        AND
      * a usable built bundle is already staged at ``src/kiro_crew/static/dist``,
        AND
      * that staged bundle is the output of the last build in this checkout.

    Everything else -- a website/ change, an unverifiable tree, a missing built
    dist, a served bundle of unknown provenance, or git being unavailable to
    answer either question -- returns ``False`` and the sync builds as it does
    today.

    *base* is the pre-merge commit the caller resolved before the run, never
    ``HEAD``: by the time this is consulted the merge has moved HEAD onto *ref*,
    so a HEAD-relative diff is vacuously empty. See
    :func:`website_diff_is_empty`.

    Dist freshness (stale CONTENT) rides on the diff-empty condition: when the
    merge changes nothing under ``website/``, the bundle it would build is
    byte-for-byte the one already staged, so declining to rebuild serves the same
    bytes. A dist left stale for a reason UNRELATED to any sync is a pre-existing
    condition this sync neither created nor is obligated to repair -- and this
    sync would not have changed it either way, because it touches nothing under
    ``website/``.

    Two things do NOT ride on the diff, and each needs its own gate:

      * PRESENCE -- ``node_modules`` and the built dist are independent artifacts,
        so the tree can match the lockfile while ``static/dist`` is absent (see
        :func:`built_dist_is_present`).
      * PROVENANCE -- staleness an EARLIER SYNC created is not a pre-existing
        condition this one may wave through: a sync whose merge landed
        ``website/`` changes and whose build then failed leaves a served bundle
        older than the source, and its retry's own diff is empty. So the served
        bundle must also be the last build's output (see
        :func:`staged_dist_matches_build_output`).

    Both gates cover the whole coupled verdict rather than only the build leg: the
    two steps skip together or neither does, so gating the shared verdict keeps
    that coupling intact -- either one failing forces BOTH ``npm ci`` and the
    build to run, exactly as today.
    """
    if website_diff_is_empty(git, repo, base, ref) is not True:
        # None (git unavailable) and False (website/ changed) both mean do not
        # skip. Only a definite empty diff clears this gate.
        return False
    if not built_dist_is_present(repo):
        # No usable served bundle on disk -> must build+stage to produce one.
        return False
    if not staged_dist_matches_build_output(repo):
        # A served bundle that is not the last build's output -> rebuild it.
        return False
    return node_modules_matches_lockfile(git, repo, ref)
