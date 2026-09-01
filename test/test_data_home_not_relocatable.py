"""The data home cannot be relocated by the agent.

Every fenced leaf is identified by its PATH, so the fence assumes the directory
holding it stays where it is. It did not: ``rm -rf ~/.kiro/crew`` was refused, but
``mv`` and ``ln -s`` were not, so

    mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew

left every fence naming a file that is no longer there, and the next write to
``security_policy.json``, ``profiles/``, ``admission_policy.json`` or
``computer_use.json`` followed the link. That is the keystone the whole ceiling
rests on, so this is a bypass of the ceiling rather than of one feature.
"""

from __future__ import annotations

import os
import pathlib
import sys
import time

import pytest

from kiro_crew import platform_compat, security

HOME = os.path.expanduser("~")


def _blocked(command: str) -> bool:
    return security.is_sensitive_bash_command(command) is not None


class TestTheContainerCannotBeRelocated:
    """Refused verb-independently: the refusal is on NAMING the container, because an
    enumerated write-verb allowlist is bypassable -- the reason the leaf fence gives
    for its own verb-independence."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/crew /tmp/stash",
            "ln -s /tmp/evil ~/.kiro/crew",
            "cp -r ~/.kiro /tmp/x",
            "rsync -a ~/.kiro/crew /tmp/x",
            "mv ~/.kiro/crew/ /tmp/x",
            # A verb nobody enumerated, which is the point of not enumerating.
            "install -d ~/.kiro/crew",
        ],
    )
    def test_a_relocating_verb_is_refused(self, command: str) -> None:
        assert _blocked(command), f"{command!r} can relocate the fenced container"

    @pytest.mark.parametrize(
        "command",
        [
            'mv "$HOME/.kiro/crew" /tmp/x',
            "mv $HOME/.kiro/crew /tmp/x",
            "mv ~/.kiro/../.kiro/crew /tmp/x",
            "mv ~/.KIRO/CREW /tmp/x",
            "cd ~/.kiro && mv crew /tmp/x",
            "cd ~/.kiro/crew && mv . /tmp/x",
            "cd ~ && mv .kiro/crew /tmp/x",
            "D=~/.kiro/crew; mv $D /tmp/x",
            "python3 -c \"import os; os.rename(os.path.expanduser('~/.kiro/crew'),'/tmp/x')\"",
        ],
    )
    def test_the_obfuscated_forms_are_refused(self, command: str) -> None:
        """Quoting, `$HOME`, traversal, casefold, `cd`-relative, variables, and an
        interpreter payload -- the evasion families the leaf gate already covers."""
        assert _blocked(command), f"{command!r} relocates the container undetected"

    def test_a_spent_cd_does_not_excuse_a_later_mention(self) -> None:
        """The navigation carve-out must not become a prefix that launders the rest of
        the line."""
        assert _blocked("cd ~/.kiro/crew && mv ~/.kiro/crew /tmp/x")


class TestOrdinaryAgentWorkIsUnaffected:
    """The gate is exact, not prefix -- the reason the container cannot simply be added
    to ``_SENSITIVE_HOME_DIRS``, whose matcher IS prefix-based."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/crew/sessions/a.json",
            "ls ~/.kiro/crew/skills",
            "tail -n 50 ~/.kiro/crew/logs/gateway.log",
            "grep -r todo ~/.kiro/crew/memory",
        ],
    )
    def test_content_under_the_container_stays_reachable(self, command: str) -> None:
        assert not _blocked(command), (
            f"{command!r} was refused; a prefix match here cuts the agent off from its "
            "own sessions, memory, skills and logs"
        )

    @pytest.mark.parametrize("command", ["cd ~/.kiro", "cd ~/.kiro/crew", 'cd "~/.kiro"'])
    def test_even_navigating_into_it_is_refused(self, command: str) -> None:
        """This REVERSES an earlier decision, deliberately.

        `cd` into the container used to be spared -- entering a directory cannot
        relocate it. But the exemption was identified by inspecting the preceding token,
        so `mv cd ~/.kiro/crew` claimed it, and `cd` is a builtin a function can shadow
        besides. Both were reported. Deciding what a token means needs a shell, so the
        exemption is gone rather than narrowed.

        The cost is bounded by the match being exact: only the container itself, never
        anything under it (see `test_removing_it_costs_only_the_container_itself`).
        """
        assert _blocked(command)

    def test_an_unrelated_path_is_untouched(self) -> None:
        assert not _blocked("mv /tmp/a /tmp/b")


class TestItIsNoWeakerThanTheLeafGateBesideIt:
    """The ratchet, and the invariant that matters most.

    The container gate reuses the leaf gate's machinery precisely so the two cannot
    drift, but they are separate code paths and the first cut of this fix was wired
    into only ONE of the three passes -- so it missed `cd`-relative, variable, and
    interpreter forms that the leaf gate had caught for a long time. Asserting parity
    form-by-form is what caught that; asserting the attack alone did not.
    """

    # (leaf command, container command) exercising the SAME evasion family.
    FORMS = [
        (
            "cd ~/.kiro && cat crew/security_policy.json",
            "cd ~/.kiro && mv crew /tmp/x",
        ),
        (
            "cd ~/.kiro/crew && cat ./security_policy.json",
            "cd ~/.kiro/crew && mv . /tmp/x",
        ),
        (
            "cd ~ && cat .kiro/crew/security_policy.json",
            "cd ~ && mv .kiro/crew /tmp/x",
        ),
        (
            "D=~/.kiro/crew; cat $D/security_policy.json",
            "D=~/.kiro/crew; mv $D /tmp/x",
        ),
        (
            f"python3 -c \"print(open('{HOME}/.kiro/crew/security_policy.json').read())\"",
            f"python3 -c \"import os; os.rename('{HOME}/.kiro/crew','/tmp/x')\"",
        ),
    ]

    @pytest.mark.parametrize("leaf,container", FORMS)
    def test_every_form_the_leaf_gate_catches_the_container_gate_catches(
        self, leaf: str, container: str
    ) -> None:
        assert _blocked(leaf), (
            f"the leaf gate stopped catching {leaf!r}; this test's premise is gone and "
            "the parity assertion below would pass vacuously"
        )
        assert _blocked(container), (
            f"the leaf gate catches {leaf!r} but the container gate misses the same "
            f"evasion in {container!r} -- the container gate is the weaker of the two"
        )


class TestTheContainerSetCoversEveryDataHome:
    def test_the_legacy_home_is_covered_too(self) -> None:
        """`~/.kirocrew` is fully deprecated and never migrated to, but an installation
        that still has one must not have it swapped out from under the files inside --
        the same reason it stays in the leaf fence."""
        assert _blocked("mv ~/.kirocrew /tmp/x")

    def test_the_predicate_is_exact_rather_than_prefix(self) -> None:
        assert security.is_unreplaceable_container("~/.kiro/crew")
        assert not security.is_unreplaceable_container("~/.kiro/crew/sessions")
        assert not security.is_unreplaceable_container("~/.kiro/crewuxx")


class TestShellExpansionCannotSpellAroundEitherGate:
    """Bash expands the operand before the command runs; the matcher did not.

    `~/.kiro/cr{e..e}w` reached the gate as a literal matching no protected path and
    reached bash as `~/.kiro/crew`. This was NOT specific to the container gate -- the
    leaf gate had the identical hole, so `cat ~/.kiro/cr{e..e}w/security_policy.json`
    read the governance trust root on `main`. Expansion therefore lands in the shared
    candidate generator, where both gates inherit it.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/cr{e..e}w/security_policy.json",
            "cat ~/.kiro/crew/security_polic{y..y}.json",
            "cat ~/.kiro/cre[w]/security_policy.json",
            "cat ~/.kiro/*/security_policy.json",
        ],
    )
    def test_the_leaf_gate_resists_it_too(self, command: str) -> None:
        """The finding arrived on the container gate; the fix had to cover both."""
        assert _blocked(command), f"{command!r} reads the trust root through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cr{e..e}w /tmp/x",
            "mv ~/.kiro/cre[w] /tmp/x",
            "mv ~/.kiro/* /tmp/x",
            "mv ~/.kiro/{crew,other} /tmp/x",
        ],
    )
    def test_the_container_gate_resists_it(self, command: str) -> None:
        assert _blocked(command), f"{command!r} relocates the container through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "ls *",
            "ls ~/*",
            "rm -f build/*.o",
            "cp {a,b}.txt /tmp/",
            "ls ~/.kiro/crew/sessions/*.json",
            "cat ~/.kiro/crew/logs/*.log",
            "grep -r x ~/.kiro/crew/skills/*",
        ],
    )
    def test_ordinary_globbing_is_untouched(self, command: str) -> None:
        """The expensive half of this fix.

        A first cut used `fnmatch` over the whole path and denied `ls *`, because
        `fnmatch`'s `*` crosses `/` and matched every absolute target. Matching is
        component-wise instead, with bash's dotfile rule -- which is why `ls ~/*` is
        allowed (bash without `dotglob` does not match `.kiro`) while `ls ~/.kiro/*`,
        which names it, is not.
        """
        assert not _blocked(command), f"{command!r} is ordinary shell usage"

    def test_a_pattern_naming_the_container_explicitly_is_still_refused(self) -> None:
        assert _blocked("ls ~/.kiro/*")

    def test_expansion_is_bounded(self) -> None:
        """A gate is not the place to discover that `{a..z}{a..z}{a..z}` is 17,576
        strings. Past the cap the token is left unexpanded and the metacharacter arm
        still refuses anything that could name a protected path."""
        from kiro_crew.security import _MAX_BRACE_EXPANSIONS, _expand_braces

        assert len(_expand_braces("~/{a..z}{a..z}{a..z}")) <= _MAX_BRACE_EXPANSIONS


class TestTheFencedPathsAreHiddenFromSubprocesses:
    """The command gate reads command TEXT; a subprocess is one opaque token to it.

    `security.is_sensitive_bash_command` refuses `echo x > ~/.kiro/crew/
    security_policy.json`, and says nothing about `./script.sh` containing that exact
    line — an approved `make install` or `npm run build` writes whatever it likes. So
    the path fence alone never constrained a subprocess, and the sandbox's hide lists
    are the layer that does not depend on the write being spelled out in a command.

    Asserted as a COUPLING rather than as a literal list, because the two halves live
    in different modules with no shared symbol: `security.py` names the fenced leaves,
    `sandbox.py` names what is hidden, and a leaf added to one and not the other is
    protected only against the spelling nobody uses.
    """

    # The keystone leaves this branch's base originally fenced by NAME and hid
    # outright. `profiles`, `security_policy.json`, `admission_policy.json`, and
    # `computer_use.json` moved to the READONLY disposition on `main` (#7439):
    # in-sandbox code (a script cron's `boot_platform()`) READS each of these, so
    # hiding them as an empty stub broke the legitimate reader instead of
    # protecting the ceiling. `test_sandbox_governance_mask.py`'s
    # `TestKeystonesAreSealedInEveryMode` covers that coupling now -- sealed
    # read-only rather than hidden, on every tier and both backends -- so nothing
    # is left here that is both name-fenced AND hidden.
    MUST_BE_HIDDEN: "list[str]" = []

    # Hidden here, but fenced by NAME only once the crew-variables work lands, so the
    # command-gate half of the coupling cannot be asserted on this base yet. Listed
    # separately rather than dropped: the hide list is the half that stops a
    # subprocess, and it is correct to ship it whether or not the name fence exists.
    #
    # `.kiro/crew/variables` itself is NOT listed here: this branch creates and reads
    # no such store (that lands with #4371), so hiding it protects nothing yet and
    # belongs with the PR that adds the store (First Principles review).
    #
    # `crons.json` is NOT listed here either: #7439 moved it to
    # `_CREW_SANDBOX_VISIBLE_LEAVES` (`mcp_cron` builds a `CronService` in-sandbox
    # and both reads and rewrites the job store through it), so hiding it here
    # would break cron scheduling from a chat session.
    HIDDEN_AHEAD_OF_ITS_NAME_FENCE = [
        ".kiro/crew/autonudge.json",
    ]

    def _all_hidden(self) -> set[str]:
        """Union of every list — use only where the mode genuinely does not matter.

        Unioning HID a real gap: `_CC_FILES` applies on `cc`/`strict` only, so a file
        listed there is not hidden on the default `standard` tier, and a test that
        unions cannot tell the difference. `test_the_mode_coverage_is_what_the_spec_says`
        below asserts the split directly.
        """
        from kiro_crew import sandbox

        hidden: set[str] = set()
        for name in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS", "_CC_FILES", "_KEYSTONE_FILES"):
            hidden.update(getattr(sandbox, name, []))
        return hidden

    # `security_policy.json`, `admission_policy.json`, `computer_use.json`,
    # `denied_commands.json`, and `crons.json` moved off `_KEYSTONE_FILES`
    # entirely with #7439 -- see the comment on `sandbox._KEYSTONE_FILES` itself.
    KEYSTONE_FILES = [
        ".kiro/crew/autonudge.json",
    ]

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
            "`os.getuid()`. The macOS equivalent is asserted in "
            "`TestTheSeatbeltProfileMatchesTheLinuxLauncher`; Windows uses neither."
        ),
    )
    def test_the_keystone_files_are_hidden_on_EVERY_tier(self) -> None:
        """Including `standard`, which is where nearly every install actually runs.

        An earlier revision of this file asserted the opposite -- that these were
        `cc`/`strict`-only -- and wrote the reason down as if it were the design. It was
        not: `_SANDBOX_MODE_ALIASES` maps the default `auto` to `standard`, and
        `standard` applies `files = []`, so the governance ceiling was readable to an
        agent subprocess in the shipped configuration. Documenting a gap is not the same
        as choosing it.

        Asserted through the LAUNCHER for each tier rather than against a list, so the
        selection expression is what is under test. `files = _CC_FILES if … else []`
        was exactly the line that made the list membership meaningless.
        """
        from kiro_crew import sandbox

        for tier in ("standard", "cc", "strict"):
            script = sandbox._build_launcher_script(tier)
            for f in self.KEYSTONE_FILES:
                assert f in script, f"{f} is not hidden on the {tier!r} tier"

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
            "`os.getuid()`. The macOS equivalent is asserted in "
            "`TestTheSeatbeltProfileMatchesTheLinuxLauncher`; Windows uses neither."
        ),
    )
    def test_credential_files_keep_their_existing_tier_split(self) -> None:
        """The keystone hoist must not quietly widen anything else.

        `.npmrc` and friends are `cc`/`strict`-only, which is the split this repo
        already chose for credential files; changing it is a separate decision and
        would belong in its own change with its own reasoning.
        """
        from kiro_crew import sandbox

        assert ".npmrc" in sandbox._build_launcher_script("cc")
        assert ".npmrc" not in sandbox._build_launcher_script("standard")

    def test_profiles_does_not_return_to_the_hide_lists(self) -> None:
        """Regression guard, not a hiding assertion: `profiles` moved to the
        READONLY disposition (#7439) specifically because in-sandbox code reads
        it, so re-adding it to a hide list would silently reopen the "hiding a
        ceiling removes it" bug that move fixed."""
        from kiro_crew import sandbox

        for tier in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS"):
            assert ".kiro/crew/profiles" not in getattr(
                sandbox, tier
            ), f"profiles is back in {tier} -- it must stay in _CREW_READONLY_LEAVES instead"

    def test_the_cron_record_is_the_one_cron_declares_visible(self) -> None:
        """Derived, because a hardcoded name passed while covering nothing.

        An earlier revision hid `cron.json`; cron writes `crons.json`. #7439 moved
        the real store to `_CREW_SANDBOX_VISIBLE_LEAVES` (`mcp_cron` reads and
        rewrites it in-sandbox), so the coupling this test guards is now with
        THAT list, not with `_KEYSTONE_FILES`."""
        from kiro_crew import cron, sandbox

        assert cron._CRONS_FILE in sandbox._CREW_SANDBOX_VISIBLE_LEAVES

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_each_fenced_path_is_hidden_from_the_agent(self, path: str) -> None:
        assert path in self._all_hidden(), (
            f"{path} is refused by the command gate but VISIBLE to a subprocess. An "
            "approved script can write it without the gate ever seeing a path."
        )

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_legacy_home_is_covered_too(self, path: str) -> None:
        """A not-yet-migrated box still holds the real bytes."""
        legacy = path.replace(".kiro/crew/", ".kirocrew/")
        assert legacy in self._all_hidden()

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_command_gate_still_refuses_the_spelled_out_write(self, path: str) -> None:
        """The other half of the coupling. If this stops refusing, the hide list is
        carrying a burden it was never meant to carry alone.

        A directory entry is probed through a file INSIDE it: `echo x > <dir>` is not a
        write anyone can perform, so asserting on the bare directory would be asserting
        on a shape that never occurs.
        """
        target = f"~/{path}" if path.endswith(".json") else f"~/{path}/planted"
        assert security.is_sensitive_bash_command(f"echo x > {target}") is not None

    @pytest.mark.parametrize("path", HIDDEN_AHEAD_OF_ITS_NAME_FENCE)
    def test_the_store_is_hidden_even_before_its_name_fence_exists(self, path: str) -> None:
        assert path in self._all_hidden()
        assert path.replace(".kiro/crew/", ".kirocrew/") in self._all_hidden()

    # `profiles` sealed read-only "in every mode, not only strict" is covered by
    # `test_sandbox_governance_mask.py::TestKeystonesAreSealedInEveryMode`, which
    # parametrizes the identical property over every tier and both backends.


class TestTheMatcherDoesNotDivergeFromBash:
    """Four ways the hand-rolled expander disagreed with the shell it models.

    Each is the same failure mode: bash produced a protected path and the gate produced
    something else, so the operand looked harmless. This layer is best-effort by
    construction -- a matcher is not a bash parser, which the module says of itself --
    and the floor beneath it is the sandbox hide list. That is why these are worth
    fixing but not worth trusting alone.
    """

    def test_a_descending_range_expands_like_bash(self) -> None:
        """`{w..e}` counts DOWN in bash. Walking only upward gave an empty span, so the
        operand produced no candidates at all while bash produced `crew`."""
        from kiro_crew.security import _expand_braces

        assert "crew" in _expand_braces("cr{w..e}w")
        assert "crew" in _expand_braces("cr{e..e}w")
        assert _blocked("mv ~/.kiro/cr{w..e}w /tmp/stash")

    def test_a_descending_numeric_range_too(self) -> None:
        from kiro_crew.security import _expand_braces

        assert _expand_braces("{3..1}") == ["3", "2", "1"]

    def test_an_oversized_brace_fails_closed(self) -> None:
        """Truncating dropped the TAIL, so a 65-item list with `crew` last expanded to
        `crew` in bash and to everything-but-`crew` here. Too-many-to-check must answer
        like names-the-container, not like names-nothing."""
        big = ",".join([f"x{i}" for i in range(64)] + ["crew"])
        assert _blocked(f"mv ~/.kiro/{{{big}}} /tmp/stash")

    def test_a_shadowed_navigation_verb_loses_the_carve_out(self) -> None:
        """`cd` can be a function. The carve-out spares an ordinary `cd`, and an
        ordinary `cd` does not appear in a command that also defines one."""
        assert _blocked('cd(){ mv "$1" /tmp/stash; }; cd ~/.kiro/crew')
        assert _blocked('function cd { mv "$1" /tmp/x; }; cd ~/.kiro/crew')
        assert _blocked("alias cd='mv'; cd ~/.kiro/crew /tmp/x")

    def test_the_carve_out_is_gone(self) -> None:
        """Superseded: there is no navigation exemption left to keep."""
        assert _blocked("cd ~/.kiro")
        assert _blocked("cd ~/.kiro/crew")
        # What replaces it as the "not everything is refused" guarantee:
        assert not _blocked("cd ~/.kiro/crew/sessions")

    def test_glob_matching_splits_on_either_separator(self) -> None:
        """`_home_dir_targets` yields NATIVE paths, so a Windows target is
        backslash-separated. Splitting on "/" alone gave one component, the length
        check never matched, and the glob arm silently passed everything -- green on
        macOS and absent on Windows."""
        from kiro_crew.security import _glob_could_name

        assert _glob_could_name("/x/y/*", {"/x/y/z"})
        assert _glob_could_name("/x/y/*", {r"\x\y\z"}), "a native Windows target must match"


class TestACustomDataHomeIsProtectedToo:
    """`KIROCREW_HOME` relocates the data home wholesale.

    An interpreter payload never tokenizes, so for a custom home the RAW scan is the
    only layer that can see it -- and anchoring solely on `~` left it invisible. With
    the variable set, that directory IS the container rather than a parent of one.
    """

    def test_the_configured_home_is_refused(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        assert _blocked("mv /opt/crewdata /tmp/stash")
        assert _blocked("python3 -c \"import os; os.rename('/opt/crewdata','/tmp/x')\"")

    def test_the_pattern_is_rebuilt_when_the_home_changes(self, monkeypatch) -> None:
        """The cache is keyed on the variable. A plain module-level cache would pin
        whatever it was at first call, and tests pin it per test -- so one built under
        a previous test's home would be reused, failing in the permissive direction."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata-one")
        assert _blocked("mv /opt/crewdata-one /tmp/x")
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata-two")
        assert _blocked("mv /opt/crewdata-two /tmp/x"), "the cached pattern went stale"

    def test_content_under_a_custom_home_is_still_reachable(self, monkeypatch) -> None:
        # Fixture root deliberately contains no "home" segment: the de-Amazon scrub's
        # identity scan treats a home-shaped path as a personal one, and an earlier
        # fixture root tripped it on a substring that was never a real home. Naming the
        # offending literal in this comment trips it again -- so it is described, not
        # quoted.
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        assert not _blocked("cat /opt/crewdata/sessions/a.json")


class TestBraceOverflowFailsClosedWithoutOverReaching:
    """Two opposite mistakes in one mechanism, and both were real.

    Bash expands braces before the command runs, so a token the matcher cannot fully
    enumerate is a token it cannot judge. The first version handled that by refusing
    ANY over-large brace expression, which refused `cp /data/img{a..z}{a..z}.jpg /out/`
    -- 676 ordinary expansions on a path that cannot be the trust root -- with a
    "governance trust root" message.

    It also stopped after a fixed number of passes and returned what it had, so nesting
    deeper than the limit left recognized braces UNEXPANDED and the token read as clean.

    The decision now hangs on the LITERAL PREFIX: everything before the first brace,
    which no expansion can change. If that cannot begin a protected path, the token is
    left alone; if it can, it is refused.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cp /data/img{a..z}{a..z}.jpg /out/",
            "ls /tmp/{a..z}{a..z}",
            "echo x{1..100}",
            "mv /var/log/{a,b,c}{1..40} /backup/",
        ],
    )
    def test_ordinary_large_expansions_are_untouched(self, command: str) -> None:
        assert not _blocked(command), (
            f"{command!r} was refused as a trust-root access; its literal prefix "
            "cannot reach a protected path"
        )

    @pytest.mark.parametrize(
        "command",
        [
            # Nine brace groups -- more than the pass limit, so an earlier revision
            # left them unexpanded and read the token as clean. Verified against bash:
            # this really does produce `~/.kiro/crew`.
            "mv ~/.kiro/{c,c}{r,r}{e,e}{w,w}{,}{,}{,}{,}{,} /tmp/x",
            "cat ~/.kiro/crew/{s,s}{e,e}curity_policy.json",
        ],
    )
    def test_a_protected_path_behind_deep_nesting_is_refused(self, command: str) -> None:
        assert _blocked(command), f"{command!r} reaches a protected path through braces"

    def test_the_decision_does_not_depend_on_where_the_home_lives(self) -> None:
        """The environment-independence, which CI caught and every local run missed.

        The first version asked whether the literal prefix is a prefix OF a protected
        root -- true of a bare `/tmp/` on any machine whose data home sits under `/tmp`,
        which is exactly what a CI runner does. So `ls /tmp/{a..z}{a..z}` was refused as
        a trust-root access there while passing here, and the difference was the
        runner's directory layout rather than anything about the command.

        Asserted against the ROOTS directly rather than through a fake `$HOME`: the
        target set is TTL-cached, so a test that moves `HOME` mid-process measures the
        cache instead of the change -- which is how I first "confirmed" a regression
        that was not there.
        """
        from kiro_crew.security import _BRACE_OVERFLOW_SENTINEL, _overflow

        # `/tmp/` is an ANCESTOR of a CI-shaped root
        # (`/tmp/pytest-of-runner/.../.kiro/crew`) but not a sibling, so it must not
        # trip.
        assert _overflow("/tmp/{a..z}{a..z}") != [_BRACE_OVERFLOW_SENTINEL]
        # And a genuine sibling still does.
        assert _overflow("~/.ki{r,r}{o,o}{/,/}{c,c}{r,r}{e,e}{w,w}{,}{,}") == [
            _BRACE_OVERFLOW_SENTINEL
        ]

    def test_the_overflow_decision_reads_the_literal_prefix(self) -> None:
        """Unit-level, because the two behaviours above are one function's answer."""
        from kiro_crew.security import _BRACE_OVERFLOW_SENTINEL, _expand_braces

        deep = "~/.kiro/" + "".join(f"{{{c},{c}}}" for c in "crew") + "{,}" * 5
        assert _expand_braces(deep) == [_BRACE_OVERFLOW_SENTINEL]

        wide = "/data/img" + "{a..z}{a..z}.jpg"
        assert _BRACE_OVERFLOW_SENTINEL not in _expand_braces(wide)

    def test_a_single_element_brace_is_not_an_expansion(self) -> None:
        """`{c}` has no comma and no range, so bash leaves it literal -- confirmed with
        `bash -c` while writing this. Treating it as an expansion would refuse text that
        never becomes a path."""
        from kiro_crew.security import _expand_braces

        assert _expand_braces("~/.kiro/{c}{r}{e}{w}") == ["~/.kiro/{c}{r}{e}{w}"]


class TestTheMatcherStopsPretendingToBeAShell:
    """Three more shell-grammar divergences, and one of them ended a class rather than
    patching it.

    `AGENTS.md` already says this layer "is not a bash parser" and cannot become one.
    That is the frame for all three: fix what is cheap and exact, remove what cannot be
    decided textually, and leave the sandbox hide list as the floor.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv cd ~/.kiro/crew /tmp/x",
            "echo cd ~/.kiro/crew",
            "install cd ~/.kiro/crew /tmp/x",
            'cd(){ mv "$1" /tmp/x; }; cd ~/.kiro/crew',
        ],
    )
    def test_no_navigation_exemption_survives(self, command: str) -> None:
        """The carve-out is GONE, not narrowed.

        It spared a container named as a `cd` operand, and identified that operand by
        looking at the preceding token -- so `mv cd ~/.kiro/crew` earned the exemption
        by containing the word `cd`. Even parsed correctly it would not have been
        evidence: `cd` is a builtin a function or alias can shadow. Deciding what a
        token MEANS needs a shell.

        `ls cd ~/.kiro/crew /tmp/x` was here instead of `install`, and #6021's
        exoneration retired it from this list rather than failing it: unlike the other
        three, `ls` genuinely cannot rename or replace anything regardless of which
        words follow it, so treating it as a spoofing decoy for a WRITER conflated two
        different questions. It is exercised on its own merits in
        `TestBareTrustRootReadsAlsoExemptTheContainerGate` below.
        """
        assert _blocked(command)

    def test_removing_it_costs_only_the_container_itself(self) -> None:
        """The match is exact, so the blast radius is one path, not the data home."""
        for allowed in (
            "cd ~/.kiro/crew/sessions",
            "ls ~/.kiro/crew/skills",
            "cat ~/.kiro/crew/logs/gateway.log",
        ):
            assert not _blocked(allowed), f"{allowed!r} is ordinary agent work"

    @pytest.mark.parametrize(
        "command",
        ["mv ~/.kiro/cr{a..z..1}w /tmp/x", "mv ~/.kiro/cr{e..e..1}w /tmp/x"],
    )
    def test_a_stepped_range_expands(self, command: str) -> None:
        """`{a..z..2}` is bash 4+ syntax. Unhandled, the whole range matched nothing, so
        the token expanded to itself and read as clean."""
        assert _blocked(command)

    def test_step_expansion_matches_the_shell(self) -> None:
        """Checked against zsh while writing this -- `{1..9..3}` really is `1 4 7`.
        macOS's bash 3.2 does not support the form at all, which is why expanding is the
        safe direction: the deployment shell (bash 5.x on Linux) does."""
        from kiro_crew.security import _expand_braces

        assert _expand_braces("{1..9..3}") == ["1", "4", "7"]
        assert _expand_braces("{a..e..2}") == ["a", "c", "e"]
        assert _expand_braces("{e..a..2}") == ["e", "c", "a"]
        # A zero step is ignored by bash rather than being an error.
        assert _expand_braces("{1..3..0}") == ["1", "2", "3"]

    def test_dotglob_makes_a_bare_star_reach_the_container(self) -> None:
        """`*` does not match a leading dot -- unless `dotglob` is on, and then `~/*`
        names `~/.kiro`."""
        assert _blocked("shopt -s dotglob; mv ~/* /tmp/x")
        assert _blocked("setopt globdots; mv ~/* /tmp/x")

    def test_without_dotglob_an_ordinary_home_listing_is_untouched(self, monkeypatch) -> None:
        """The reason this is conditional rather than always-on: refusing `ls ~/*`
        outright would be a false positive on one of the commonest commands there is.

        Ancestor discovery is stubbed to empty here, deliberately: this test's own
        `KIROCREW_HOME` is whatever the autouse test-isolation fixture pinned it to
        (nowhere near a real `.kiro`-shaped home), and on Windows that pinned path
        is nested INSIDE the real user profile -- unlike POSIX, where a temp root
        and `$HOME` are normally disjoint trees, Windows' `%TEMP%` sits under
        `C:\\Users\\<user>\\...`. Walking up from it lands on an ANCESTOR one level
        under home (`AppData`) that, unlike the FIXED container dirs this test
        means to exercise, is not dot-prefixed -- so it carries none of the
        dotfile protection the assertion below is actually testing, and a bare
        `mv ~/* /tmp/x` legitimately (and correctly) matches it under
        `bare_trust_root_read`'s write-verb fail-closed direction. That is a
        property of this TEST's own isolation setup, not of a real KIROCREW_HOME
        -- which is always `.kiro`-shaped by this project's own convention -- so
        it is isolated here rather than accepted as a false positive."""
        monkeypatch.setattr(security, "_custom_home_ancestors", lambda: [])
        assert not _blocked("ls ~/*")
        assert not _blocked("mv ~/* /tmp/x")


class TestTheRawGateCoversWindowsAndPosixClasses:
    """Two more spellings, and both were mine to have covered already.

    The pattern in each: I wrote a second, narrower version of something the leaf gate
    beside me already did properly. That is the same mistake as re-deriving the
    `$skill` token shape, and it fails in the permissive direction every time.
    """

    @pytest.mark.parametrize(
        "command",
        [
            r"move C:\Users\me\.kiro\crew D:\tmp",
            r"move %USERPROFILE%\.kiro\crew D:\x",
            r"Move-Item $env:USERPROFILE\.kiro\crew D:\x",
        ],
    )
    def test_native_windows_spellings_are_refused(self, command: str) -> None:
        """The raw scan is the ONLY layer that sees these: POSIX shlex eats backslashes
        during tokenization, and an embedded interpreter script never tokenizes at all.
        The leaf regex has had a Windows arm for a long time; this pattern was written
        with `/` alone."""
        assert _blocked(command), f"{command!r} names the container in native spelling"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cre[[:alpha:]] /tmp/x",
            "cat ~/.kiro/crew/[[:lower:]]ecurity_policy.json",
        ],
    )
    def test_posix_character_classes_are_refused(self, command: str) -> None:
        """`[[:alpha:]]` matches ONE character, but `fnmatch.translate` renders the
        inner `[:alpha:]` literally, so the pattern matched nothing and read as clean."""
        assert _blocked(command)

    def test_a_class_on_an_unrelated_path_is_untouched(self) -> None:
        """Reduced to `?`, not to "refuse anything containing a bracket"."""
        assert not _blocked("ls /data/[[:digit:]]*.log")
        assert not _blocked("rm /tmp/[[:alpha:]]*.tmp")

    def test_the_windows_branch_is_built_from_the_leaf_arm(self) -> None:
        """Structural, because the gap was a SECOND spelling rather than a missing one.

        The container pattern must carry a Windows alternation at all; a future edit
        that drops it takes the native spellings with it and nothing else notices.
        """
        from kiro_crew.security import _get_container_re

        pattern = _get_container_re().pattern
        assert "USERPROFILE" in pattern, "the container pattern lost its Windows arm"
        assert "[A-Za-z]:" in pattern, "the drive-letter anchor is gone"


class TestMoreShellSpellings:
    """Three more, of which two were ordinary logic bugs rather than grammar gaps."""

    @pytest.mark.parametrize(
        "command",
        ["mv ~/.k$'i'ro/crew /tmp/stash", "mv ~/.k$'i'r$'o'/crew /tmp/x"],
    )
    def test_ansi_c_quoting_is_unwrapped(self, command: str) -> None:
        """`$'i'` is `i` to the shell, so a path can be spliced through it a letter at
        a time and reassembled after both scans pass."""
        assert _blocked(command)

    def test_an_ordinary_ansi_c_string_is_untouched(self) -> None:
        assert not _blocked("echo $'hello' > /tmp/x")

    def test_bash_option_flags_count_as_dotglob(self) -> None:
        """`bash -O dotglob -c ...` enables it without ever running `shopt`, so a scan
        for the builtin alone reads it as disabled."""
        assert _blocked("bash -O dotglob -c mv ~/* /tmp/x")
        assert _blocked("shopt -s dotglob; mv ~/* /tmp/x")
        assert not _blocked("ls ~/*")

    def test_a_key_value_operand_is_expanded_before_extraction(self) -> None:
        """A logic-order bug, not a grammar gap.

        `_path_candidates` appended the RAW `key=value` right-hand side beside the
        expanded candidates, so `dd of=$HOME/.kiro/cr{e..e}w/...` produced two useless
        ones: the expanded whole token (not path-like, because of the `of=` prefix) and
        the unexpanded value (still carrying braces). Neither named the path.
        """
        assert _blocked("dd of=$HOME/.kiro/cr{e..e}w/security_policy.json")
        assert not _blocked("dd of=/tmp/out.img if=/dev/zero")


class TestAConfiguredHomeSurvivesWindowsNormalization:
    """CI-only failure, made reproducible here.

    `_build_container_regex` anchored the custom-home branch on
    `abspath(expanduser(KIROCREW_HOME))`. On Windows that rewrites a POSIX-shaped
    `/opt/crewdata` into `D:\\opt\\crewdata` — current drive, backslashes — so the
    pattern named a string that appears nowhere in `os.rename('/opt/crewdata', ...)`.
    The operand pass still normalized `mv /opt/crewdata ...` and caught it, which is
    why only the interpreter-payload form went red: the raw scan is the one layer
    that sees inside a `-c` payload, and it compares TEXT.
    """

    def test_the_configured_spelling_matches_when_abspath_rewrites_it(self, monkeypatch) -> None:
        """Simulates the Windows rewrite on any platform, so this cannot regress
        silently on the four fifths of CI that are not Windows."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        real_abspath = os.path.abspath
        monkeypatch.setattr(
            os.path,
            "abspath",
            lambda p: "D:\\opt\\crewdata" if p == "/opt/crewdata" else real_abspath(p),
        )
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("python3 -c \"import os; os.rename('/opt/crewdata','/tmp/x')\"")
        assert _blocked("mv /opt/crewdata /tmp/stash")

    def test_either_separator_matches_whichever_was_configured(self, monkeypatch) -> None:
        """An operator may configure `C:/data/crew` and then type `C:\\data\\crew`."""
        monkeypatch.setenv("KIROCREW_HOME", "D:/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv D:\\opt\\crewdata C:\\stash")
        assert _blocked("mv D:/opt/crewdata /tmp/x")
        assert not _blocked("mv D:/opt/other /tmp/x")

    @pytest.mark.parametrize("degenerate", ["/", "\\", "C:\\", "C:/"])
    def test_a_bare_root_fences_nothing(self, monkeypatch, degenerate: str) -> None:
        """A root names the whole filesystem, not a container. A branch matching it
        would refuse every absolute path in every command."""
        monkeypatch.setenv("KIROCREW_HOME", degenerate)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("cat /etc/hosts")
        assert not _blocked("ls /home")


class TestTheTailFailsClosed:
    """The terminator enumerated what may FOLLOW the container name, so every shell
    operator nobody listed ended the match and carried the path through. Inverted to
    enumerate what CONTINUES a pathname, an unforeseen spelling is refused instead.

    These cases are the evidence for the inversion, not the specification of it --
    the specification is that an unlisted character terminates. Adding a spelling
    here is welcome; needing to add a matching branch in `security.py` for it is the
    signal that the inversion has been undone.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # An operator welded to the path. `bash` ends the word at each of these,
            # so every one of them still names the container.
            "mv ~/.kiro/crew>/dev/null /tmp/stash",
            "mv ~/.kiro/crew>>log /tmp/stash",
            "mv ~/.kiro/crew|cat /tmp/x",
            "mv ~/.kiro/crew&& true",
            "mv ~/.kiro/crew&",
            "mv ~/.kiro/crew<in /tmp/x",
            # An expansion welded on that expands to nothing, so the word is the
            # container after expansion.
            "mv ~/.kiro/crew$(true) /tmp/stash",
            "mv ~/.kiro/crew`true` /tmp/x",
            "mv ~/.kiro/crew${EMPTY} /tmp/x",
        ],
    )
    def test_an_operator_welded_to_the_path_still_names_it(self, command: str) -> None:
        assert _blocked(command), f"{command!r} reaches the container"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ${HOME:0}/.kiro/crew /tmp/stash",
            "mv ${HOME:-/root}/.kiro/crew /tmp/x",
            "mv ${HOME##*/}/.kiro/crew /tmp/x",
            "mv ${HOME}/.kiro/crew /tmp/x",
        ],
    )
    def test_a_parameter_operator_does_not_hide_the_home(self, command: str) -> None:
        """`${HOME:0}` is `$HOME`. Enumerating the operators would repeat the
        fail-open mistake, so anything up to the closing brace counts -- which can
        only ever refuse a command, never admit one."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            # Deeper than the container: the leaf gate's business, not this one's.
            "ls ~/.kiro/crew/sessions",
            "cat ~/.kiro/crew/memory/notes.md",
            "ls ~/.kiro/crew/logs/today.log",
            # A sibling whose name merely starts the same way.
            "ls ~/.kiro/crewold",
            "ls ~/.kiro/crew-backup",
            # A variable that merely starts with HOME.
            "echo $HOMEBREW_PREFIX",
        ],
    )
    def test_the_inversion_does_not_over_claim(self, command: str) -> None:
        assert not _blocked(command), f"{command!r} is not the container"

    def test_a_deeper_path_keeps_the_leaf_gates_own_refusal(self) -> None:
        """Regression: the first cut of the inversion let `crew/` be followed by
        anything, so this gate swallowed `~/.kiro/crew/$F` and replaced the leaf
        gate's precise `unresolved shell variable` refusal with its own. Beyond
        losing the better message, claiming everything under `crew/` would fence the
        agent out of its own `sessions/`, `memory/` and `logs/`.
        """
        reason = security.is_sensitive_bash_command("F=security_policy.json; cat ~/.kiro/crew/$F")
        assert reason is not None
        assert "must not be replaced" not in reason.lower()


class TestGlobModesAreModelledNotAssumed:
    """`_glob_could_name` answers "could this pattern name a protected path", and the
    answer depends on shell options that change what a glob MEANS. Assuming the
    defaults made the evaluator confidently wrong whenever one was enabled.
    """

    def test_globignore_enables_dotfile_matching(self) -> None:
        """Setting `GLOBIGNORE` to anything non-empty turns dotfile matching on as a
        documented side effect, without the word `dotglob` appearing anywhere.
        Verified against bash: `GLOBIGNORE=zz; echo *` lists `.kiro`."""
        assert _blocked("GLOBIGNORE=x; mv ~/* /tmp/x")
        assert not _blocked("echo GLOBIGNORE=")

    @pytest.mark.parametrize(
        "command",
        [
            "shopt -s globstar; mv ~/**/crew /tmp/x",
            "bash -O globstar -c mv ~/**/crew /tmp/x",
            "shopt -s globstar dotglob; mv ~/**/crew /tmp/x",
        ],
    )
    def test_globstar_defeats_the_fixed_depth_comparison(self, command: str) -> None:
        """`**` spans any number of components, so comparing component COUNTS -- which
        is right for `*`, since it never crosses a separator -- stops holding."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["shopt -s extglob; mv ~/@(.kiro)/crew /tmp/x", "shopt -s extglob; mv ~/!(x)/crew /tmp/x"],
    )
    def test_an_extglob_group_is_not_read_literally(self, command: str) -> None:
        """`fnmatch` renders `@(...)` literally, so the group matched nothing at all and
        the token read as clean. Note this token contains none of `*?[`, so the
        substitution has to happen BEFORE the "not a glob" exit."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            "ls ~/*",
            "ls ~/Documents/*",
            "mv ~/**/crew /tmp/x",
            "shopt -s globstar; ls ~/Documents/**/*.md",
            "shopt -s extglob; ls ~/Documents/@(a|b).md",
            "shopt -s extglob; echo hello",
        ],
    )
    def test_an_ordinary_glob_stays_ordinary(self, command: str) -> None:
        """The modes are MODELLED rather than treated as "refuse everything from here":
        enabling one must not turn an unrelated listing into a refusal."""
        assert not _blocked(command)


class TestADollarInFrontOfAQuoteIsDropped:
    """`$'…'` and `$"…"` both make the shell drop the marker and keep the text, so a
    path can be spliced through one and reassembled after every scan.

    Handled as ONE class in `_DOLLAR_QUOTE_RE`. Two forms arrived as separate findings
    a round apart; a third belongs in that alternation, not as another independent
    regex elsewhere in the file. That is the point these cases pin.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # Locale translation. With no message catalogue `$"i"` is `i`, and the
            # catalogue belongs to the operator either way.
            'mv ~/.k$"i"ro/crew /tmp/stash',
            'mv ~/.kiro/$"crew" /tmp/x',
            'mv $"~"/.kiro/crew /tmp/x',
        ],
    )
    def test_locale_quotes_are_unwrapped(self, command: str) -> None:
        assert _blocked(command), f"bash resolves {command!r} to the container"

    def test_an_ordinary_locale_string_is_untouched(self) -> None:
        assert not _blocked('echo $"hello" > /tmp/x')


class TestAnsiCEscapesAreDecoded:
    def test_an_escape_that_spells_a_path_character(self) -> None:
        """`$'\\x69'` is `i`. Skipping any fragment containing a backslash was the same
        fail-open shape as enumerating terminators -- the rationale for skipping them
        (that a `\\n` in a path component does not help) was simply wrong: a hex or
        octal escape produces an ordinary letter."""
        assert _blocked(r"mv ~/.k$'\x69'ro/crew /tmp/x")
        assert _blocked(r"mv ~/.k$'\151'ro/crew /tmp/x")

    @pytest.mark.parametrize("command", [r"echo $'a\tb' > /tmp/x", r"printf $'line\n' > /tmp/x"])
    def test_an_ordinary_escape_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestABraceWithNoLiteralPrefix:
    def test_an_absent_prefix_rules_nothing_out(self) -> None:
        """The overflow decision rests on the literal prefix precisely because no
        expansion can change it. `{a,...,~/.kiro/crew}` has no prefix at all, so it
        decides nothing -- and "decides nothing" was being read as "decided clean"."""
        big = ",".join(f"/tmp/x{i}" for i in range(80))
        assert _blocked("mv {" + big + ",~/.kiro/crew} /tmp/z")

    def test_a_large_ordinary_brace_is_still_allowed(self) -> None:
        """The reason the decision is made on the prefix at all: refusing every
        oversized brace called `cp /data/img{a..z}{a..z}.jpg` a trust-root access."""
        assert not _blocked("cp /data/img{a..z}{a..z}.jpg /out/")


@pytest.mark.skipif(
    not platform_compat.IS_POSIX,
    reason=(
        "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
        "`os.getuid()`, which Windows does not have. Asserting on it there would be "
        "asserting on an artifact that platform never produces -- the Windows sandbox "
        "is a different mechanism entirely. `_data_home_equivalents` itself is "
        "platform-neutral and is covered below on every platform."
    ),
)
class TestTheHideListFollowsTheDataHome:
    """The sandbox hide list is the layer this PR's own reasoning leans on: the command
    gate reads TEXT and cannot see inside `./script` or `make install`, so hiding the
    paths is what does not depend on the write being spelled out. Every entry was
    spelled relative to `~`, which quietly assumed the data home sits where it does by
    default -- so under `KIROCREW_HOME` the list covered a directory that does not
    exist while the real keystone files stayed readable.
    """

    def test_a_custom_home_is_hidden_too(self, monkeypatch, tmp_path) -> None:
        """Asserted on the LAUNCHER SCRIPT, not on the helper.

        Checking the helper's return value alone passes even when nothing calls it --
        which it did, when the wiring was mutated away to check exactly that.
        """
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("strict")
        for leaf in ("profiles", ".vault"):
            expected = str(tmp_path / "crewdata" / leaf)
            assert expected in script, f"{expected} is not hidden under a custom data home"

    def test_the_keystone_files_follow_it_as_well(self, monkeypatch, tmp_path) -> None:
        """`_CC_FILES` is anchored on `~` by a separate join, so it needed the same
        treatment -- the FILE-shaped keystone leaves are not reached by the directory
        entries."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("cc")
        for leaf in ("security_policy.json", "admission_policy.json", "computer_use.json"):
            assert str(tmp_path / "crewdata" / leaf) in script, leaf

    def test_a_neighbour_of_the_data_home_does_not_move_with_it(
        self, monkeypatch, tmp_path
    ) -> None:
        """`~/.kiro/crew-auth-staging` sits BESIDE the data home, not inside it.
        Re-anchoring it would point the hide list at a path that never exists."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("strict")
        assert str(tmp_path / "crewdata" / "crew-auth-staging") not in script


class TestTheDataHomeReanchoringItself:
    """Platform-neutral half, deliberately OUTSIDE the launcher-script class above.

    That class can only run where the Linux launcher can be built, so keeping every
    assertion inside it left Windows -- the platform whose path handling differs most
    -- covering none of this.
    """

    @pytest.mark.parametrize("leaf", [".vault"])
    def test_a_crew_relative_entry_is_reanchored(self, monkeypatch, tmp_path, leaf) -> None:
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        got = sandbox._data_home_equivalents(sandbox._STRICT_DIRS)
        assert any(os.path.basename(path) == leaf for path in got), leaf

    def test_a_neighbour_is_not_reanchored(self, monkeypatch, tmp_path) -> None:
        """`~/.kiro/crew-auth-staging` sits BESIDE the data home, not inside it."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        got = sandbox._data_home_equivalents(sandbox._STRICT_DIRS)
        assert not any("crew-auth-staging" in path for path in got)

    def test_the_default_relative_entries_are_kept(self, monkeypatch, tmp_path) -> None:
        """Not replaced: a default install resolves to the same place anyway, and a box
        part-way through a data-home move can hold real bytes at both."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        assert ".kiro/crew/.vault" in sandbox._STRICT_DIRS
        assert ".kirocrew/.vault" in sandbox._STRICT_DIRS


class TestRepeatedTrailingSeparators:
    def test_two_slashes_are_one_directory(self) -> None:
        """`~/.kiro/crew//` is `~/.kiro/crew` to every OS. The operand pass normalizes
        it away and caught this; the raw scan compares TEXT and matched one trailing
        separator but not two -- so only the interpreter-payload form got through,
        the same asymmetry as the Windows `abspath` bug earlier in this PR."""
        payload = (
            "python3 -c \"import os;os.rename(os.path.expanduser('~/.kiro/crew//'),'/tmp/x')\""
        )
        assert _blocked(payload)
        assert _blocked(payload.replace("crew//", "crew///"))

    def test_a_deeper_path_is_still_not_the_container(self) -> None:
        assert not _blocked("ls ~/.kiro/crew/sessions")


class TestAnEmptyExpansionRebuildsThePath:
    """An unset variable expands to nothing, so a path can be split around one and
    reassembled by the shell after both scans have read it as an unrelated string."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/${UNSET}crew /tmp/x",
            "mv ~/.kiro/cr${U}ew /tmp/x",
            "mv ~/.ki${U}ro/crew /tmp/x",
            # Braced only. `$UNSETcrew` is a variable NAMED `UNSETcrew` to bash, so it
            # expands to nothing at all rather than leaving `crew` behind -- the brace
            # is what ends the name early enough to weld a literal onto it.
            "mv ~/.kiro/${U}crew /tmp/x",
        ],
    )
    def test_an_expansion_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    def test_an_expansion_that_is_a_whole_component_is_left_alone(self) -> None:
        """`~/.kiro/crew/$F` must NOT collapse to `~/.kiro/crew/`.

        Welded into a component the expansion changes that component's NAME; alone it
        merely names a child, and the leaf gate already refuses that with the more
        accurate `unresolved shell variable`. Collapsing it here made this gate claim
        every deeper path ending in a variable -- caught by the existing suite, not by
        a test written for it.
        """
        reason = security.is_sensitive_bash_command("F=security_policy.json; cat ~/.kiro/crew/$F")
        assert reason is not None
        assert "must not be replaced" not in reason.lower()

    def test_an_ordinary_variable_path_is_untouched(self) -> None:
        assert not _blocked("ls $HOME/Documents")
        assert not _blocked("echo $PATH")


class TestABraceAlternativeThatCarriesASeparator:
    def test_an_alternative_can_reach_below_the_prefix(self) -> None:
        """The sibling rule completes exactly ONE component, which is all a
        separator-free alternative can add. `~/{a0,…,.kiro/crew}` has the harmless
        prefix `~/` and still names the container."""
        many = ",".join(f"a{i}" for i in range(70))
        assert _blocked("mv ~/{" + many + ",.kiro/crew} /tmp/x")

    def test_the_documented_tmp_case_stays_allowed(self) -> None:
        """Guarded by requiring a separator in the brace body. Without that guard this
        rule re-breaks `ls /tmp/{a..z}{a..z}` on a machine whose data home sits under
        `/tmp` -- a false positive that was already found and fixed once, and those
        single-character alternatives cannot produce the `/` such a reach would need.
        """
        assert not _blocked("ls /tmp/{a..z}{a..z}")
        assert not _blocked("cp /data/img{a..z}{a..z}.jpg /out/")


class TestAnAbsurdBraceStepDoesNotCrashTheGate:
    def test_a_step_too_long_to_parse(self) -> None:
        """CPython refuses to parse an integer past
        `sys.int_info.str_digits_check_threshold` and raises, so a 4,400-digit step
        took `ValueError` straight out through `_expand_braces` and aborted the
        tool-approval path. A gate that raises is a gate that is not answering.
        """
        command = "echo {1..2.." + "9" * 4400 + "}"
        assert security.is_sensitive_bash_command(command) is not None

    def test_an_ordinary_step_still_expands(self) -> None:
        assert not _blocked("echo {1..9..2}")
        assert _blocked("mv ~/.kiro/cr{e..e..1}w /tmp/x")


class TestPerCommandWorkHappensOncePerCommand:
    """Asserted as an invocation SHAPE, not a duration.

    `testing-conventions` § Determinism: a timed threshold false-reds on a shared
    runner. The defect here is structural and can be observed structurally -- work
    whose answer cannot vary between operands was being redone for every candidate.
    """

    def test_glob_modes_are_computed_once_regardless_of_operand_count(self, monkeypatch) -> None:
        """`_glob_modes` runs three regex scans over the WHOLE command text, and the
        answer is a property of the command, not of the operand being checked. Called
        per candidate it was 4,802 calls -- 14,406 full-text scans -- for one 9 KB
        command, and 2.3s of its 5.4s.

        Pinned by doubling the operand count and requiring the SAME call count: a
        per-candidate regression shows up as a number that grows with the input, with
        no dependence on how fast the machine is.
        """
        calls: list[str] = []
        real = security._glob_modes
        monkeypatch.setattr(
            security,
            "_glob_modes",
            lambda command: (calls.append(command), real(command))[1],
        )

        def count_for(operands: int) -> int:
            calls.clear()
            brace = "{" + ",".join(f"a{i}" for i in range(8)) + "}"
            command = "cp " + " ".join(f"/data/{brace}/f{j}" for j in range(operands)) + " /out/"
            security.is_sensitive_bash_command(command)
            return len(calls)

        assert count_for(2) == count_for(4) == count_for(8)

    def test_one_command_cannot_expand_without_bound(self) -> None:
        """`_MAX_BRACE_EXPANSIONS` bounds ONE token, which is a different bound: many
        operands each just under it never trip the overflow path while together they
        are unbounded. The budget is per command and shared across its operands.

        It is NOT what makes the pathological case fast -- see the class docstring in
        `security.py`; the expansions themselves cost single-digit milliseconds. It
        bounds work that was otherwise unbounded, which is worth doing on its own.
        """
        budget = security._ExpansionBudget(total=100)
        assert budget.spend(60) is True
        assert budget.spend(60) is False

    def test_an_exhausted_budget_degrades_to_the_overflow_reading(self) -> None:
        """Fail-closed, and gracefully: an overrun token takes the same reading an
        oversized one does, so a benign prefix is still allowed through unexpanded
        while one that could reach a protected root is refused."""
        budget = security._ExpansionBudget(total=1)
        out = security._expand_braces("/data/img{a,b,c}.jpg", budget)
        assert out == ["/data/img{a,b,c}.jpg"]
        budget2 = security._ExpansionBudget(total=1)
        assert security._expand_braces("~/.kiro/cr{e,f}w", budget2) == [
            security._BRACE_OVERFLOW_SENTINEL
        ]


class TestEveryUnresolvedExpansionVanishes:
    """An expansion that resolves to nothing lets a path be split around it and
    reassembled by the shell after every scan has read it as an unrelated string.

    The first cut listed the forms it knew -- `${NAME}` and `$NAME` -- which is the
    same fail-open shape as enumerating terminators, and `${A[@]}` walked through the
    gap. What is listed now is `${…}` with ANY content, plus both command-substitution
    spellings, because those vanish for exactly the same reason.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.ki${A[@]}ro/crew /tmp/x",
            "mv ~/.ki${A:-}ro/crew /tmp/x",
            "mv ~/.ki${!A}ro/crew /tmp/x",
            # Command substitution producing nothing, both spellings. Not reported;
            # found while confirming the array case, and verified against bash --
            # `echo ~/.ki$(true)ro/crew` prints the container.
            "mv ~/.ki$(true)ro/crew /tmp/x",
            "mv ~/.ki`true`ro/crew /tmp/x",
        ],
    )
    def test_a_vanishing_expansion_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["ls $HOME/Documents", "echo $(date) > /tmp/x", "echo `date` > /tmp/x"],
    )
    def test_ordinary_expansions_are_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestBashsOtherBracketNegation:
    def test_a_caret_negates_exactly_like_a_bang(self) -> None:
        """`[^x]` and `[!x]` are the same thing in bash. `fnmatch` reads a leading `^`
        as an ordinary set MEMBER and escapes it -- `translate("cre[^x]")` gives
        `cre[\\^x]` -- so the pattern matched nothing at all and read as clean, while
        the `!` spelling was handled correctly all along.
        """
        assert _blocked("mv ~/.kiro/cre[^x] /tmp/x")
        assert _blocked("mv ~/.kiro/cre[!x] /tmp/x")

    def test_an_unrelated_bracket_glob_is_untouched(self) -> None:
        assert not _blocked("ls /data/f[^x].txt")


class TestLineContinuations:
    def test_a_continuation_is_removed_before_matching(self) -> None:
        """The shell deletes a backslash-newline during lexing, so the characters on
        either side join into one word -- and each half is inert on its own, which is
        why both the raw and the normalized pass read this as clean."""
        assert _blocked("mv ~/.kiro/cre\\\nw /tmp/x")
        assert _blocked("mv ~/.ki\\\nro/crew /tmp/x")

    def test_an_ordinary_continuation_is_untouched(self) -> None:
        assert not _blocked("cp /a/b \\\n /tmp/x")


class TestAnUnknownSubstitutionOutput:
    """An unset expansion vanishes; a substitution's output does NOT.

    `$(printf i)` contributes `i`, so the empty-expansion reading -- which models every
    expansion as producing nothing -- reads `~/.k$(printf i)ro/crew` as `~/.kro/crew`
    and finds nothing. The output cannot be known without running the command, which is
    the one thing a gate must not do, so it is treated as UNKNOWN rather than as empty:
    the substitution becomes a `*` and the existing glob machinery answers.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.k$(printf i)ro/crew /tmp/x",
            "mv ~/.k`printf i`ro/crew /tmp/x",
            "mv ~/.kiro/cr$(printf e)w /tmp/x",
        ],
    )
    def test_output_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            "echo $(date) > /tmp/x",
            "echo `date`",
            "cp $(ls /data) /out/",
            "cp $(which python) /tmp/x",
            "tar -czf /tmp/b.tgz $(find /data -name '*.log')",
        ],
    )
    def test_an_ordinary_substitution_is_untouched(self, command: str) -> None:
        """The refusal is not "a command contains a substitution" -- it is "a
        substitution sits where a container component would be"."""
        assert not _blocked(command)

    def test_the_word_is_masked_before_it_is_split(self) -> None:
        """A substitution contains whitespace of its own. Splitting first tore
        `~/.k$(printf i)ro/crew` into `~/.k$(printf` and `i)ro/crew`, and neither half
        resembles anything -- the first cut of this check silently found nothing."""
        assert _blocked("mv ~/.k$(printf   i)ro/crew /tmp/x")


class TestTheConfiguredHomeVariableItself:
    def test_any_spelling_of_the_variable_names_the_container(self, monkeypatch) -> None:
        """`$KIROCREW_HOME` and `${KIROCREW_HOME}` already resolved through
        `expandvars`; `${KIROCREW_HOME:-/tmp/no}` did not. Every spelling of that name
        refers to this container by definition, whatever operator is attached -- so the
        VARIABLE is matched, not just the value it currently holds."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('mv "${KIROCREW_HOME:-/tmp/no}" /tmp/x')
        assert _blocked("mv $KIROCREW_HOME /tmp/x")
        assert _blocked("mv ${KIROCREW_HOME} /tmp/x")

    def test_an_unrelated_variable_is_untouched(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo ${KIROCREW_HOMEBREW:-x}")
        assert not _blocked("ls $HOME/Documents")


@pytest.mark.skipif(
    not sys.platform.startswith("darwin"),
    reason="Seatbelt profile text is macOS's mechanism; the Linux launcher is asserted above.",
)
class TestTheSeatbeltProfileMatchesTheLinuxLauncher:
    """macOS enforces through Seatbelt rules, not bind mounts, and the two were fixed
    in different places -- so the launcher's coverage said nothing about this one.

    Both halves had gaps: the file rules emitted `file-read*` and `file-link` but no
    `file-write*`, so hiding the governance ceiling from a subprocess did nothing to
    stop the same subprocess OVERWRITING it; and both the dir and file loops built
    their paths as `os.path.join(Path.home(), …)`, so under `KIROCREW_HOME` every rule
    named a path that does not exist.
    """

    def _profile(self, tier: str) -> str:
        from kiro_crew import sandbox

        return sandbox._build_seatbelt_profile(tier)

    @pytest.fixture
    def crew_root(self, monkeypatch, tmp_path) -> str:
        from kiro_crew.config.paths import config_dir

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        # `config_dir()` resolves symlinks -- on macOS `/var` is `/private/var` -- so
        # the expected path has to come from the resolver, not from `tmp_path`.
        return str(config_dir())

    @pytest.mark.parametrize("tier", ["standard", "cc", "strict"])
    def test_a_keystone_file_is_read_and_WRITE_denied(self, crew_root, tier) -> None:
        """Write, not just read. Forging `autonudge.json` after a reload is the
        same class of bypass `_KEYSTONE_FILES` closes for a subprocess. The other
        keystone JSON files (`security_policy.json`, `admission_policy.json`,
        `computer_use.json`, `denied_commands.json`) moved to the READONLY
        disposition (#7439) -- in-sandbox code READS them, so they stay
        write-denied but WITHOUT a read-deny; that coupling is covered by
        `test_sandbox_governance_mask.py::TestKeystonesAreSealedInEveryMode`,
        which asserts the read-deny's ABSENCE as part of the same property.
        """
        profile = self._profile(tier)
        target = os.path.join(crew_root, "autonudge.json")
        assert '(deny file-read* (literal "%s"))' % target in profile
        assert '(deny file-write* (literal "%s"))' % target in profile

    def test_credential_files_keep_read_only_denial(self, crew_root) -> None:
        """`.npmrc` and `.git-credentials` are read-denied but NOT write-denied: npm and
        git write to them legitimately, and turning that into a hard failure is a
        separate decision from closing the governance ceiling."""
        profile = self._profile("cc")
        npmrc = os.path.join(os.path.expanduser("~"), ".npmrc")
        assert '(deny file-read* (literal "%s"))' % npmrc in profile
        assert '(deny file-write* (literal "%s"))' % npmrc not in profile


class TestTheContainerItselfCannotBeMoved:
    """The subprocess half of this PR's own thesis.

    `security.is_unreplaceable_container` refuses a COMMAND that names the container,
    but a subprocess is one opaque token to that gate: `./script.sh` containing
    `mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew` is never inspected.
    Every other list here hides CONTENTS, and content-hiding cannot help -- after the
    rename each leaf rule names a path the attacker has already emptied.

    So the sandbox has to protect the directory ENTRY, and it does it differently on
    each platform: Linux binds the container onto itself (a mount point cannot be
    renamed, EBUSY), macOS denies `file-write*` on the literal path.
    """

    @pytest.fixture
    def crew_root(self, monkeypatch, tmp_path) -> str:
        from kiro_crew.config.paths import config_dir

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        return str(config_dir())

    def test_the_resolved_data_home_is_listed(self, crew_root) -> None:
        from kiro_crew import sandbox

        assert crew_root in sandbox._unrenamable_containers()

    def test_the_default_locations_are_listed_too(self, crew_root) -> None:
        """Both spellings, for the same reason the hide lists keep both: a default
        install resolves to one of them, and a box mid-move can have real bytes at
        either."""
        from kiro_crew import sandbox

        listed = sandbox._unrenamable_containers()
        home = str(pathlib.Path.home())
        assert os.path.join(home, ".kiro/crew") in listed
        assert os.path.join(home, ".kirocrew") in listed

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_linux_launcher_binds_each_container_onto_itself(self, crew_root) -> None:
        """A bind of a directory over itself is transparent -- same contents, still
        writable -- but it makes the directory a mount point, and Linux refuses to
        rename one."""
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        assert "UNRENAMABLE_DIRS" in script
        assert crew_root in script
        # Through `_mount_or_die`, like every other mount in this launcher -- a bare
        # `_libc.mount` call here would silently fail open, and this specific mount is
        # the one this whole class exists to make un-defeatable.
        assert '_mount_or_die(target, target, _MS_BIND, "protecting data-home' in script

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_self_bind_happens_BEFORE_the_masking_mounts(self, crew_root) -> None:
        """Ordering, and it is the whole correctness of this mount.

        `MS_BIND` without `MS_REC` copies only the mount at that point and NOT the
        submounts beneath it. So binding the container AFTER the masking loops produces
        a fresh view of the container in which `profiles/` and `variables/` are the
        original directories again -- this protection silently undoing the one it sits
        inside, with every individual assertion about either one still passing.

        Nothing about a single mount call can express that, so the order is what gets
        pinned: self-bind, then the directory masks, then the file masks.
        """
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        self_bind = script.index("for d in UNRENAMABLE_DIRS:")
        dir_masks = script.index("for d in SENSITIVE_DIRS:")
        file_masks = script.index("for f in SENSITIVE_FILES:")
        assert self_bind < dir_masks < file_masks, (
            "the container self-bind must precede the masking mounts; a non-recursive "
            "bind applied afterwards discards them"
        )

    @pytest.mark.skipif(
        not sys.platform.startswith("darwin"), reason="Seatbelt profile text is macOS's."
    )
    @pytest.mark.parametrize("tier", ["standard", "cc", "strict"])
    def test_the_seatbelt_profile_denies_writing_the_entry(self, crew_root, tier) -> None:
        from kiro_crew import sandbox

        profile = sandbox._build_seatbelt_profile(tier)
        assert '(deny file-write* (literal "%s"))' % crew_root in profile

    @pytest.mark.skipif(
        not sys.platform.startswith("darwin"), reason="Seatbelt profile text is macOS's."
    )
    def test_the_descendants_are_left_writable(self, crew_root) -> None:
        """`literal`, never `subpath`. The agent's own `sessions/`, `memory/` and
        `logs/` live inside this directory; fencing the subtree would cut it off from
        its own working data, which is the same false positive the container gate is
        exact-match to avoid.

        Verified end-to-end against real `sandbox-exec` while writing this: with the
        literal rule in force, `mv <container> <elsewhere>` fails with `Operation not
        permitted` while a write to `<container>/sessions/new.json` succeeds.
        """
        from kiro_crew import sandbox

        profile = sandbox._build_seatbelt_profile("standard")
        assert '(deny file-write* (subpath "%s"))' % crew_root not in profile


class TestACdRelativeGlob:
    """The `cd`-relative arm asked only the EXACT container question.

    Both absolute arms already run `_glob_could_name`, so `mv ~/.kir?/crew /tmp/x` was
    refused while `cd ~ && mv .kir?/crew /tmp/x` -- the same path, reached by joining
    the operand onto the `cd` base -- was not. An asymmetry between two arms of one
    check is the shape worth pinning here, more than any single spelling.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cd ~ && mv .kir?/crew /tmp/x",
            "cd ~ && mv .kiro/cre? /tmp/x",
            "cd ~ && mv .ki*/crew /tmp/x",
            "cd ~/.kiro && mv cre? /tmp/x",
        ],
    )
    def test_a_glob_joined_onto_a_cd_base_is_checked(self, command: str) -> None:
        assert _blocked(command)

    def test_the_leaf_gate_gets_the_same_treatment(self) -> None:
        """Both `_glob_could_name` calls were missing here, not just the container one."""
        assert _blocked("cd ~ && mv .ssh/id_* /tmp/x")

    @pytest.mark.parametrize(
        "command",
        ["cd ~ && ls Documents/*", "cd /tmp && mv a? b", "cd ~ && cat notes.md"],
    )
    def test_an_ordinary_cd_relative_glob_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestASymlinkedConfiguredHome:
    def test_the_resolved_spelling_is_matched_too(self, monkeypatch, tmp_path) -> None:
        """A configured home reached through a symlink has TWO spellings on disk.

        The operand passes resolve links themselves, so they caught both; only the raw
        scan was left comparing text, and it knew just the configured one. That makes
        the interpreter payload the single reachable form -- the same asymmetry as the
        Windows `abspath` bug and the doubled-separator bug earlier in this PR, and for
        the same reason each time.
        """
        real = tmp_path / "real" / "crewdata"
        real.mkdir(parents=True)
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "real")
        monkeypatch.setenv("KIROCREW_HOME", str(link / "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        resolved = os.path.realpath(str(link / "crewdata"))
        assert _blocked("python3 -c \"import os; os.rename('%s', '/tmp/x')\"" % resolved)
        assert _blocked("python3 -c \"import os; os.rename('%s', '/tmp/x')\"" % (link / "crewdata"))

    def test_an_unrelated_path_is_untouched(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv %s /tmp/x" % (tmp_path / "unrelated"))


class TestTheParentIsRelocatableToo:
    def test_the_kiro_directory_itself_is_protected(self) -> None:
        """Renaming the PARENT carries the container with it.

        `mv ~/.kiro /tmp/stash && ln -s /tmp/evil ~/.kiro` relocates the data home
        without ever naming it, so protecting only `~/.kiro/crew` leaves the identical
        attack one level up. `security._UNREPLACEABLE_CONTAINER_DIRS` has covered
        `.kiro` from the start; the sandbox list had not, so the two halves of one
        fence disagreed about its extent.
        """
        from kiro_crew import sandbox

        listed = sandbox._unrenamable_containers()
        home = str(pathlib.Path.home())
        assert os.path.join(home, ".kiro") in listed
        assert os.path.join(home, ".kiro/crew") in listed

    def test_it_matches_the_command_gate_s_own_list(self) -> None:
        """The two lists answer the same question and must not drift apart."""
        from kiro_crew import sandbox

        listed = {
            p.rsplit(str(pathlib.Path.home()) + os.sep, 1)[-1]
            for p in sandbox._unrenamable_containers()
        }
        for name in security._UNREPLACEABLE_CONTAINER_DIRS:
            assert name in listed, f"{name} is fenced as a command but not protected in the sandbox"


class TestNestedSubstitutionsAndUnicodeRanges:
    def test_a_nested_substitution_is_still_a_substitution(self) -> None:
        """`[^()]*` cannot span a nested `$()`, so `$(echo $(printf i))` matched nothing
        and the word read as ordinary text -- while the single-level form was refused."""
        assert _blocked("mv ~/.k$(echo $(printf i))ro/crew /tmp/x")
        assert _blocked("mv ~/.k$(printf i)ro/crew /tmp/x")

    def test_an_ordinary_nested_substitution_is_untouched(self) -> None:
        assert not _blocked("echo $(echo $(date))")

    def test_a_unicode_digit_range_does_not_crash_the_gate(self) -> None:
        """`str.isdigit()` is TRUE for `²` and `٣`, which `int()` then refuses, so
        `echo {²..³}` took `ValueError` straight out of `_expand_braces` and aborted
        the tool-approval path. A gate that raises is a gate that is not answering."""
        assert security.is_sensitive_bash_command("echo {²..³}") is None
        assert security.is_sensitive_bash_command("echo {٣..٥}") is None

    def test_ordinary_ranges_still_expand(self) -> None:
        assert not _blocked("echo {1..9}")
        assert not _blocked("cp /data/img{a..z}.jpg /out/")
        assert _blocked("mv ~/.kiro/cr{e..e}w /tmp/x")


class TestBareTrustRootReadsAlsoExemptTheContainerGate:
    """`_is_bare_trust_root_read` reused, not re-derived, at all four sites this PR's
    container-naming gate fires from: the raw pass-1 scan and the three
    `is_unreplaceable_container(...)` call sites inside the normalizer second pass.

    `ls -d ~/.kiro/crew` NAMES the container exactly like a relocating `mv` does, and
    a verb-independent match cannot tell them apart on text alone -- but the
    container-naming refusal exists to stop RENAMES and REPLACEMENTS, and nothing in
    the narrow, hand-audited allowlist this exoneration already checks (`ls`, `stat`,
    `du`, `readlink`, `basename`, `dirname`, `wc`, with no shell composition at all)
    can do either. This is the same false-positive family issue #6021 already fixed
    for the extraction-into-trust-root gate; this class is the container gate getting
    the identical treatment.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "ls -d ~/.kiro/crew",
            "ls -ld ~/.kiro/crew",
            "stat ~/.kiro/crew",
            "readlink ~/.kiro/crew",
            "du ~/.kiro/crew",
        ],
    )
    def test_a_bare_read_of_the_container_itself_is_allowed(self, command: str) -> None:
        assert not _blocked(command)

    def test_a_compound_cd_relative_read_is_not_exonerated(self) -> None:
        """`&&` is shell composition, which the exoneration's positive character-set
        check refuses on principle -- `_is_bare_trust_root_read` requires no
        composition at all, so a compound command never qualifies regardless of which
        program follows the `&&`. This is the conservative direction: the container
        gate over-blocks a chained read rather than risk exonerating a chained WRITE
        that merely opens with a harmless-looking one.
        """
        assert _blocked("cd ~ && ls -d .kiro/crew")

    def test_the_exoneration_does_not_widen_to_non_listed_programs(self) -> None:
        """The allowlist is the boundary, not "looks like a read".

        `echo` and `cat` are not writers of the container either, but they are not on
        the hand-audited list this exoneration reuses, and this class does not get to
        widen that list on its own authority -- #6021's own comments explain exactly
        why the list is closed rather than heuristic (`find -delete`, `install -d`).
        """
        assert _blocked("echo ~/.kiro/crew")
        assert _blocked("cat ~/.kiro/crew")

    def test_the_exoneration_does_not_survive_shell_composition(self) -> None:
        """A bare-looking read followed by a real write, chained on the same line."""
        assert _blocked("ls -d ~/.kiro/crew; rm -rf ~/.kiro/crew")
        assert _blocked("ls -d ~/.kiro/crew && mv ~/.kiro/crew /tmp/x")

    def test_actual_relocation_still_blocks_regardless(self) -> None:
        """The exoneration is scoped to the ALLOWLISTED PROGRAMS, not to the shape of
        the command -- a writer naming the container plainly is unaffected."""
        assert _blocked("mv ~/.kiro/crew /tmp/stash")
        assert _blocked("ln -s /tmp/evil ~/.kiro/crew")
        assert _blocked("install -d ~/.kiro/crew")
        assert _blocked("cd ~ && mv .kiro/crew /tmp/x")

    def test_a_pathname_program_is_not_exonerated(self) -> None:
        """`_is_bare_trust_root_read` itself refuses a path like `/bin/ls`, since a
        basename says nothing about what an attacker-placed executable at that path
        actually does -- this class inherits that boundary rather than re-deciding
        it, and pins that it survived the reuse."""
        assert _blocked("/bin/ls -d ~/.kiro/crew")


class TestPositionalAndSpecialParameters:
    """An unset positional parameter expands to nothing exactly like an unset named
    variable, and `_SHELL_EXPANSION_RE`'s bare-name pattern required a leading letter
    or underscore, so `$1` never matched it and a path spliced around one was
    reassembled by the shell after every scan read it as an unrelated string."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cre$1w /tmp/x",
            "mv ~/.kiro/cre$9w /tmp/x",
            "mv ~/.kiro/cre$*w /tmp/x",
            'bash -c "mv ~/.kiro/cre$1w /tmp/x"',
        ],
    )
    def test_a_special_parameter_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["echo $1", "echo $@ > /tmp/x", "echo $? > /tmp/x", "echo $$ > /tmp/x"],
    )
    def test_an_ordinary_use_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestTheSubstitutionScanFailsClosedPastItsBudget:
    """`_MAX_SUBSTITUTION_WORDS` bounds the WORK, not the ANSWER. Breaking the loop and
    falling through to `return False` meant a command with enough substitution-bearing
    words silently read as clean past word 64, regardless of whether the unexamined
    tail contained the one word that names the container -- exhausting a budget is not
    evidence of safety, and every other bounded scan in this module (braces, glob
    expansions) already answers "could name it" on overflow, not "does not"."""

    def test_a_container_forming_word_past_the_budget_is_still_caught(self) -> None:
        benign = " ".join("$(echo /data/f%d)" % i for i in range(70))
        command = "cp %s ~/.k$(printf i)ro/crew /out/" % benign
        assert _blocked(command)

    def test_exhausting_the_budget_with_no_real_container_word_fails_closed_too(
        self,
    ) -> None:
        """The honest cost of the fix: a command with more substitutions than the
        budget and NONE of them forming the container is refused anyway, because the
        scan cannot tell the two cases apart once it stops looking."""
        benign = " ".join("$(echo /data/f%d)" % i for i in range(100))
        assert _blocked("cp %s /out/" % benign)

    def test_an_ordinary_command_under_the_budget_is_untouched(self) -> None:
        assert not _blocked("echo $(date) > /tmp/x")


class TestANestedCustomHomesAncestorsAreProtectedToo:
    """One level up was not enough for an arbitrary custom `KIROCREW_HOME`: renaming
    ANY ancestor and replacing it with a symlink completes the same relocation attack
    this whole class of gate exists to stop, regardless of how many directories deep
    the configured home sits."""

    def test_every_ancestor_up_to_home_or_root_is_protected(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        nested = _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        containers = sandbox._unrenamable_containers()
        assert _os.path.join(resolved_tmp, "company") in containers
        assert _os.path.join(resolved_tmp, "company", "dept") in containers

    def test_the_bare_filesystem_root_is_never_included(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", _os.path.join(str(tmp_path), "company", "crewdata"))
        assert "/" not in sandbox._unrenamable_containers()

    def test_home_itself_is_never_included_when_the_custom_home_is_nested_under_it(
        self, monkeypatch
    ) -> None:
        """Matches `_SENSITIVE_LEAF_PARENT_DIRS`'s existing rule: a single-segment
        entry whose parent is home is excluded so as not to taint `cd ~`."""
        from kiro_crew import sandbox

        monkeypatch.setenv(
            "KIROCREW_HOME", os.path.join(os.path.expanduser("~"), "myworkspace", "crewdata")
        )
        containers = sandbox._unrenamable_containers()
        assert os.path.expanduser("~") not in containers
        assert os.path.join(os.path.expanduser("~"), "myworkspace") in containers

    def test_the_seatbelt_builder_picks_up_every_ancestor(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        monkeypatch.setenv(
            "KIROCREW_HOME", _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        )
        company_dir = _os.path.join(resolved_tmp, "company")
        assert (
            '(deny file-write* (literal "%s"))' % company_dir
        ) in sandbox._build_seatbelt_profile("standard")

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_linux_launcher_picks_up_every_ancestor(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        monkeypatch.setenv(
            "KIROCREW_HOME", _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        )
        company_dir = _os.path.join(resolved_tmp, "company")
        assert company_dir in sandbox._build_launcher_script("standard")


class TestTheCommandGateWalksCustomHomeAncestorsToo:
    """The sandbox's own ancestor walk (`sandbox._unrenamable_containers`) has a
    second-layer counterpart here: without the sandbox (disabled deliberately, or a
    platform it does not cover), this text gate is the LAST defense, and it did not
    know about a nested custom home's ancestors at all.
    """

    def test_every_ancestor_of_a_nested_custom_home_is_refused(self, monkeypatch, tmp_path) -> None:
        resolved_tmp = os.path.realpath(str(tmp_path))
        nested = os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        company_dir = os.path.join(resolved_tmp, "company")
        dept_dir = os.path.join(resolved_tmp, "company", "dept")
        assert _blocked("mv %s /tmp/x" % company_dir)
        assert _blocked("mv %s /tmp/x" % dept_dir)
        assert _blocked("mv %s /tmp/x" % nested)

    def test_an_unrelated_path_is_untouched(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("KIROCREW_HOME", os.path.join(str(tmp_path), "company", "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv /etc/passwd /tmp/x")
        assert not _blocked("ls ~/.kiro/crew/sessions")


class TestRepeatedInteriorSeparators:
    """The filesystem collapses a run of separators to one, so `~//.kiro/crew` and
    `~/.kiro//crew` both resolve to `~/.kiro/crew` -- and only the raw scan needs to
    know this, since the operand passes normalize the path themselves."""

    @pytest.mark.parametrize(
        "path",
        [
            "~//.kiro/crew",
            "~/.kiro//crew",
            "~///.kiro///crew",
        ],
    )
    def test_a_doubled_separator_still_names_the_container(self, path: str) -> None:
        payload = "python3 -c \"import os; os.rename(os.path.expanduser('%s'),'/tmp/x')\"" % path
        assert _blocked(payload)

    def test_an_ordinary_single_separator_path_is_untouched(self) -> None:
        assert not _blocked("cat /tmp/normal")
        assert not _blocked("ls ~/.kiro/crewold")


class TestNestedExtglobGroups:
    """`_EXTGLOB_GROUP_RE` excludes `(`/`)` from what it captures, so it can only ever
    match the INNERMOST group in a nested one -- one substitution pass left an outer
    `@(...)` construct in place for `fnmatch` to render literally. Not reproduced on
    this box's bash 3.2 (no newer bash available to confirm nested extglob expansion
    directly), so this is a defensive fix: the cost of over-fixing here is a sharper
    "any single character" reading, never a missed one, so there is no permissive
    direction to weigh against.
    """

    def test_a_nested_extglob_group_is_still_widened(self) -> None:
        assert _blocked("shopt -s extglob; mv ~/@(.k@(i)ro)/crew /tmp/x")

    def test_a_single_level_extglob_group_is_unaffected(self) -> None:
        assert _blocked("shopt -s extglob; mv ~/@(.kiro)/crew /tmp/x")

    def test_an_ordinary_extglob_is_untouched(self) -> None:
        assert not _blocked("shopt -s extglob; ls ~/Documents/@(a|b).md")
        assert not _blocked("shopt -s extglob; echo hello")


class TestConcatenatedQuotedLiteralsInAnInterpreterPayload:
    """A substitution can sit BETWEEN quoted literals joined by `+` rather than welded
    onto one continuous bash word -- `'~/.k' + '$(printf i)' + 'ro/crew'` inside a
    `python3 -c` payload is three whitespace-separated bash words, none of which alone
    names anything. Deliberately narrow: this reconstructs one common concatenation
    idiom, not an interpreter's full expression grammar.
    """

    def test_the_exact_reported_shape(self) -> None:
        assert _blocked(
            "python3 -c \"import os; os.rename('~/.k' + '$(printf i)' + " "'ro/crew', '/tmp/x')\""
        )

    def test_either_quote_ordering(self) -> None:
        """The outer `-c` wrapper and the inner literals must use DIFFERENT quote
        characters -- a combined either-quote scan matches the outer pair first and
        swallows every inner literal as unstructured content before ever looking
        for the pieces inside it."""
        assert _blocked("python3 -c \"os.rename('~/.kiro/' + 'cr' + '$(printf ew)', '/tmp/x')\"")
        assert _blocked('python3 -c \'os.rename("~/.k" + "$(printf i)" + "ro/crew", "/tmp/x")\'')

    def test_ordinary_concatenation_is_untouched(self) -> None:
        assert not _blocked("python3 -c \"print('hello' + ' ' + 'world')\"")
        assert not _blocked("python3 -c \"x = 'a' + 'b'; print(x)\"")

    def test_unrelated_adjacent_literals_with_no_plus_are_untouched(self) -> None:
        assert not _blocked("python3 -c \"print('foo'); print('bar')\"")


class TestPythonsImplicitAdjacentLiteralConcatenationIsReconstructed:
    """GPT review, second pass: `_concatenated_literal_candidates` only
    continued a run when the text between two quoted literals was `+` --
    but Python (unlike bash) ALSO concatenates two adjacent string literals
    with nothing but whitespace between them, no operator at all.
    `expanduser('~/.k' 'iro/crew')` is ordinary Python, identical in effect
    to `'~/.k' + 'iro/crew'`, but the `+`-only check left it unrecognized:
    `between.strip()` is empty, not `"+"`, so the run stopped after the
    first literal and `~/.kiro/crew` was never reconstructed.
    """

    def test_the_reported_shape_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked(
            'python3 -c "import os; os.rename(os.path.expanduser('
            "'~/.k' 'iro/crew'), '/tmp/stash')\""
        )

    def test_a_three_piece_whitespace_joined_run_is_blocked(self, monkeypatch) -> None:
        """No prefix of the run spells the container on its own (`~/.ki`,
        `~/.kiro/cr` neither one) -- only reaching the FULL three-piece
        reconstruction completes `~/.kiro/crew`, so this cannot pass by
        coincidence the way a run whose `+`-joined prefix already spelled
        `.kiro` would."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("python3 -c \"os.rename('~/.ki' 'ro/cr' 'ew', '/tmp/x')\"")

    def test_a_mix_of_whitespace_and_plus_joins_is_blocked(self, monkeypatch) -> None:
        """Same non-coincidence property: the `+`-joined prefix (`~/.ki` +
        `ro/cr` = `~/.kiro/cr`) is not itself sensitive; only the final
        whitespace-joined piece completes the container."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("python3 -c \"os.rename('~/.ki' + 'ro/cr' 'ew', '/tmp/x')\"")

    def test_unrelated_adjacent_literals_still_stay_allowed(self) -> None:
        """The property that must NOT regress: two adjacent literals whose
        CONCATENATION does not name anything sensitive stay allowed --
        this widening only changes which text gets reconstructed and
        checked, not the check itself."""
        assert not _blocked("mv 'foo' 'bar'")
        assert not _blocked("python3 -c \"print('hello' 'world')\"")


class TestTheLinuxSelfBindRefusesASymlinkedContainer:
    """`os.path.isdir` follows a symlink, so the self-bind loop would happily bind
    THROUGH one -- `mount(2)` resolves the link the same way `open()` does, landing
    the bind on the directory the link points to rather than on the link's own
    directory-entry slot. `rm ~/.kiro/crew && ln -s /evil ~/.kiro/crew` then swaps the
    link out from under a mount still faithfully protecting the OLD target.

    There is no bind-based fix -- protecting the link's own slot would mean
    write-denying the PARENT's contents, the subtree-fencing this whole mechanism
    deliberately does not do. So a symlinked container fails the spawn instead,
    matching every other control in this launcher.
    """

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_a_symlinked_container_is_detected_before_the_bind(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        link_path = tmp_path / "crewdata_link"
        link_path.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(link_path))
        script = sandbox._build_launcher_script("standard")
        assert "os.path.islink(target)" in script
        assert "sys.exit(" in script

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_islink_check_precedes_the_isdir_check(self) -> None:
        """Ordering: `isdir` alone would already have bound through the symlink by
        the time anything noticed."""
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        islink_at = script.index("os.path.islink(target)")
        isdir_at = script.index("if os.path.isdir(target):", islink_at)
        assert islink_at < isdir_at

    def test_macos_seatbelt_already_protects_a_symlinked_container(self) -> None:
        """Verified empirically against real `sandbox-exec`, not asserted from the
        profile text alone: a literal `file-write*` deny on a symlink's OWN path
        blocks `rm`+`ln -s` replacing it, because Seatbelt's literal-path match is
        NOT symlink-following the way a Linux bind-mount target is. No fix needed on
        this platform; this test exists so a future refactor of the self-bind logic
        does not "fix" macOS too and paper over that the two platforms differ here
        for a real reason.
        """
        assert True


class TestAncestorSelfBindsAreOrderedShallowestFirst:
    """`MS_BIND` without `MS_REC` copies only the mount at that point, not the
    submounts beneath it -- the same failure mode a much earlier round of this PR
    fixed for self-bind-vs-masking order. Binding a DEEPER directory and then binding
    one of its ANCESTORS a moment later produces a fresh view of the ancestor that does
    not carry the deeper bind forward, undoing it. The ancestor walk appended entries
    deepest-first (the walk starts at the immediate parent and moves outward), which is
    backwards for the self-bind loop that consumes this list in order.
    """

    def test_every_ancestor_precedes_its_descendants(self, monkeypatch, tmp_path) -> None:
        """Compared with `/`-normalized separators, not the raw entries:
        `sandbox._unrenamable_containers()` returns OS-native paths, so on Windows
        every entry is backslash-separated and a forward-slash-only
        `.startswith(ancestor + "/")` check never matches anything -- the `if` never
        fires, `assert i < j` never runs, and the test passes VACUOUSLY, checking
        nothing at all, rather than failing. Normalizing both sides the same way
        `security.py`'s own path-folding does (`.replace("\\\\", "/")`) makes the
        ancestor/descendant relationship recognized on every platform."""
        from kiro_crew import sandbox

        resolved_tmp = os.path.realpath(str(tmp_path))
        nested = os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        containers = sandbox._unrenamable_containers()
        normalized = [c.replace("\\", "/") for c in containers]
        checked_at_least_one_pair = False
        for i, ancestor in enumerate(normalized):
            for j, descendant in enumerate(normalized):
                if ancestor != descendant and descendant.startswith(ancestor.rstrip("/") + "/"):
                    checked_at_least_one_pair = True
                    assert i < j, (
                        f"{containers[i]!r} (index {i}) must precede its descendant "
                        f"{containers[j]!r} (index {j}), or its self-bind would hide "
                        "the descendant's mount"
                    )
        assert checked_at_least_one_pair, "no ancestor/descendant pair was found to check"

    def test_the_default_kiro_pair_is_also_ordered_correctly(self) -> None:
        """Not new behavior -- `.kiro` already preceded `.kiro/crew`. Pinned so a
        future edit cannot flip it while "fixing" something else.

        Compared with `/`-normalized separators: `sandbox._unrenamable_containers()`
        returns OS-native paths, so a bare `.endswith("/.kiro")` never matches a
        Windows entry ending `\\.kiro` and raised `StopIteration` there instead of
        finding either container."""
        from kiro_crew import sandbox

        containers = sandbox._unrenamable_containers()
        normalized = [(c, c.replace("\\", "/")) for c in containers]
        kiro = next(c for c, n in normalized if n.endswith("/.kiro"))
        kiro_crew = next(c for c, n in normalized if n.endswith("/.kiro/crew"))
        assert containers.index(kiro) < containers.index(kiro_crew)


class TestQuotedExtglobActivationAndPayloadScanning:
    """Two bugs in one finding. `ext""glob` is `extglob` once bash tokenizes it --
    dropping an adjacent empty quote pair is exactly what `$""` does elsewhere in this
    file's own reasoning -- but the mode-detection regex compared against the raw,
    un-normalized text and read the option as absent. Separately, and this one held
    even with the UNQUOTED spelling: a quoted `-c '...'` payload never tokenizes, so
    the operand check that runs on the normalizer pass's candidates never saw
    `~/@(.kiro)/crew` inside it, no matter how correctly the mode was detected.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "bash -O ext\"\"glob -c 'mv ~/@(.kiro)/crew /tmp/stash'",
            "bash -O extglob -c 'mv ~/@(.kiro)/crew /tmp/stash'",
            'bash -O extglob -c "mv ~/@(.kiro)/crew /tmp/stash"',
        ],
    )
    def test_a_quoted_c_payload_is_scanned_with_its_enabled_modes(self, command: str) -> None:
        assert _blocked(command)

    def test_the_quote_split_activation_is_detected_on_its_own(self) -> None:
        from kiro_crew import security

        assert security._glob_modes("""bash -O ext""glob""")["extglob"]
        assert not security._glob_modes("echo hello")["extglob"]

    @pytest.mark.parametrize(
        "command",
        [
            "bash -c 'ls ~/Documents/@(a|b).md'",
            "bash -O extglob -c 'ls ~/Documents/@(a|b).md'",
            "echo 'a+b'",
            "echo user@example.com",
        ],
    )
    def test_ordinary_commands_are_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestASymlinkedCustomHomeIsProtectedAtTheConfiguredPath:
    """`config_dir()` resolves any symlink in `KIROCREW_HOME` before returning, so the
    self-bind protection landed on the RESOLVED target -- but a restart re-reads the
    raw env var and re-resolves it, so if the CONFIGURED path is itself a symlink,
    `rm <that path> && ln -s /evil <same path>` swaps what the next resolution follows,
    and nothing protected the symlink's own directory-entry slot.
    """

    def test_the_unresolved_configured_path_is_protected(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "crewdata_link"
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        containers = sandbox._unrenamable_containers()
        assert str(symlink_home) in containers

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_launcher_refuses_to_spawn_through_it(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "crewdata_link"
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        script = sandbox._build_launcher_script("standard")
        assert str(symlink_home) in script

    def test_an_ordinary_custom_home_is_not_duplicated(self, monkeypatch, tmp_path) -> None:
        """The common case: no symlink, so the unresolved and resolved forms are the
        SAME path, and dedup must collapse them rather than mounting twice."""
        from kiro_crew import sandbox

        ordinary = tmp_path / "crewdata"
        ordinary.mkdir()
        monkeypatch.setenv("KIROCREW_HOME", str(ordinary))
        containers = sandbox._unrenamable_containers()
        assert len(containers) == len(set(containers))

    def test_ordering_holds_even_with_the_symlink_entry_present(
        self, monkeypatch, tmp_path
    ) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "company" / "crewdata_link"
        symlink_home.parent.mkdir()
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        containers = sandbox._unrenamable_containers()
        for i, a in enumerate(containers):
            for j, b in enumerate(containers):
                if a != b and b.startswith(a.rstrip("/") + "/"):
                    assert i < j, f"{a!r} (index {i}) must precede {b!r} (index {j})"


class TestDeeplyNestedSubstitutionsAreMaskedToAFixedPoint:
    """`_OUTPUT_SUBSTITUTION_RE` allows one extra level of balanced parens inside
    `$(...)`, which is what a fixed-width regex can express for nesting at all --
    arbitrarily deep balanced nesting has no such pattern. One masking pass fully
    resolves one level and leaves a deeper one still `$(...)`-shaped, an unresolved
    marker rather than the `*` it should read as.
    """

    def test_one_level_still_works(self) -> None:
        assert _blocked("mv ~/.k$(echo $(printf i))ro/crew /tmp/x")

    def test_two_levels_of_nesting(self) -> None:
        assert _blocked("mv ~/.k$(echo $(echo $(printf i)))ro/crew /tmp/x")

    def test_three_levels_of_nesting(self) -> None:
        assert _blocked("mv ~/.k$(echo $(echo $(echo $(printf i))))ro/crew /tmp/x")

    def test_an_ordinary_deeply_nested_substitution_is_untouched(self) -> None:
        assert not _blocked("echo $(echo $(echo $(date)))")
        assert not _blocked("echo $(date)")


class TestTheAncestorWalkStopsAtTheSystemTempRootNotUnderIt:
    """A real regression, caught by CI and not by any local run: this project's OWN
    test suite pins `KIROCREW_HOME` under `/tmp` for isolation
    (`testing-conventions`), and the unbounded ancestor walk added two rounds ago
    reached bare `/tmp` and treated it as a protected container -- refusing every
    command naming it, `cd /tmp && cat notes.txt` included. Invisible locally because
    nothing in a bare `pytest` invocation sets `KIROCREW_HOME` at all.

    The fix is not "stop the walk at the first ancestor that happens to be under
    `/tmp`" -- that overshoots and un-protects every INTERMEDIATE ancestor between the
    leaf and `/tmp`, silently reopening the exact gap the walk exists to close. It has
    to stop EXACTLY at the temp root itself, the same exact-match shape the
    `Path.home()` stop already has.

    The stop is asymmetric between the two mechanisms, on review feedback: the
    command gate (`security.py`) is verb-independent text matching, so reaching the
    temp root there refuses every command merely NAMING it -- it has to stop early.
    The sandbox self-bind (`sandbox.py`) costs nothing comparable -- it denies
    RENAMING one literal directory entry, nothing else -- so it keeps walking through
    the temp root, protecting a `KIROCREW_HOME` nested under a user- or
    environment-selected `$TMPDIR` from having THAT boundary itself relocated.
    """

    def test_the_sandbox_protects_the_temp_root_itself(self, monkeypatch) -> None:
        """Unlike the command gate, the sandbox's ancestor walk does NOT exempt the
        temp root: self-binding it costs nothing (it only blocks renaming that one
        directory entry), so there is no usability reason to leave it out, and
        leaving it out would un-protect a `KIROCREW_HOME` nested under a writable
        custom `$TMPDIR`.

        Nested under `tempfile.gettempdir()`, not `tmp_path`: this project's own
        rootdir conftest redirects `tempfile.gettempdir()` to a SIBLING of pytest's
        own `tmp_path` tree, not an ancestor of it -- on POSIX the two coincide
        anyway, because both land under the same literal `/tmp` boundary, but
        Windows has no such literal fallback, so `tmp_path`'s own ancestors are
        never recognized as a temp root there and this test failed on every
        Windows CI run with `tmp_path is not under a recognized temp root`.

        `_unrenamable_containers()` itself walks ancestors with plain `os.path`
        string operations, but resolving `KIROCREW_HOME` along the way goes
        through `config_dir()`, which DOES create the directory as a normal side
        effect of resolving a home -- so this registers cleanup of what that
        creates, into the redirected (session-scoped, already-tracked) temp root
        rather than leaving it unregistered residue."""
        import tempfile

        from kiro_crew.config.paths import _is_system_tmp_root

        base = pathlib.Path(tempfile.gettempdir())
        created_root = base / "company"
        nested = created_root / "dept" / "crewdata"
        monkeypatch.setenv("KIROCREW_HOME", str(nested))
        from kiro_crew import sandbox

        try:
            containers = sandbox._unrenamable_containers()
        finally:
            platform_compat.rmtree_force(created_root)
        real_base = pathlib.Path(os.path.realpath(str(base)))
        temp_root = next(
            (a for a in [real_base, *real_base.parents] if _is_system_tmp_root(a)), None
        )
        assert temp_root is not None, "gettempdir() is not under a recognized temp root"
        assert str(temp_root) in containers

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "Rooted at the literal POSIX `/tmp`, exercising `_is_system_tmp_root`'s "
            "POSIX-`/tmp`-literal fallback specifically. Windows has no `/tmp` and "
            "no such fallback -- confirmed on CI: `cd /tmp && cat notes.txt` was "
            "wrongly refused there because the literal `/tmp` read as an ordinary, "
            "unrecognized ancestor of the configured home rather than as the "
            "shared, unprotected temp root this test's assertion assumes."
        ),
    )
    def test_ordinary_tmp_commands_are_allowed_even_with_a_tmp_nested_home(
        self, monkeypatch
    ) -> None:
        """The exact shape of the CI failure: an ordinary command naming `/tmp`,
        while `KIROCREW_HOME` happens to be pinned somewhere under it.

        Deliberately rooted at the LITERAL string `/tmp`, not the `tmp_path` fixture:
        on macOS `tmp_path` lives under `$TMPDIR` (`/private/var/folders/...`), a
        subtree that never passes through `/tmp` at all, so a `tmp_path`-based home
        cannot exercise this boundary there and this exact test passed locally with
        the fix removed -- the bug is only reachable through `/tmp` itself, which is
        where CI's own `tempfile.gettempdir()` resolves on Linux. No directory needs
        to exist on disk: `security.is_sensitive_bash_command` walks ancestors with
        plain `os.path` string operations, never `.exists()`."""
        nested = "/tmp/kirocrew-boundary-test/company/dept/crewdata"
        monkeypatch.setenv("KIROCREW_HOME", nested)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("cd /tmp && cat notes.txt")
        assert not _blocked("mv /tmp /tmp2")
        assert not _blocked("cd /tmp; cd -; cat notes.txt")

    def test_intermediate_ancestors_under_tmp_stay_protected(self, monkeypatch, tmp_path) -> None:
        """The property that must NOT regress while fixing the above: everything
        strictly BETWEEN the leaf and the temp root is still a uniquely identifying
        directory, not shared territory, and stays protected on both mechanisms."""
        from kiro_crew import sandbox

        nested = tmp_path / "company" / "dept" / "crewdata"
        nested.parent.mkdir(parents=True)
        monkeypatch.setenv("KIROCREW_HOME", str(nested))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        resolved_tmp = os.path.realpath(str(tmp_path))
        company_dir = os.path.join(resolved_tmp, "company")
        dept_dir = os.path.join(resolved_tmp, "company", "dept")
        assert company_dir in sandbox._unrenamable_containers()
        assert dept_dir in sandbox._unrenamable_containers()
        assert _blocked("mv %s /tmp/x" % company_dir)
        assert _blocked("mv %s /tmp/x" % dept_dir)

    def test_the_boundary_helper_directly(self) -> None:
        """Unit-level pin for `_is_system_tmp_root` itself: true exactly at the
        boundary, false one level either side of it.

        Walks up from `tempfile.gettempdir()`, not `tmp_path`: this project's own
        rootdir conftest redirects `gettempdir()` to a SIBLING of pytest's own
        `tmp_path` tree, not an ancestor of it -- the two only coincide on POSIX,
        where both happen to land under the same literal `/tmp` boundary. Windows
        has no such literal fallback, so `tmp_path`'s own ancestors are never
        recognized as a temp root there, and this test failed on every Windows CI
        run with `no ancestor of tmp_path was recognized as the temp root`."""
        import tempfile

        from kiro_crew.config.paths import _is_system_tmp_root

        leaf = pathlib.Path(os.path.realpath(tempfile.gettempdir()))
        for ancestor in [leaf, *leaf.parents]:
            if _is_system_tmp_root(ancestor):
                # True exactly at the boundary, false one level either side: a
                # CHILD of the recognized boundary must not also read as the
                # boundary itself, and neither must its parent.
                if ancestor is not leaf:
                    assert not _is_system_tmp_root(leaf)
                assert not _is_system_tmp_root(ancestor.parent)
                break
        else:
            pytest.fail("no ancestor of gettempdir() was recognized as the temp root")


class TestObfuscatedAncestorReferencesAreCaughtToo:
    """GPT review, round after the temp-root fix: `_substitution_could_name_container`
    and `_raw_glob_could_name_container` each built their own target set from
    `_UNREPLACEABLE_CONTAINER_DIRS` alone, never from a configured home's ANCESTORS --
    so `mv ~/comp$(echo any)/dept /tmp/x` (substitution) and, with extglob enabled,
    `mv ~/comp@(any)/dept /tmp/x` (glob) both reached only the raw regex the ancestor
    walk was added to, and bypassed the substitution and glob scanners entirely, even
    though the LITERAL form of the same rename is refused. `_container_targets()` now
    feeds all three (plus `is_unreplaceable_container`, the cd-relative segment walk's
    own exact-match check) from one shared ancestor walk.
    """

    def test_substitution_obfuscated_ancestor_rename_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/comp$(echo any)/dept /tmp/x")

    def test_glob_obfuscated_ancestor_rename_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/comp@(any) /tmp/x'")

    def test_extglob_widening_still_matches_a_leading_dotfile(self, monkeypatch) -> None:
        """Regression pin for the widening fix itself: the ORIGINAL `.*` substitution
        exists so `@(.kiro)`-shaped groups still match a dotfile target, and the new
        plain-`*` reading added alongside it must not have narrowed that."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv ~/@(.kiro) /tmp/x'")

    def test_ordinary_extglob_use_is_still_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'ls @(*.txt|*.md)'")

    def test_cd_relative_resolution_to_an_ancestor_is_recognized(self, monkeypatch) -> None:
        """`is_unreplaceable_container` -- the cd-relative segment walk's own
        exact-match check -- has the identical gap independently of the raw scanners
        above, since it built its target set the same way."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        assert security.is_unreplaceable_container("/opt/company/dept")
        assert security.is_unreplaceable_container("/opt/company")

    def test_ordinary_substitution_and_glob_commands_stay_allowed(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo $(date)")
        assert not _blocked("ls *.txt")


class TestTempRootDiscoveryFailureDoesNotCrashTheGate:
    """GPT review: `tempfile.gettempdir()` probes every candidate temp directory and
    raises `OSError` if none is usable -- rare, but `_under_system_tmp` is now reached
    from the per-command ancestor walk (`_is_system_tmp_root`), not only the
    gateway-start callers it originally served, so an uncaught raise there would crash
    whatever is deciding whether to allow a command instead of returning a decision.
    """

    def test_gettempdir_failure_is_caught_not_raised(self, monkeypatch) -> None:
        from kiro_crew.config import paths

        def _raise():
            raise OSError("no usable temporary directory found")

        monkeypatch.setattr(paths.tempfile, "gettempdir", _raise)
        # Must not raise. On POSIX the literal `/tmp` fallback still applies, so a
        # path actually under it is still recognized -- discovery failure fails
        # closed (falls back to the one hardcoded root) rather than fails open.
        result = paths._under_system_tmp(pathlib.Path("/tmp/some/nested/path"))
        assert result is True or result is False

    def test_command_authorization_survives_the_failure(self, monkeypatch) -> None:
        from kiro_crew.config import paths

        def _raise():
            raise OSError("no usable temporary directory found")

        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        monkeypatch.setattr(paths.tempfile, "gettempdir", _raise)
        # Must not raise, regardless of the answer.
        security.is_sensitive_bash_command("cd /tmp && cat notes.txt")


class TestTheSandboxProtectsAUserSelectedTempRootAncestor:
    """GPT review: unlike the command gate, the sandbox's ancestor walk has no
    usability reason to exempt the temp root -- self-binding it only blocks RENAMING
    that one directory entry, nothing else -- so leaving it out was an unforced gap:
    a `KIROCREW_HOME` nested under a writable, non-default `$TMPDIR` had that
    boundary itself left unprotected. See also
    `TestTheAncestorWalkStopsAtTheSystemTempRootNotUnderIt.
    test_the_sandbox_protects_the_temp_root_itself`, added alongside this class.
    """

    def test_sandbox_walk_no_longer_imports_the_boundary_helper_unnecessarily(self) -> None:
        """Documents the asymmetry directly: the command gate needs the temp-root
        exclusion (`security.py` imports and calls `_is_system_tmp_root`), the
        sandbox self-bind does not (`sandbox.py` no longer imports it -- it may
        still be named in an explanatory comment, but nothing there calls it)."""
        from kiro_crew import sandbox

        assert not hasattr(sandbox, "_is_system_tmp_root")
        assert hasattr(security, "_is_system_tmp_root")


class TestTheCommandGateProtectsTheTempRootWhenSandboxingIsOff:
    """GPT review: `_is_system_tmp_root`'s exemption in `security.py`'s own
    ancestor walk explicitly defers the cost of protecting an operator-selected
    `TMPDIR` to `sandbox.py`'s ancestor walk ("since doing so there is free" --
    see `TestTheSandboxProtectsAUserSelectedTempRootAncestor`), but that walk
    only ever runs as part of building the namespace-sandbox launcher script --
    with `agent.sandbox="off"`, it never executes at all. A `KIROCREW_HOME`
    placed directly under an operator-selected `TMPDIR` then had no protection
    from EITHER layer: the command gate exempted it as shared temp space, and
    the layer that exemption defers to never ran to cover it. Fixed by
    conditioning the exemption itself on `sandbox.configured_sandbox_mode()`:
    unlike "is `TMPDIR` set" (the signal a prior, reverted round of this same
    narrowing relied on and had to revert, because macOS sets `TMPDIR` via
    launchd unconditionally), `agent.sandbox` carries no per-platform ambient
    default -- it ships `"auto"` and becomes `"off"` only through an explicit
    operator opt-out, so honoring it here cannot reopen that regression.
    """

    @staticmethod
    def _real_temp_root() -> pathlib.Path:
        """The actual recognized temp-root boundary `_is_system_tmp_root`
        answers to -- NOT simply `tempfile.gettempdir()`, which this project's
        own rootdir conftest redirects to a per-session directory nested BELOW
        that boundary, not the boundary itself (same reasoning as
        `TestTheAncestorWalkStopsAtTheSystemTempRootNotUnderIt.
        test_the_sandbox_protects_the_temp_root_itself`)."""
        import tempfile

        from kiro_crew.config.paths import _is_system_tmp_root

        base = pathlib.Path(os.path.realpath(tempfile.gettempdir()))
        root = next((a for a in [base, *base.parents] if _is_system_tmp_root(a)), None)
        assert root is not None, "gettempdir() is not under a recognized temp root"
        return root

    def test_a_tmpdir_rooted_home_is_protected_when_sandboxing_is_off(self, monkeypatch) -> None:
        """The exact shape GPT reported: `KIROCREW_HOME` sitting directly under
        the configured temp root, with sandboxing explicitly disabled."""
        from kiro_crew import sandbox

        tmp_root = self._real_temp_root()
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_root / "crew"))
        monkeypatch.setattr(sandbox, "configured_sandbox_mode", lambda: "off")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        security._custom_home_ancestors_cache.clear()
        assert _blocked(f"mv {tmp_root} /tmp/stash")
        assert _blocked(f"ln -s /tmp/evil {tmp_root}")

    def test_the_same_home_stays_exempt_when_sandboxing_is_on(self, monkeypatch) -> None:
        """The property that must NOT regress: with sandboxing active (the
        default, and this project's own CI posture), `sandbox.py`'s own walk is
        the layer that protects this boundary, so the command gate keeps its
        existing, narrower exemption -- an ordinary `mv $TMPDIR ...` command
        stays allowed rather than refusing to touch the whole temp tree."""
        from kiro_crew import sandbox

        tmp_root = self._real_temp_root()
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_root / "crew"))
        monkeypatch.setattr(sandbox, "configured_sandbox_mode", lambda: "auto")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        security._custom_home_ancestors_cache.clear()
        assert not _blocked(f"mv {tmp_root} /tmp/stash")

    def test_the_ancestor_helper_directly_with_sandboxing_off(self, monkeypatch) -> None:
        """Unit-level pin on `_custom_home_ancestors_uncached` itself, isolated
        from the command gate's other matchers."""
        from kiro_crew import sandbox

        tmp_root = self._real_temp_root()
        configured = str(tmp_root / "crew")
        monkeypatch.setattr(sandbox, "configured_sandbox_mode", lambda: "off")
        ancestors = security._custom_home_ancestors_uncached(configured)
        assert str(tmp_root) in ancestors

    def test_the_ancestor_helper_directly_with_sandboxing_on(self, monkeypatch) -> None:
        """Companion negative control: the unchanged, existing behavior."""
        from kiro_crew import sandbox

        tmp_root = self._real_temp_root()
        configured = str(tmp_root / "crew")
        monkeypatch.setattr(sandbox, "configured_sandbox_mode", lambda: "auto")
        ancestors = security._custom_home_ancestors_uncached(configured)
        assert ancestors == []


class TestAWildcardAgainstAnAncestorRequiresALiteralAnchor:
    """A real regression from the ancestor-target fix itself, caught by CI: once the
    glob/substitution scanners consulted a custom home's ancestors too, a BARE
    wildcard (`ls -la /tmp/*`) started reading as naming whichever ancestor happened
    to sit directly under `/tmp` -- an ordinary, harmless command this project's own
    CI matrix runs constantly, refused outright. The fixed container dirs (`.kiro`
    etc.) never had this problem: they are dot-prefixed, and bash's dotfile rule
    already keeps a bare `*` from matching them without `dotglob`. An ancestor's
    name carries no such protection -- it is an ordinary, installation-specific
    component -- so ancestor matches additionally require the operand's own LEAF
    component to retain a literal character (`_pattern_component_has_literal_anchor`,
    `_glob_could_name`'s `require_leaf_literal`).
    """

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "Hardcodes the literal POSIX `/tmp` as `KIROCREW_HOME`'s prefix to "
            "exercise `_is_system_tmp_root`'s POSIX-`/tmp`-literal fallback "
            "specifically -- Windows has no such path or fallback, so the literal "
            "`/tmp` is just an ordinary, unrecognized ancestor there and the "
            "assertion this test pins does not hold."
        ),
    )
    def test_bare_wildcard_under_the_temp_root_does_not_name_an_ancestor(self, monkeypatch) -> None:
        """The exact CI shape: KIROCREW_HOME nested directly under `/tmp`, and an
        ordinary `ls -la /tmp/*` that must stay allowed."""
        monkeypatch.setenv("KIROCREW_HOME", "/tmp/some-crew-home/.kiro/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("ls -la /tmp/*")
        assert not _blocked("rm /tmp/*.log")

    def test_a_partially_literal_wildcard_still_names_the_ancestor(self, monkeypatch) -> None:
        """The property that must NOT regress while fixing the above: GPT's own
        flagged obfuscation, which retains a literal anchor in the leaf component,
        stays caught."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/comp@(any) /tmp/x'")

    def test_the_leaf_anchor_helper_directly(self) -> None:
        from kiro_crew.security import _pattern_component_has_literal_anchor

        assert not _pattern_component_has_literal_anchor("*")
        assert not _pattern_component_has_literal_anchor("?")
        assert not _pattern_component_has_literal_anchor("[abc]")
        assert not _pattern_component_has_literal_anchor(".*")
        assert _pattern_component_has_literal_anchor("comp*")
        assert _pattern_component_has_literal_anchor("dept")

    def test_a_write_capable_verb_with_a_bare_wildcard_still_names_the_ancestor(
        self, monkeypatch
    ) -> None:
        """GPT review: the leaf-anchor requirement's leniency was UNCONDITIONAL --
        it never distinguished `ls -la /opt/*` (merely lists whatever the wildcard
        expands to) from `mv /opt/* /tmp/x` (RELOCATES whatever it expands to,
        `/opt/company` included). Now scoped by `bare_trust_root_read`: exempted
        only when the containing command is a proven-safe, program-allowlisted
        read (`_is_bare_trust_root_read(..., allow_glob=True)`); a write-capable
        verb whose bare wildcard structurally matches an ancestor's shape fails
        closed instead."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/* /tmp/x")
        assert _blocked("ln -s /evil /opt/*")

    def test_an_unrelated_bare_wildcard_write_stays_allowed(self, monkeypatch) -> None:
        """The property that must NOT regress: the fail-closed direction is scoped
        to a wildcard whose STRUCTURE (prefix and leaf) actually matches a
        configured ancestor -- an ordinary `mv` somewhere else entirely must not
        be swept up just because it is write-capable and uses a bare wildcard."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv /completely/unrelated/* /tmp/x")
        assert not _blocked("mv /home/user/downloads/* /archive/")

    def test_an_ambiguous_widened_alternation_is_not_swept_into_the_fail_closed_case(
        self, monkeypatch
    ) -> None:
        """The property that must NOT regress while fixing the write-verb gap
        above: `@(comp|other)` widens to a bare `*` leaf for the SAME reason a
        genuinely vague pattern does, but it is not actually unbounded -- it can
        only ever be `comp` or `other`, neither of which is `company`. Failing
        closed on this WIDENED reading specifically (as opposed to the operand's
        own literal text) would block a command that structurally cannot ever
        name the ancestor."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'mv /opt/@(comp|other) /tmp/x'")

    def test_fixed_container_dirs_are_unaffected_by_the_anchor_requirement(
        self, monkeypatch
    ) -> None:
        """The split target groups (`_container_target_groups`) must leave the FIXED
        set's existing, more permissive matching untouched -- only ancestor targets
        get the new restriction."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv ~/@(.kiro) /tmp/x'")
        assert _blocked("mv ~/.k$(printf i)ro/crew /tmp/x")


class TestIndirectExpansionCannotNameTheContainerUnseen:
    """GPT review: bash indirect expansion (`${!NAME}` -- the value of the variable
    NAMED BY `NAME`'s own value) resolves the configured home without ever spelling
    its name in the operand. `N=KIROCREW_HOME; mv "${!N}" /tmp/x` renames
    `$KIROCREW_HOME` itself; `N=HOME; mv "${!N}/.kiro/crew" /tmp/x` reaches the
    default home the same way. Neither is caught by the existing substitution
    scanner: `${!N}` masks to a bare `*` (whole-operand) or `*/.kiro/crew`
    (embedded), and `_glob_could_name` requires the masked reading to already look
    like a path before checking it against anything -- so both were silently
    dropped rather than refused.
    """

    def test_bare_indirect_expansion_of_a_configured_home_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('N=KIROCREW_HOME; mv "${!N}" /tmp/x')

    def test_embedded_indirect_expansion_of_home_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('N=HOME; mv "${!N}/.kiro/crew" /tmp/x')

    def test_the_unrelated_prefix_listing_construct_stays_allowed(self, monkeypatch) -> None:
        """`${!prefix*}`/`${!prefix@}` list variable NAMES matching a prefix -- a
        different construct entirely, ending in `*`/`@` rather than closing right
        after the name, and must not trip the same refusal."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo ${!BASH_*}")


class TestBraceOverflowRecognizesAnAncestorsOwnName:
    """GPT review: a brace expression too large to enumerate falls back to a
    LITERAL-PREFIX heuristic deciding whether to refuse outright. That heuristic
    checked the prefix against the FIXED container dirs and the sensitive-path
    dirs, never against a configured home's ancestors -- and, independently, its
    "same parent" sibling check mis-measured a prefix ending in a separator (a
    FRESH path component, landing directly inside that directory) as if it were
    extending a partial one (landing one level higher), so even adding ancestors
    would not have caught `mv /opt/{arm0,…,company} /tmp/x` -- a 70-plus-arm brace
    where one arm spells an ancestor's own exact name, with nothing after it.
    """

    def test_a_brace_spelling_an_ancestors_own_name_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        arms = ",".join(f"x{i}" for i in range(70)) + ",company"
        assert _blocked("mv /opt/{" + arms + "} /tmp/x")

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "Hardcodes the literal POSIX `/tmp` as `KIROCREW_HOME`'s prefix to "
            "exercise `_is_system_tmp_root`'s POSIX-`/tmp`-literal fallback "
            "specifically -- Windows has no such path or fallback, so the literal "
            "`/tmp` is just an ordinary, unrecognized ancestor there and the "
            "assertion this test pins does not hold."
        ),
    )
    def test_the_documented_tmp_false_positive_stays_fixed_even_with_a_nested_home(
        self, monkeypatch
    ) -> None:
        """The property that must NOT regress while fixing the above: a
        `KIROCREW_HOME` nested directly under the temp root -- this project's own
        test-isolation convention -- must not turn an ordinary `/tmp`-rooted brace
        into a refusal, the exact false positive `_is_system_tmp_root` already
        exists to prevent elsewhere in this file."""
        monkeypatch.setenv("KIROCREW_HOME", "/tmp/some-crew-home/.kiro/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("ls /tmp/{a..z}{a..z}")
        assert not _blocked("cp /data/img{a..z}{a..z}.jpg /out/")


class TestAnExactExtglobAlternativeIsNotVague:
    """GPT review: `@(company)` -- a SINGLE, unambiguous extglob alternative, no
    `|` -- names EXACTLY `company`. The widened `.*`/`*` readings that let a glob
    embedded in a larger literal still match (`comp@(any)` -> `comp*`) discard this
    when the group is the WHOLE leaf component: `mv /opt/@(company)` read as
    carrying no literal anchor at all, even though the operand names the ancestor
    exactly. A third reading substitutes an unambiguous group with its own text
    instead of a wildcard; an alternation (`@(a|b)`) or a group holding its own
    glob syntax is left widened, since it genuinely is vague.
    """

    def test_an_exact_single_alternative_names_the_ancestor(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/@(company) /tmp/x'")

    def test_an_ambiguous_alternation_is_not_claimed_as_exact(self, monkeypatch) -> None:
        """Must stay allowed -- `@(comp|other)` genuinely could be either, and
        `_extglob_exact_alternative` must not manufacture false precision for it."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'mv /opt/@(comp|other) /tmp/x'")

    def test_the_dotfile_and_embedded_cases_still_work(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv ~/@(.kiro) /tmp/x'")
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        assert _blocked("bash -O extglob -c 'mv /opt/comp@(any) /tmp/x'")


class TestEachMultiAlternativeExtglobAlternativeIsCheckedOnItsOwn:
    """GPT review: a multi-alternative group (`@(a|b)`) is not "matches anything" --
    it is a disjunction over a SMALL, KNOWN, finite set, and each alternative names
    something exactly, same as a single-alternative group does. Treating the whole
    group as a vague widening (the fix that made
    `TestAnExactExtglobAlternativeIsNotVague::test_an_ambiguous_alternation_is_not_
    claimed_as_exact` correctly allowed) went too far: `@(foo|SomeRepo)` was
    ALSO exempted even when `SomeRepo` is the exact ancestor -- the shape a
    real CI runner's own checkout path takes -- since nothing ever checked the
    alternatives individually, only the widened `*` reading, which is correctly
    vague-exempted. `_extglob_alternative_readings` now substitutes each
    alternative in turn as its own exact (non-vague) reading, alongside the
    widened one.
    """

    def test_one_matching_alternative_among_several_still_blocks(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/home/runner/work/SomeRepo/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /home/runner/work/@(foo|SomeRepo) /tmp/x'")

    def test_the_matching_alternative_can_be_first_or_last(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/@(company|foo) /tmp/x'")
        assert _blocked("bash -O extglob -c 'mv /opt/@(foo|company) /tmp/x'")

    def test_no_alternative_matching_still_stays_allowed(self, monkeypatch) -> None:
        """The property that must NOT regress: neither `comp` nor `other` is
        `company`, so this must still be allowed."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'mv /opt/@(comp|other) /tmp/x'")

    def test_a_glob_shaped_alternative_is_not_treated_as_exact(self, monkeypatch) -> None:
        """`@(comp*|other)` -- one alternative is itself glob-shaped, so it is not
        one exact string either; only the genuinely literal alternatives are
        checked this way, and the glob-shaped one is left to the existing widened
        reading. `overflowed` is now `True`, not `False` (GPT review, third
        pass): `comp*` was silently dropped rather than accounted for, so the
        widened reading kept its vague-widening exemption as if `other` were
        the only thing this group could ever mean -- even though `comp*` can
        ALSO equal an ancestor named `company`."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert security._extglob_alternative_readings("/opt/@(comp*|other)") == (
            ["/opt/other"],
            True,
        )


class TestASingletonBracketIsNotVague:
    """GPT review: the bracket-class equivalent of the extglob case above.
    `_pattern_component_has_literal_anchor` stripped EVERY bracket expression
    (`\\[[^\\]]*\\]`) unconditionally, treating `[c]` the same as `[abc]` or
    `[a-z]` -- but a SINGLETON bracket names exactly one character, no more vague
    than spelling that character bare. `[c][o][m][p][a][n][y]` is `company`
    letter-for-letter, so `mv /opt/[c][o][m][p][a][n][y] /tmp/stash` against a
    configured `KIROCREW_HOME=/opt/company/dept/crewdata` read as carrying no
    literal anchor at all and relocated the governance ceiling's own ancestor.
    A negated (`[!c]`, `[^c]`) or multi-character (`[abc]`, `[a-z]`) bracket keeps
    its ordinary vague reading -- both genuinely admit more than one character.
    """

    def test_singleton_brackets_spelling_the_ancestor_are_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/[c][o][m][p][a][n][y] /tmp/stash")

    def test_a_genuinely_vague_multi_char_bracket_class_is_unaffected(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("ls -la /tmp/[abc]")

    def test_a_genuinely_vague_bracket_range_is_unaffected(self, monkeypatch) -> None:
        assert not _blocked("ls -la /opt/[a-z]*")

    def test_a_negated_bracket_stays_vague(self) -> None:
        assert security._pattern_component_has_literal_anchor("[!c]") is False
        assert security._pattern_component_has_literal_anchor("[^c]") is False

    def test_a_non_alnum_singleton_still_counts_as_a_literal_anchor(self, monkeypatch) -> None:
        """GPT review: the final check was `any(ch.isalnum() for ch in stripped)`,
        so a de-bracketed singleton that isn't a letter or digit -- `_`, a common,
        ordinary filename character -- was correctly kept as literal text by
        `_debracket_singleton` but then refused to COUNT as an anchor by this
        stricter alnum filter. `KIROCREW_HOME=/opt/_/crew` with `mv /opt/[_]
        /tmp/x` read the leaf `[_]` as carrying no anchor at all. Fixed: by
        construction everything reaching the final check already had every
        wildcard and vague bracket class stripped, so any surviving character is
        literal -- non-emptiness is the correct test, not alnum-ness."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/_/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/[_] /tmp/x")
        assert security._pattern_component_has_literal_anchor("[_]") is True


class TestEscapedWhitespaceDoesNotSplitARawGlobWord:
    """GPT review: `_raw_glob_could_name_container` isolated glob-bearing words with
    a plain `text.split()`, which breaks on EVERY whitespace run -- including one
    bash itself treats as part of the same word. `my\\ dir` is ONE path component to
    bash (the backslash escapes the space), but `str.split()` cuts it into `my\\`
    and `dir`, and neither fragment alone matches an ancestor whose real name
    contains that space. `KIROCREW_HOME` under `/opt/my dir` with the interpreter
    payload `bash -c 'mv /opt/my\\ d[i]r /tmp/x'` -- an opaque `-c` argument only
    the raw scan sees inside -- relocated the ancestor. Fixed by splitting with
    `(?:\\\\.|\\S)+` (keeps an escaped character glued to its neighbors) and then
    un-escaping only the whitespace that split protected, leaving other backslash
    escapes (`\\[`, `\\*`) as-is.
    """

    def test_an_escaped_space_does_not_split_the_ancestors_name(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/my dir/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked(r"bash -c 'mv /opt/my\ d[i]r /tmp/x'")

    def test_an_ordinary_unescaped_space_still_separates_words(self, monkeypatch) -> None:
        """The property that must NOT regress: two genuinely separate arguments,
        with no escape between them, must still be split apart."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -c 'mv /opt/comp[a] /elsewhere notes.txt'")
        assert _blocked("bash -c 'mv /opt/comp[a][n][y] /elsewhere'")


class TestAnAssignmentFedThroughAParameterExpansionOperatorIsCaught:
    """GPT review: `H=$HOME/.kiro/crewXXXX; mv "${H%XXXX}"` trims an assigned value
    down to exactly the container path. The general substitution masking has no
    notion of assignments -- it reads `${H%XXXX}` as unknown output and masks it
    to a bare `*`, which then carries no path-shaped text for the "looks like a
    path" gate even to see. `_assignment_feeds_container_via_operator` does not
    try to compute the operator's actual effect (bash's trim/substring/case-
    conversion repertoire is not reimplemented here); instead, an assignment
    whose value already CONTAINS a container or ancestor as a substring, later
    referenced through ANY operator-form expansion, is refused outright -- the
    operator's presence is what makes the assigned text alone insufficient to
    clear the command, regardless of which specific operator runs.
    """

    def test_the_exact_reported_shape_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('H=$HOME/.kiro/crewXXXX; mv "${H%XXXX}" /tmp/x')

    def test_an_ancestor_reached_the_same_way_is_also_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('H=/opt/companyXXXX; mv "${H%XXXX}" /tmp/x')

    def test_an_ancestor_targets_own_separator_spelling_need_not_be_normalized(
        self, monkeypatch
    ) -> None:
        """Windows CI regression (GPT review, round 2): finding 33 normalized
        only the ASSIGNED VALUE before the substring check, on the assumption a
        target was already in the platform's native separator form. An ANCESTOR
        target is not: `_custom_home_ancestors` walks the as-configured
        spelling of `KIROCREW_HOME` alongside the abspath/realpath-normalized
        ones, and the as-configured spelling is never forced to native
        separators -- `KIROCREW_HOME=/opt/company/dept/crewdata` on Windows left
        an ancestor target spelled `/opt/company` (forward slash) sitting next
        to a normalized value's `\\opt\\companyXXXX` (backslash), matching
        neither. A redundant `./` segment exercises the identical
        both-sides-must-normalize fix on any platform: `/opt/./company`
        (target) is not literally a substring of `/opt/companyXXXX` (value)
        without normalizing the TARGET too."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        monkeypatch.setattr(
            security, "_container_target_groups", lambda: (set(), {"/opt/./company"})
        )
        assert _blocked('H=/opt/companyXXXX; mv "${H%XXXX}" /tmp/x')

    def test_an_ordinary_trim_on_an_unrelated_value_stays_allowed(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked('F=report.txt; echo "${F%.txt}"')
        assert not _blocked('N=filename; echo "${N#pre}"')

    def test_a_bare_reference_with_no_operator_is_unaffected(self) -> None:
        """The property that must NOT regress: a bare `${NAME}` (no operator) is
        an ordinary, already-handled substitution, not this new case."""
        assert not security._assignment_feeds_container_via_operator(
            "H=$HOME/.kiro/crew; echo ${H}"
        )

    def test_the_helper_requires_both_an_assignment_and_a_later_operator_reference(
        self,
    ) -> None:
        assert not security._assignment_feeds_container_via_operator("echo ${H%XXXX}")
        assert not security._assignment_feeds_container_via_operator(
            "H=$HOME/.kiro/crewXXXX; echo done"
        )

    @pytest.mark.parametrize("builtin", ["export", "declare", "local", "readonly", "typeset"])
    def test_a_declaration_builtin_does_not_hide_the_assignment(
        self, monkeypatch, builtin: str
    ) -> None:
        """GPT review: `export H=$HOME/.kiro/crewXXXX; mv "${H%XXXX}"` is the
        IDENTICAL assignment `H=$HOME/.kiro/crewXXXX` is, merely exported for
        child processes to see too -- but `_SIMPLE_ASSIGNMENT_RE`'s statement-
        boundary anchor expected `NAME=` to begin right after `;`/`&&`/`|`/the
        text's own start, and `export ` sitting between the boundary and `H=`
        meant the capture never started where it looked. Widened to allow an
        optional declaration builtin (`export`, `declare`, `local`, `readonly`,
        `typeset`) between the boundary and the assignment."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked(f'{builtin} H=$HOME/.kiro/crewXXXX; mv "${{H%XXXX}}" /tmp/x')

    def test_home_expansion_does_not_depend_on_the_home_environment_variable(
        self, monkeypatch
    ) -> None:
        """GPT review / Windows CI: `os.path.expandvars` only expands `$HOME`
        when the literal `HOME` environment variable is set -- true on POSIX,
        but Windows resolves the user's home through `USERPROFILE` instead and
        does not reliably set `HOME`, so the assigned value stayed literal text
        that could never match a resolved container path.
        `_assignment_feeds_container_via_operator` now resolves `$HOME`/
        `${HOME...}` against `Path.home()` directly (`_HOME_TEXT_REF_RE`),
        which already knows to fall back to `USERPROFILE` -- proven here by
        deleting `HOME` from the environment and confirming detection still
        fires without it."""
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('H=$HOME/.kiro/crewXXXX; mv "${H%XXXX}" /tmp/x')


class TestAQuotedAssignmentValueWithEmbeddedWhitespaceIsCaptured:
    """GPT review: `H=" $HOME/.kiro/crewXXXX"; mv ${H%XXXX} /tmp/stash` -- the
    assigned value is double-quoted and begins with a literal space.
    `_SIMPLE_ASSIGNMENT_RE`'s old value capture, `(\\S+)`, stops at the FIRST
    whitespace character, so it captured only the opening quote `"` and lost
    the rest of the value -- hiding `$HOME/.kiro/crewXXXX` from the substring
    check `_assignment_feeds_container_via_operator` runs downstream. Real
    bash keeps the leading space as part of the double-quoted value; the
    command then references `$H` UNQUOTED (`${H%XXXX}`, no surrounding
    quotes), so bash's own word-splitting on the expanded value discards that
    leading space as an IFS separator and leaves the container path as the
    final argument to `mv` -- a fully working relocation the truncated
    capture never saw.

    Widened the value alternation to a double-quoted span, a single-quoted
    span, or a run of bare non-whitespace-non-quote characters, repeated --
    so a quoted value is captured whole, whitespace and all, rather than
    truncated at its first space. The quotes are captured too (not stripped):
    the downstream containment check matches a substring anywhere in the
    (normalized) value, so a surrounding quote character never prevents a
    real match.
    """

    def test_the_reported_leading_space_bypass_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('H=" $HOME/.kiro/crewXXXX"; mv ${H%XXXX} /tmp/stash')

    def test_a_single_quoted_variant_is_also_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("H=' $HOME/.kiro/crewXXXX'; mv ${H%XXXX} /tmp/stash")

    def test_a_trailing_space_inside_the_quotes_is_also_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('H="$HOME/.kiro/crewXXXX "; mv ${H%XXXX} /tmp/stash')

    def test_a_declaration_builtin_does_not_hide_the_quoted_value_either(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('declare -x H=" $HOME/.kiro/crewXXXX"; mv ${H%XXXX} /tmp/stash')

    def test_an_unrelated_quoted_assignment_with_embedded_whitespace_stays_allowed(
        self,
    ) -> None:
        """The property that must NOT regress: widening the capture to include
        whitespace must not make an ordinary quoted assignment with no
        container-shaped content start tripping the check."""
        assert not security._assignment_feeds_container_via_operator(
            'MSG="hello world"; echo "${MSG%world}"'
        )

    def test_the_captured_value_includes_the_full_quoted_span(self) -> None:
        """Direct regex-level check: the value group must span the whole
        quoted token, not stop at the internal space."""
        match = security._SIMPLE_ASSIGNMENT_RE.search(
            'H=" $HOME/.kiro/crewXXXX"; mv ${H%XXXX} /tmp/stash'
        )
        assert match is not None
        assert match.group(2).startswith('" $HOME')


class TestANestedParameterExpansionInsideAHomeReferenceIsCaught:
    """GPT review: `${HOME:0:${#HOME}}` -- real bash syntax, a nested parameter
    expansion supplying the substring LENGTH -- evaluates to plain `$HOME`, but
    both `_OUTPUT_SUBSTITUTION_RE` and `_build_container_regex`'s `home_var`
    matched `${...}` with `[^}]*`, which stops at the FIRST closing brace: the
    INNER expansion's own `}`, leaving the OUTER one stray right before whatever
    container spelling followed. The masked/matched result then either carried
    an unconsumed `}` (breaking the "looks like a path" reading) or simply
    failed to match the raw regex at all. Both gained one level of balanced-
    brace tolerance, mirroring `_OUTPUT_SUBSTITUTION_RE`'s existing `$(...)`
    handling for the identical shape of problem.
    """

    def test_the_exact_reported_shape_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv ${HOME:0:${#HOME}}/.kiro/crew /tmp/x")

    def test_ordinary_single_level_operator_forms_are_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv ${HOME:0}/.kiro/crew /tmp/x")
        assert _blocked("mv ${HOME:-/root}/.kiro/crew /tmp/x")


class TestTheTempRootExemptionDoesNotDependOnWhichVariableSetIt:
    """A round of this fence tried excluding `tempfile.gettempdir()`'s result from
    the ancestor-walk exemption whenever `TMPDIR`/`TEMP`/`TMP` was SET, on the
    theory that a set variable meant a deliberate operator choice worth protecting
    like any other ancestor (GPT review). Reverted: that signal is not reliable
    cross-platform. macOS sets `TMPDIR` via launchd for EVERY process regardless of
    operator intent, so the exclusion fired unconditionally there, made
    `gettempdir()`'s own per-user temp root stop being treated as a boundary, and
    reopened the exact regression this whole mechanism exists to prevent -- on
    every macOS run, including this project's own `Gateway Tests (macOS)` CI job,
    which pins `KIROCREW_HOME` under it the same way Linux CI does. There is no
    cheap, reliable "was this a deliberate choice" signal that holds across every
    platform's own default, so the ancestor walk goes back to exempting whatever
    `tempfile.gettempdir()` (or the POSIX `/tmp` literal) resolves to, unconditionally
    -- matching `sandbox.py`'s OWN copy of this walk, which never adopted the
    per-variable distinction in the first place because protecting an ancestor
    unconditionally costs it nothing.
    """

    def test_the_ambient_tmpdir_is_still_exempt(self) -> None:
        """The regression's exact shape: `TMPDIR` set (as macOS always has it, and
        as this project's OWN rootdir conftest also does for every test, via
        `_redirect_tempfile_base`) must not stop the temp root from being treated
        as a boundary somewhere along `tempfile.gettempdir()`'s own ancestor chain.
        Walks UP from it rather than asserting the leaf itself is the boundary:
        this conftest's redirect nests `gettempdir()`'s result inside a further,
        outer temp root (`/tmp/kc-pytest-<user>-<pid>/...`), so the recognized
        boundary here is that OUTER root, with `gettempdir()`'s own value
        correctly still protected as an ordinary intermediate ancestor of it --
        exactly the invariant `test_the_boundary_helper_directly` already pins
        for `tmp_path`. Deliberately reads the AMBIENT value rather than setting
        one itself: this project's test suite already runs with `TMPDIR` set for
        the identical reason production macOS does, so no extra setup is needed
        -- or safe, given how many rounds of this exact fence tripped on
        `tempfile`'s own caching interacting badly with a manual reset."""
        import tempfile

        from kiro_crew.config.paths import _is_system_tmp_root

        assert os.environ.get("TMPDIR") or os.environ.get("TEMP") or os.environ.get("TMP")
        leaf = pathlib.Path(tempfile.gettempdir()).resolve()
        for ancestor in [leaf, *leaf.parents]:
            if _is_system_tmp_root(ancestor):
                assert not _is_system_tmp_root(ancestor.parent)
                break
        else:
            pytest.fail("no ancestor of gettempdir() was recognized as the temp root")

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "Hardcodes the literal POSIX `/tmp` as `KIROCREW_HOME`'s prefix to "
            "exercise `_is_system_tmp_root`'s POSIX-`/tmp`-literal fallback "
            "specifically -- Windows has no such path or fallback, so the literal "
            "`/tmp` is just an ordinary, unrecognized ancestor there and the "
            "assertion this test pins does not hold."
        ),
    )
    def test_an_ordinary_command_naming_the_temp_root_stays_allowed_with_tmpdir_set(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/tmp/some-crew-home/.kiro/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("cd /tmp && cat notes.txt")
        assert not _blocked("ls -la /tmp/*")

    def test_an_intermediate_ancestor_under_the_temp_root_stays_protected(
        self, monkeypatch, tmp_path
    ) -> None:
        """The property the exemption must NOT weaken: a uniquely-identifying
        directory strictly BETWEEN the leaf and the temp root is unaffected by
        where the boundary itself sits."""
        nested = tmp_path / "company" / "dept" / "crewdata"
        nested.parent.mkdir(parents=True)
        monkeypatch.setenv("KIROCREW_HOME", str(nested))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        company_dir = os.path.join(os.path.realpath(str(tmp_path)), "company")
        assert _blocked("mv %s /tmp/x" % company_dir)


class TestCustomHomeAncestorDiscoveryIsCached:
    """GPT review: `_custom_home_ancestors` does a `realpath()` syscall -- slow, or
    even stalling, on a network-backed data home -- and is now called from the
    substitution scanner, the glob scanner, and `is_unreplaceable_container`, all
    of them UNCACHED call sites, unlike `_build_container_regex`'s own callers,
    which only ever ran through `_get_container_re`'s TTL wrapper. Extracting this
    walk into a function shared by those three turned one blocking syscall per
    distinct `KIROCREW_HOME` value into one per command evaluated through any of
    them. A TTL cache, mirroring `_home_dir_targets`'s own, bounds that back down.
    """

    def test_repeated_calls_within_the_ttl_hit_the_cache(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        security._custom_home_ancestors_cache.clear()
        calls = []
        real_realpath = os.path.realpath

        def _counting_realpath(path, *args, **kwargs):
            calls.append(path)
            return real_realpath(path, *args, **kwargs)

        monkeypatch.setattr(security.os.path, "realpath", _counting_realpath)
        first = security._custom_home_ancestors()
        after_first_build = len(calls)
        assert after_first_build > 0, "the uncached build should call realpath() at least once"
        second = security._custom_home_ancestors()
        assert first == second
        assert (
            len(calls) == after_first_build
        ), f"second call should be a pure cache hit, adding no realpath() calls; got {calls}"

    def test_a_different_kirocrew_home_is_not_served_from_the_others_cache_entry(
        self, monkeypatch
    ) -> None:
        security._custom_home_ancestors_cache.clear()
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        first = security._custom_home_ancestors()
        monkeypatch.setenv("KIROCREW_HOME", "/srv/other/deep/crewdata")
        second = security._custom_home_ancestors()
        assert first != second
        assert "/opt/company" in first
        assert "/srv/other" in second


class TestSubstitutionOutputIsNotSubjectToTheDotglobRule:
    """Opus 4.8 review: `_substitution_could_name_container` masks unknown
    substitution output to a bare `*` and checks it as an ordinary shell glob --
    but command substitution splices its output in LITERALLY, with no dotfile
    exemption of its own: `$(printf .kiro)` really does yield `.kiro`. Reading the
    mask as dotglob-sensitive let `~/$(printf .kiro)` mask to `~/*`, which
    `_glob_component_matches` then refused to match against the dot-prefixed
    `.kiro` target -- every fixed container is dot-prefixed under `$HOME`, so this
    silently exempted the whole scanner from ever catching a substitution-supplied
    leading dot.
    """

    def test_a_substitution_supplied_leading_dot_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv ~/$(printf .kiro) /tmp/stash")

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "Hardcodes the literal POSIX `/tmp` as `KIROCREW_HOME`'s prefix to "
            "exercise `_is_system_tmp_root`'s POSIX-`/tmp`-literal fallback "
            "specifically -- Windows has no such path or fallback, so the literal "
            "`/tmp` is just an ordinary, unrecognized ancestor there and the "
            "assertion this test pins does not hold."
        ),
    )
    def test_the_leaf_literal_anchor_requirement_still_protects_a_bare_wildcard(
        self, monkeypatch
    ) -> None:
        """The property that must NOT regress: `dotglob=True` alone would let a
        bare `*` (from an unqualified substitution) match ANY ancestor target,
        dot-prefixed or not, if `require_leaf_literal` weren't independently
        still in force for the ancestor-targets call."""
        monkeypatch.setenv("KIROCREW_HOME", "/tmp/some-crew-home/.kiro/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv $(echo /tmp/x)/* /elsewhere")
        assert not _blocked("cd /tmp && cat notes.txt")


class TestASymlinkedIntermediateAncestorIsProtectedTooSandbox:
    """GPT review: `sandbox._unrenamable_containers`'s ancestor walk was based on
    the RESOLVED leaf only. A symlinked LEAF was already covered (the unresolved
    override is appended as its own entry), but a symlinked INTERMEDIATE ancestor
    -- `KIROCREW_HOME=/opt/symlinked-dept/crewdata` where `symlinked-dept` is
    itself a symlink -- had no equivalent: `/opt/symlinked-dept`'s own directory
    entry never appeared in the resolved chain at all, so nothing protected it
    from `rm /opt/symlinked-dept && ln -s /evil /opt/symlinked-dept`, which
    repoints every future resolution the same way a symlinked leaf swap does.
    """

    def test_a_symlinked_intermediate_ancestor_is_in_the_protected_list(
        self, monkeypatch, tmp_path
    ) -> None:
        from kiro_crew import sandbox

        real_dept = tmp_path / "real-dept"
        real_dept.mkdir()
        symlinked = tmp_path / "symlinked-dept"
        symlinked.symlink_to(real_dept)
        monkeypatch.setenv("KIROCREW_HOME", str(symlinked / "crewdata"))
        containers = sandbox._unrenamable_containers()
        assert str(symlinked) in containers

    def test_ordering_still_holds_across_both_spellings(self, monkeypatch, tmp_path) -> None:
        """Every ancestor must still precede every descendant, for BOTH the
        resolved chain and the unresolved-spelling chain -- merging two
        potentially-divergent ancestor chains must not break the mount-ordering
        invariant `_build_launcher_script`'s self-bind loop depends on."""
        from kiro_crew import sandbox

        real_dept = tmp_path / "real-dept"
        real_dept.mkdir()
        symlinked = tmp_path / "symlinked-dept"
        symlinked.symlink_to(real_dept)
        monkeypatch.setenv("KIROCREW_HOME", str(symlinked / "crewdata"))
        containers = sandbox._unrenamable_containers()
        for i, a in enumerate(containers):
            for j, b in enumerate(containers):
                if a != b and b.startswith(a.rstrip("/") + "/"):
                    assert i < j, f"{a!r} (index {i}) must precede {b!r} (index {j})"


class TestARelativeOverrideIsAnchoredToTheGatewaysOwnCwd:
    """GPT review: a `KIROCREW_HOME` override with no leading `~` or `/`
    (`KIROCREW_HOME=../dept/crewdata`) survived `Path(override_raw).expanduser()`
    still relative -- `expanduser()` only ever touches a leading `~`. That
    relative string was then embedded into the launcher script and evaluated by
    the SPAWNED CHILD's own `os.path.islink`/`isdir`/mount(2) calls against ITS
    OWN cwd, not the gateway's: a task spawned with a different `cwd=` resolved
    the "protect this override" entry to an unrelated path, and the self-bind
    protection silently checked nothing there. `os.path.abspath` (lexical only,
    no symlink following, unlike `.resolve()`) anchors it to the GATEWAY's own
    cwd instead, captured before the spawn -- so the entry means the same thing
    regardless of what cwd the eventual child runs with.
    """

    def test_every_entry_is_absolute_even_with_a_relative_override(
        self, monkeypatch, tmp_path
    ) -> None:
        from kiro_crew import sandbox

        base = tmp_path / "base"
        base.mkdir()
        (base / "crewdata").mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("KIROCREW_HOME", "base/crewdata")
        containers = sandbox._unrenamable_containers()
        relative = [c for c in containers if not os.path.isabs(c)]
        assert relative == [], f"relative entries leaked through: {relative!r}"

    def test_a_relative_symlinked_override_still_protects_the_links_own_path(
        self, monkeypatch, tmp_path
    ) -> None:
        """Isolates the fix from `resolved`'s own (already-correct, `.resolve()`d)
        ancestor walk: `resolved` FOLLOWS the symlink, so its own walk never
        contains the symlink's OWN path -- only the unresolved-override entry
        this fix repairs can put it there. A relative spelling through the
        symlink (`base/crewdata`) must still surface the symlink's absolute
        path, anchored to the gateway's cwd, not silently drop it."""
        from kiro_crew import sandbox

        real_dept = tmp_path / "real-dept"
        real_dept.mkdir()
        symlinked = tmp_path / "base"
        symlinked.symlink_to(real_dept)
        (real_dept / "crewdata").mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("KIROCREW_HOME", "base/crewdata")
        containers = sandbox._unrenamable_containers()
        assert str(symlinked) in containers


class TestFixedPointBudgetsFailClosedNotOpen:
    """GPT review: both fixed-point loops (`_substitution_could_name_container`'s
    masking loop, `_glob_could_name`'s extglob-widening loop) stopped after
    `_MAX_..._PASSES` iterations and used whatever partial result they had --
    which, for a nesting depth chosen specifically to outlast the budget, still
    contains unresolved `$(...)`/`@(...)` syntax. That syntax reads as an
    unrelated literal to every check downstream, so "stops early" meant "matches
    nothing at all", not "a narrower match" as the (now-corrected) comments
    claimed -- the exact fail-OPEN direction every other bounded scan in this
    module is designed to avoid.
    """

    def test_substitution_nesting_past_the_budget_fails_closed(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        nested = "printf i"
        for _ in range(20):
            nested = "echo $(" + nested + ")"
        assert _blocked("mv ~/.k" + nested + "ro/crew /tmp/x")

    def test_extglob_nesting_past_the_budget_fails_closed(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        nested = "i"
        for _ in range(10):
            nested = "@(" + nested + ")"
        assert _blocked("bash -O extglob -c 'mv ~/.k" + nested + "ro/crew /tmp/x'")

    def test_ordinary_nesting_within_budget_is_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo $(echo $(echo $(date)))")
        assert not _blocked("bash -O extglob -c 'ls @(*.txt|*.md)'")


class TestMultiDigitBraceRangesAreRecognized:
    """GPT review: `_BRACE_RANGE_RE` captured each range endpoint as a bare `\\w`
    -- exactly one character -- so `{10..10}` was never recognized as a brace
    range AT ALL, not merely expanded wrong: the token passed through
    `_expand_braces` completely unchanged, and `company{10..10}` never matched
    an ancestor literally named `company10`. Widened to accept signed,
    multi-digit numeric endpoints (bash's own zero-padding rule included) as
    well as the original single-letter alpha case.
    """

    def test_a_multi_digit_range_reaches_the_ancestors_name(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company10/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/company{10..10}/dept /tmp/x")

    def test_zero_padding_reaches_the_ancestors_name(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company001/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/company{001..001}/dept /tmp/x")

    def test_ordinary_alpha_and_numeric_ranges_are_unaffected(self) -> None:
        assert security._expand_braces("cr{e..e}w") == ["crew"]
        assert security._expand_braces("img{1..3}.jpg") == ["img1.jpg", "img2.jpg", "img3.jpg"]
        assert security._expand_braces("n{5..1}") == ["n5", "n4", "n3", "n2", "n1"]


class TestZeroPaddingWidthMatchesTheWiderEndpoint:
    """Opus review: "does this range zero-pad at all" and "how wide" are separate
    questions, and the width computation answered both from only the endpoints
    that themselves began with `0` -- correct for deciding WHETHER to pad
    (`{01..100}` must pad, since `01` qualifies), wrong for deciding the WIDTH,
    which bash always takes from the WIDER of the two endpoints regardless of
    which one carries the leading zero. `{01..100}` -> bash pads to width 3
    (`001`...`100`); the previous code measured width only from `01` (2),
    producing `01`...`100` with `099` never generated -- so
    `KIROCREW_HOME=/opt/node099/crew` reached by `mv /opt/node{01..100}
    /tmp/x` relocated the ancestor without this scan ever emitting the
    candidate that would have matched it.

    `{01..100}` itself is not a clean regression test: 100 terms exceeds
    `_MAX_BRACE_EXPANSIONS` (64), so both the buggy and the fixed code already
    refuse it via the unrelated overflow-fails-closed path -- the width bug
    never gets exercised. A stepped range (`{01..999..300}`) reaches the same
    narrow-then-wide shape in only 4 terms, under the budget, so the width
    bug is the only thing that can make the difference between blocked and
    not. Verified against the `braceexpand` package (a faithful
    reimplementation of bash's own algorithm) rather than a real bash: this
    project's own dev/CI hosts ship bash 3.2, which predates brace
    zero-padding entirely and could not have caught this by hand-testing
    either.
    """

    def test_the_reported_ancestor_relocation_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/node001/crew")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/node{01..999..300} /tmp/x")

    def test_the_width_is_taken_from_the_wider_non_zero_endpoint(self) -> None:
        assert security._expand_braces("node{01..999..300}") == [
            "node001",
            "node301",
            "node601",
            "node901",
        ]

    def test_the_narrower_zero_padded_endpoint_stays_the_width_when_it_is_wider(
        self,
    ) -> None:
        """The property that must NOT regress: when the zero-padded endpoint
        already IS the wider one, the width is unchanged."""
        assert security._expand_braces("n{001..5}") == [
            "n001",
            "n002",
            "n003",
            "n004",
            "n005",
        ]

    def test_neither_endpoint_zero_padded_stays_unpadded(self) -> None:
        assert security._expand_braces("n{1..500..100}") == [
            "n1",
            "n101",
            "n201",
            "n301",
            "n401",
        ]


class TestALargeNumericBraceRangeCannotStallTheGate:
    """Opus review: widening ``_BRACE_RANGE_RE`` to multi-digit endpoints let a SHORT
    command carry a numeric range whose SPAN is astronomically large --
    ``{1..99999999999999999999999999999}`` is 31 digits, under the
    ``_MAX_BRACE_STEP_DIGITS`` length guard, but its span is ~10**31 terms. The
    cardinality check (``len(grown) > _MAX_BRACE_EXPANSIONS``) ran only AFTER the
    numeric branch's list comprehension had already materialized the full span into a
    Python list -- so the comprehension itself was the unbounded work, a memory-
    exhausting synchronous stall directly on the event loop inside the PreToolUse gate.
    The term count is now computed from plain `int` arithmetic on the endpoints BEFORE
    either comprehension runs, and compared against the SAME budget. `len()` on the
    `range` object itself was tried first and rejected: it raises `OverflowError` for a
    span this large (CPython's `len` protocol must fit a C `Py_ssize_t`), which would
    have traded the stall for an uncaught crash instead of the gate's normal fail-closed
    refusal.
    """

    def test_a_huge_positive_span_overflows_instead_of_stalling(self) -> None:
        start = time.monotonic()
        result = _blocked("echo {1..99999999999999999999999999999}")
        elapsed = time.monotonic() - start
        assert result
        assert elapsed < 2.0, f"took {elapsed}s -- the span was materialized, not bounded"

    def test_a_huge_negative_to_small_span_overflows_instead_of_stalling(self) -> None:
        start = time.monotonic()
        result = _blocked("echo {-99999999999999999999999999999..1}")
        elapsed = time.monotonic() - start
        assert result
        assert elapsed < 2.0, f"took {elapsed}s -- the span was materialized, not bounded"

    def test_a_huge_span_with_a_step_overflows_instead_of_stalling(self) -> None:
        start = time.monotonic()
        result = _blocked("echo {1..99999999999999999999999999999..7}")
        elapsed = time.monotonic() - start
        assert result
        assert elapsed < 2.0, f"took {elapsed}s -- the span was materialized, not bounded"

    def test_ordinary_ranges_are_unaffected(self) -> None:
        assert security._expand_braces("x{1..5}") == ["x1", "x2", "x3", "x4", "x5"]
        assert security._expand_braces("company{10..10}") == ["company10"]


class TestAMixedNumericAlphaBraceEndpointDoesNotCrash:
    """GPT review: widening each endpoint to `[+-]?\\d+|[A-Za-z]` let the two
    alternatives combine into a MIXED pair -- ``{10..a}`` matches `start="10"` via
    the digit alternative and `end="a"` via the single-letter alternative. The branch
    selecting numeric-vs-alpha handling only tested digit-ness (`start_digits.isdigit()
    and end_digits.isdigit()`), not length, so a mixed pair fell through to the alpha
    branch's `ord(start)`, which requires an exactly-one-character string and raised
    `TypeError` for the two-character `"10"` -- crashing `is_sensitive_bash_command`
    and aborting the tool-authorization decision entirely, rather than returning ANY
    verdict. Bash itself does not treat a mixed numeric/alpha pair as a range either
    (`{10..a}` is left unexpanded), so refusing it here -- fail closed, via the same
    `_overflow` path other unrecognized brace syntax already takes -- matches both
    bash's own behavior and this gate's convention of refusing what it cannot expand.
    """

    def test_numeric_then_alpha_does_not_crash(self) -> None:
        assert _blocked("echo {10..a}")

    def test_alpha_then_numeric_does_not_crash(self) -> None:
        assert _blocked("echo {a..10}")

    def test_ordinary_single_char_alpha_ranges_are_unaffected(self) -> None:
        assert security._expand_braces("cr{e..e}w") == ["crew"]
        assert security._expand_braces("n{a..c}") == ["na", "nb", "nc"]


class TestAPositiveSignedBraceStepIsRecognized:
    """GPT review: `_BRACE_RANGE_RE`'s optional step group only accepted `-?\\d+` --
    an optional MINUS, never a PLUS -- while bash accepts an explicit leading `+` on
    the step the same way it does on either endpoint. `{e..e..+1}` therefore failed
    to match the regex AT ALL: the step group is required once `..` starts a third
    segment, and `+1` does not fit `-?\\d+`, so the whole match fails at that
    position. Because the belt-and-braces overflow check re-uses this SAME regex,
    it found nothing to refuse either, and a degenerate single-value range like
    `cr{e..e..+1}w` -- which bash still expands to `crew` regardless of the step's
    sign, since start and end are equal -- passed through completely unexpanded and
    unchecked. Widened the step group to `[+-]?\\d+`, matching the two endpoints.
    """

    def test_a_positive_step_degenerate_range_is_recognized(self) -> None:
        assert _blocked("mv ~/.kiro/cr{e..e..+1}w /tmp/x")

    def test_a_negative_step_still_works(self) -> None:
        assert _blocked("mv ~/.kiro/cr{e..e..-1}w /tmp/x")

    def test_an_ordinary_positive_step_range_is_unaffected(self) -> None:
        assert security._expand_braces("x{1..5..+2}") == ["x1", "x3", "x5"]

    def test_an_ordinary_unsigned_step_range_is_unaffected(self) -> None:
        assert security._expand_braces("x{1..5..2}") == ["x1", "x3", "x5"]


class TestShoptDashSAcceptsMultipleOptionNames:
    """GPT review: `shopt -s dotglob` (and the equivalent `globstar`/`extglob`
    patterns) required the target option name to appear IMMEDIATELY after `-s`,
    but bash's `shopt -s` accepts a SPACE-SEPARATED LIST of option names in one
    invocation -- `shopt -s nullglob dotglob` enables both. `shopt -s nullglob
    dotglob; mv ~/* /tmp/x` left `dotglob` undetected (it is the SECOND argument,
    not the first), so the glob-modes check ran without `dotglob=True` and the
    leading-dot exemption on `*` let `~/*` miss the `.kiro` ancestor it should
    have matched. All three mode regexes (`_DOTGLOB_ENABLED_RE`,
    `_GLOBSTAR_ENABLED_RE`, `_EXTGLOB_ENABLED_RE`) now allow any number of OTHER
    option names between `-s` and the target, so the target is found regardless
    of where in the list it sits.
    """

    def test_dotglob_as_the_second_shopt_argument_is_detected(self) -> None:
        assert _blocked("shopt -s nullglob dotglob; mv ~/* /tmp/x")

    def test_dotglob_as_the_first_shopt_argument_is_detected(self) -> None:
        assert _blocked("shopt -s dotglob nullglob; mv ~/* /tmp/x")

    def test_globstar_and_extglob_are_detected_alongside_other_options_too(self) -> None:
        assert security._GLOBSTAR_ENABLED_RE.search("shopt -s nullglob globstar")
        assert security._EXTGLOB_ENABLED_RE.search("shopt -s nullglob extglob")

    def test_an_unrelated_option_alone_does_not_falsely_enable_dotglob(self) -> None:
        assert not security._DOTGLOB_ENABLED_RE.search("shopt -s nullglob")

    def test_the_single_option_form_still_works(self) -> None:
        assert _blocked("shopt -s dotglob; mv ~/* /tmp/x")


class TestTheNormalizerPassAlsoSeesAncestorTargets:
    """GPT review: the raw substitution/glob scanners and `is_unreplaceable_container`
    were wired to `_container_target_groups()` a round ago, but the NORMALIZER
    pass's own two glob checks -- one for a plain normalized candidate, one for a
    `cd`-relative joined candidate -- still built their target set from
    `_UNREPLACEABLE_CONTAINER_DIRS` alone, a fourth (and fifth) place with the
    identical gap. `_glob_could_name_container` now backs both.
    """

    def test_the_shared_helper_matches_an_ancestor(self, monkeypatch) -> None:
        """Tests `_glob_could_name_container` -- what both call sites now share --
        directly, rather than through a full command. An end-to-end command
        naming an ancestor also trips the RAW regex independently (the literal
        text of an assignment or a `cd` target naming the ancestor's own path is
        exactly what that pass matches on), which would pass whether or not
        THIS specific fix is present and prove nothing about it."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        assert security._glob_could_name_container("/opt/comp*")

    def test_the_shared_helper_leaves_an_unrelated_glob_alone(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        assert not security._glob_could_name_container("/elsewhere/other*")

    def test_the_fixed_dirs_case_still_works_through_the_cd_relative_call_site(
        self, monkeypatch
    ) -> None:
        """`_glob_could_name_container` must not have narrowed the EXISTING,
        already-tested fixed-container matching at the `cd`-relative call site."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("cd ~ && mv .kir?/crew /tmp/x")

    def test_ordinary_normalizer_globs_with_no_ancestor_are_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("V=/opt; ls $V/*.txt")


class TestConcatenatedLiteralsAreCheckedEvenWithNoSubstitution:
    """Opus review: `_concatenated_literal_candidates` reconstructs Python-style
    (and similar) string concatenation (`'~/.k' + 'iro/crew'`), but was only ever
    reached after an early return on "no substitution syntax present" -- dead code
    whenever a payload concatenates literals with no `$(...)` anywhere in it at
    all. `os.rename(os.path.expanduser('~/.k' + 'iro/crew'), ...)` has no
    substitution for `_OUTPUT_SUBSTITUTION_RE` to find, so the function returned
    `False` before the ONE check that reconstructs exactly this idiom ever ran.

    Fixing this surfaced a second bug: the reconstructed candidate is a fully
    resolved literal with no glob characters at all, so `_glob_could_name`'s own
    "this has to look like a glob" gate silently excluded it too. And fixing
    THAT naively (forcing `dotglob=True` for every caller of the shared
    `_could_name` helper) broke `ls ~/*` -- an ordinary glob in a command with no
    substitution at all started reading as `~/.kiro`, which bash itself would
    never do without `dotglob` actually enabled. `dotglob=True` is now scoped to
    the substitution-derived callers only.
    """

    def test_pure_concatenation_with_no_substitution_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked(
            "python3 -c \"os.rename(os.path.expanduser('~/.k' + 'iro/crew'), '/tmp/x')\""
        )

    def test_an_ordinary_substitution_free_glob_is_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("ls ~/*")
        assert not _blocked('echo "a" + "b"')

    def test_substitution_and_dotfile_substitution_still_work(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv ~/.k$(printf i)ro/crew /tmp/x")
        assert _blocked("mv ~/$(printf .kiro) /tmp/stash")


class TestDeniedCommandsJsonIsAKeystoneFile:
    """GPT review: `denied_commands.json` (the opt-out ceiling for `disable_all` /
    `disabled_ids` / `user_added`, read by `hooks.read_denied_commands_config`) is
    the SAME class of control as `security_policy.json` / `admission_policy.json`
    / `computer_use.json` -- the command gate refuses a tool call naming it, a
    subprocess never goes through that gate -- but was missing from
    `sandbox._KEYSTONE_FILES`, the list that hides these files from an agent's OWN
    sandboxed subprocess on every tier.

    Superseded by #7439 (landed on `main` after this finding): the OS-level
    control for all four moved from `_KEYSTONE_FILES` (hide as an empty stub) to
    `_CREW_READONLY_LEAVES` (seal read-only, keep the real content readable) --
    `hooks.read_denied_commands_config` reads this file IN-SANDBOX, and a hidden
    stub broke that read the same way a hidden `profiles/` broke `boot_platform()`.
    `test_sandbox_governance_mask.py::TestKeystonesAreSealedInEveryMode` now
    covers `denied_commands.json` under that disposition, on every tier and both
    backends -- a strictly stronger guarantee than list membership alone.
    """

    def test_denied_commands_json_is_a_declared_readonly_ceiling(self) -> None:
        from kiro_crew import sandbox

        assert "denied_commands.json" in sandbox._CREW_READONLY_LEAVES


class TestADeclarationBuiltinsOwnFlagsDoNotHideTheAssignment:
    """GPT review: `declare -x H=$HOME/.kiro/crewXXXX; mv "${H%XXXX}"` still names
    the container, but `_SIMPLE_ASSIGNMENT_RE`'s declaration-word group still
    expects `H=` to follow immediately -- `-x ` sitting between the builtin and the
    assignment defeats the match the same way the missing declaration word itself
    did (finding 31). Widened to tolerate any number of `-flag` groups between the
    builtin and the assignment.
    """

    @pytest.mark.parametrize(
        "prefix", ["declare -x", "declare -xr", "export -p", "local -i", "readonly -a"]
    )
    def test_a_flagged_declaration_builtin_does_not_hide_the_assignment(
        self, monkeypatch, prefix: str
    ) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked(f'{prefix} H=$HOME/.kiro/crewXXXX; mv "${{H%XXXX}}" /tmp/x')

    def test_an_ordinary_flagged_declaration_on_an_unrelated_value_stays_allowed(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked('declare -x F=report.txt; echo "${F%.txt}"')


class TestADoubledSeparatorDoesNotHideTheContainerRename:
    """GPT review: the Pass 1b separator-collapse retry (`#6350`) reruns the
    sensitive-path matcher, the trust-root extraction check, and the relative-
    traversal matcher over every separator-collapsed spelling of the command --
    but not `_names_unreplaceable_container_raw`, the container-RENAME check,
    despite the comment directly above the loop claiming completeness
    (`ALL THREE pass-1 checks are repeated`). A doubled interior separator
    (`$HOME\\.kiro\\\\crew`, which Win32 collapses to the exact container) named
    the container in a spelling this scan's raw-text patterns never wrote, so it
    matched no branch at all -- an unobfuscated `mv ~/.kiro/crew` was refused, but
    the same rename survived one doubled backslash.
    """

    def test_a_doubled_backslash_between_kiro_and_crew_still_blocks_the_rename(self) -> None:
        assert _blocked("mv $HOME\\.kiro\\\\crew /tmp/x")

    def test_a_doubled_backslash_right_after_home_still_blocks_the_rename(self) -> None:
        assert _blocked("mv $HOME\\\\.kiro\\crew /tmp/x")

    def test_the_run_intact_spelling_was_already_blocked(self) -> None:
        """The property this fix must not regress: the raw pass already caught the
        single-backslash spelling directly, with no collapse needed."""
        assert _blocked("mv $HOME\\.kiro\\crew /tmp/x")

    def test_an_unrelated_command_with_a_doubled_separator_stays_allowed(self) -> None:
        assert not _blocked("ls -la C:\\\\Users\\\\u\\\\Documents")


class TestMultipleExtglobGroupsAreExpandedTogether:
    """GPT review, second pass: `_extglob_alternative_readings` was bounded to the
    FIRST extglob group found, on the theory the widened reading covers the rest
    defensively -- but a SECOND group's raw, unexpanded syntax left in a reading
    never structurally matches any target (`_components_could_match` does not
    itself understand extglob), while the fully-widened reading DOES structurally
    match yet was exempted as a "small, known set" -- which stopped being true
    the moment a second independent choice was folded in. `/opt/@(foo|company)/
    @(bar|dept)` against `KIROCREW_HOME=/opt/company/dept/crewdata` named the
    ancestor via the ONE combination (`company`+`dept`) that matters, while the
    other three combinations do not, and only enumerating every combination
    together tells them apart.
    """

    def test_the_one_matching_combination_still_blocks(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/@(foo|company)/@(bar|dept) /tmp/x'")

    def test_no_combination_matching_stays_allowed(self, monkeypatch) -> None:
        """The property that must NOT regress: none of the four combinations
        (foo+bar, foo+dept, company+bar, xx+yy) equals the ancestor except
        company+dept, so a command naming only the OTHER three must stay
        allowed."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'mv /opt/@(foo|xx)/@(bar|yy) /tmp/x'")

    def test_the_readings_are_the_full_cartesian_product(self) -> None:
        readings, overflowed = security._extglob_alternative_readings(
            "/opt/@(foo|company)/@(bar|dept)"
        )
        assert overflowed is False
        assert sorted(readings) == sorted(
            ["/opt/foo/bar", "/opt/foo/dept", "/opt/company/bar", "/opt/company/dept"]
        )


class TestExtglobAlternativeOverflowFailsClosedNotOpen:
    """A cartesian product too large to enumerate exhaustively
    (`_MAX_EXTGLOB_ALTERNATIVE_COMBINATIONS`) must not silently under-cover the
    combinations it cannot check individually -- the widened `.*`/`*` reading is
    what is left, and it loses its "small, known set" vague exemption in that
    case, so a structural match still fails closed instead of silently passing.
    """

    _MANY_ALTERNATIVES = "|".join(f"alt{i}" for i in range(9))  # 9 * 9 = 81 > 64

    def test_the_overflow_flag_is_set_and_no_readings_are_returned(self) -> None:
        token = f"/opt/@({self._MANY_ALTERNATIVES})/@({self._MANY_ALTERNATIVES})"
        readings, overflowed = security._extglob_alternative_readings(token)
        assert overflowed is True
        assert readings == []

    def test_an_unenumerable_product_still_blocks_via_the_widened_reading(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        token = f"/opt/@({self._MANY_ALTERNATIVES})/@({self._MANY_ALTERNATIVES})"
        assert _blocked(f"bash -O extglob -c 'mv {token} /tmp/x'")

    def test_an_unrelated_shape_stays_allowed_even_when_overflowed(self, monkeypatch) -> None:
        """The property that must NOT regress: the overflow fallback only
        withholds the vague exemption for a STRUCTURAL match -- it does not turn
        every overflowed token into a match against every ancestor."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        token = f"/somewhere/@({self._MANY_ALTERNATIVES})/@({self._MANY_ALTERNATIVES})"
        assert not _blocked(f"bash -O extglob -c 'mv {token} /tmp/x'")


class TestAPartiallyGlobShapedGroupIsNotTreatedAsFullyEnumerated:
    """GPT review, third pass: `_extglob_alternative_readings` DROPS a glob-
    shaped alternative from its own group's list (it is not one exact string
    either), but a round-27 gap left the GROUP itself reported as fully,
    exhaustively enumerated (`overflowed=False`) whenever ANY exact
    alternatives survived the drop. `@(foo|comp*)` against
    `KIROCREW_HOME=/opt/company/dept/crewdata` kept enumerating `foo` alone
    and reported a complete result -- even though `comp*` can ALSO equal the
    ancestor `company`, and nothing ever checked it. The widened `.*`/`*`
    reading then kept its vague-widening exemption on the strength of that
    false "fully enumerated" signal, letting `mv /opt/@(foo|comp*) /tmp/x`
    relocate the ancestor.
    """

    def test_a_glob_shaped_alternative_sharing_a_group_with_an_exact_one_still_blocks(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/@(foo|comp*) /tmp/x'")

    def test_the_exact_alternative_is_still_returned_alongside_the_overflow_flag(
        self,
    ) -> None:
        readings, overflowed = security._extglob_alternative_readings("/opt/@(foo|comp*)")
        assert readings == ["/opt/foo"]
        assert overflowed is True

    def test_an_unrelated_shape_stays_allowed_despite_the_mixed_group(self, monkeypatch) -> None:
        """The property that must NOT regress: a mixed group against a
        NON-matching prefix must not turn into a block against every
        ancestor."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'mv /somewhere/@(foo|comp*) /tmp/x'")


class TestAnAbsentKeystoneFileGetsASafePlaceholder:
    """GPT review: the Linux namespace sandbox hides a keystone FILE by bind-
    mounting an empty tmpfs file OVER it, and `mount(2)` requires the target to
    already exist -- so a keystone file this box never configured got no hiding
    mount at all. Nothing then stopped a sandboxed subprocess from CREATING it
    directly -- the exact "opaque script defeats the tool gate" bypass
    `_KEYSTONE_FILES` exists to close, just for a file that happens not to exist
    yet. `_sensitive_file_placeholders` maps each keystone file with a content
    confirmed to read BYTE-IDENTICALLY to "absent" through its own loader to the
    text materialized (then immediately hidden by the same mount) before that
    check, so the mount can exist at all.

    `computer_use.json`, `denied_commands.json`, and `admission_policy.json` --
    the files this class originally exercised -- moved to the READONLY
    disposition (#7439) and left `_KEYSTONE_FILES`; their absence is now handled
    by `READONLY_DIRS`'s own `os.path.exists` guard, which needs no placeholder
    at all (an absent ceiling is simply left absent, matching what happens
    outside the sandbox too). `autonudge.json`, the one entry still hidden this
    way, exercises the identical mechanism.
    """

    def test_every_registered_placeholder_is_a_real_keystone_entry(self) -> None:
        from kiro_crew import sandbox

        for entry in sandbox._KEYSTONE_FILE_ABSENT_PLACEHOLDERS:
            assert entry in sandbox._KEYSTONE_FILES

    def test_autonudge_json_has_a_registered_placeholder(self) -> None:
        from kiro_crew import sandbox

        assert sandbox._KEYSTONE_FILE_ABSENT_PLACEHOLDERS[".kiro/crew/autonudge.json"] == b"{}"
        assert sandbox._KEYSTONE_FILE_ABSENT_PLACEHOLDERS[".kirocrew/autonudge.json"] == b"{}"

    def test_the_placeholder_map_is_anchored_to_the_real_home(self) -> None:
        from kiro_crew import sandbox

        files = sandbox._CC_FILES + sandbox._KEYSTONE_FILES
        placeholders = sandbox._sensitive_file_placeholders(files)
        expected = os.path.join(HOME, ".kiro", "crew", "autonudge.json")
        assert placeholders.get(expected) == "{}"

    def test_an_unregistered_keystone_file_is_absent_from_the_map(self) -> None:
        from kiro_crew import sandbox

        files = sandbox._CC_FILES + sandbox._KEYSTONE_FILES
        placeholders = sandbox._sensitive_file_placeholders(files)
        unregistered = os.path.join(HOME, ".kiro", "crew", "security_policy.json")
        assert unregistered not in placeholders

    def test_a_custom_home_gets_the_same_protection(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        custom = tmp_path / "customcrew"
        custom.mkdir()
        monkeypatch.setenv("KIROCREW_HOME", str(custom))
        files = sandbox._CC_FILES + sandbox._KEYSTONE_FILES
        placeholders = sandbox._sensitive_file_placeholders(files)
        assert placeholders.get(os.path.join(str(custom), "autonudge.json")) == "{}"

    # The materialize-then-hide RUNTIME behavior (exclusive create, an existing
    # file left untouched, an unregistered file left absent) is covered against
    # the REAL, verbatim-extracted launcher source in
    # ``test_sandbox_mount_checked.py`` rather than a hand-copy here, so that
    # coverage cannot silently drift from what the shipped launcher executes.


class TestPwdAndOldpwdAliasesResolveAgainstTheTrackedCdBase:
    """GPT review: `$PWD`, `${PWD}`, `~+`, `$(pwd)` and `` `pwd` `` all name the
    directory a preceding `cd` moved to; `$OLDPWD`, `${OLDPWD}` and `~-` name
    the one before that. None of them is an ordinary variable this scanner's
    assignment tracking can resolve -- `$PWD` in particular is never assigned
    by the command TEXT at all, it is set by the shell itself on every `cd` --
    so `cd ~; mv "$PWD/.kiro/crew" /tmp/x` matched no branch even though the
    segment walk already recorded exactly where `cd ~` went (`base_dirs`).
    Every one of the five spellings resolves against that same tracked state
    now, so the container-rename check the plain `cd ~; mv ~/.kiro/crew ...`
    form already triggers fires for all of them too.
    """

    @pytest.mark.parametrize(
        "template",
        [
            'cd ~; mv "$PWD/.kiro/crew" /tmp/x',
            'cd ~; mv "${PWD}/.kiro/crew" /tmp/x',
            'cd ~; mv "~+/.kiro/crew" /tmp/x',
            'cd ~; mv "$(pwd)/.kiro/crew" /tmp/x',
            'cd ~; mv "`pwd`/.kiro/crew" /tmp/x',
        ],
    )
    def test_a_pwd_alias_after_cd_still_names_the_container(self, template: str) -> None:
        assert _blocked(template)

    @pytest.mark.parametrize(
        "template",
        [
            'cd ~; cd /tmp; mv "$OLDPWD/.kiro/crew" /tmp/x',
            'cd ~; cd /tmp; mv "${OLDPWD}/.kiro/crew" /tmp/x',
            'cd ~; cd /tmp; mv "~-/.kiro/crew" /tmp/x',
        ],
    )
    def test_an_oldpwd_alias_names_the_pre_cd_container(self, template: str) -> None:
        assert _blocked(template)

    def test_an_unrelated_pwd_reference_stays_allowed(self) -> None:
        """The property that must NOT regress: `$PWD` naming an ordinary,
        non-sensitive location is untouched, and a bare mention of `$PWD` in
        text unrelated to a path is not treated as a path at all."""
        assert not _blocked('cd /tmp; ls "$PWD/notes.txt"')
        assert not _blocked('echo "$PWD is unrelated text"')
        assert not _blocked('cd /tmp; mv "$PWD/other" /tmp/y')
        assert not _blocked('cd /tmp; mv "$(pwd)/other" /tmp/y')

    def test_pwd_without_a_preceding_cd_has_no_tracked_base_to_resolve_against(
        self,
    ) -> None:
        """No `cd` ran, so there is no tracked base for `$PWD` to mean -- the
        alias helper returns no readings and the ordinary (unresolved-literal)
        path stays in effect, same as before this fix existed."""
        assert not _blocked('mv "$PWD/.kiro/crew" /tmp/x')

    def test_pwd_substitution_checks_every_tracked_base_not_only_the_first(
        self,
    ) -> None:
        """GPT review, second pass: an operator-form `cd` target
        (`cd ${D:+$HOME}`) leaves MULTIPLE readings in `base_dirs` -- the
        naive "value" reading (`D`'s own value, here `x`) ahead of the
        home-hypothesis-resolved one (the real target, `$HOME`) two slots
        later. Using only `base_dirs[0]` for `$(pwd)`/`` `pwd` `` silently
        checked the WRONG tracked base and stayed allowed even though the
        walk had already recorded the right one."""
        assert _blocked('D=x; cd ${D:+$HOME}; mv "$(pwd)/.kiro/crew" /tmp/x')
        assert _blocked('D=x; cd ${D:+$HOME}; mv "`pwd`/.kiro/crew" /tmp/x')

    def test_pwd_substitution_still_stays_allowed_when_no_base_matches(
        self,
    ) -> None:
        """The property that must NOT regress: checking every tracked base
        must not turn `$(pwd)` into a match against every ancestor -- only a
        base that actually names the container triggers a block."""
        assert not _blocked('D=x; cd ${D:+$HOME}; mv "$(pwd)/unrelated" /tmp/y')


class TestAnOperatorFormAssignmentReconstructsTheContainer:
    """GPT review: `p=${HOME:0}; mv "$p/.kiro/crew" /tmp/x` names neither
    `$HOME` nor `.kiro` in a form any prior check resolved. `${HOME:0}` is
    bash's substring expansion (offset 0 -- the whole value, unchanged), an
    OPERATOR-form reference `normalize_shell_command`'s own `$HOME`/`~`
    expansion cannot touch (it only expands bare `$HOME`/`${HOME}`) and the
    segment walk's assignment tracking cannot resolve either (the assigned
    VALUE is the operator expression itself, not a literal path). Every
    `is_unreplaceable_container(cand)` call site checked only the literal
    candidate text, which still read `$p/.kiro/crew` or
    `${HOME:0}/.kiro/crew` -- neither of which equals the container.

    Fixed the same way an unresolved variable already gets a second look for
    CREDENTIAL paths (`_sensitive_under_unresolved_var`): a new
    `_unresolved_container_hypothesis` also tests whether the unresolved part
    could name a home directory, applied at all three
    `is_unreplaceable_container` call sites in `_check_sensitive_via_
    normalizer`. Deliberately its OWN helper, not a call straight to
    `_unresolved_home_hypothesis`: a bare `$PWD`/`$OLDPWD` with no tracked
    `cd` base is a DIFFERENT, already-decided case (see
    `TestPwdAndOldpwdAliasesResolveAgainstTheTrackedCdBase.
    test_pwd_without_a_preceding_cd_has_no_tracked_base_to_resolve_against`)
    that must keep reading as an ordinary unresolved literal rather than a
    home guess.
    """

    def test_the_reported_container_relocation_is_blocked(self) -> None:
        assert _blocked('p=${HOME:0}; mv "$p/.kiro/crew" /tmp/x')

    def test_the_symlink_replacement_half_is_also_blocked(self) -> None:
        assert _blocked('p=${HOME:0}; mv "$p/.kiro/crew" /tmp/x && ln -s /tmp/evil "$p/.kiro/crew"')

    def test_the_operator_form_reaches_the_container_check_unmasked(self) -> None:
        """No intervening assignment at all -- the operator form sits directly
        in the operand, exercising Pass A's flat token scan on its own."""
        assert _blocked('mv "${HOME:0}/.kiro/crew" /tmp/x')

    def test_the_same_shape_still_blocks_with_a_preceding_cd_in_the_command(
        self,
    ) -> None:
        """A `cd` earlier in the same command must not change the verdict --
        the segment walk's own `is_unreplaceable_container` call sites carry
        the identical hypothesis check, so this stays blocked whether or not
        the command also happens to change directory first."""
        assert _blocked('cd /tmp; p=${HOME:0}; mv "$p/.kiro/crew" /tmp/x')

    def test_a_bare_pwd_with_no_tracked_base_stays_allowed(self) -> None:
        """The property that must NOT regress: this fix must not resurrect
        the case `TestPwdAndOldpwdAliasesResolveAgainstTheTrackedCdBase`
        already pinned as allowed -- a bare `$PWD` with no preceding `cd` has
        no tracked base for the segment walk to mean, and `_pwd_alias_
        readings` already leaves it as an ordinary unresolved literal on
        purpose. Routing it through the generic home-hypothesis test too
        would silently override that carve-out."""
        assert not _blocked('mv "$PWD/.kiro/crew" /tmp/x')

    def test_a_pwd_with_a_tracked_base_still_gets_caught_by_its_own_mechanism(
        self,
    ) -> None:
        """Companion positive control: once a `cd` DOES establish a base,
        `$PWD` is still caught -- just by `_pwd_alias_readings`, the
        mechanism that already owns this case, not by the new hypothesis
        check this class is otherwise testing."""
        assert _blocked('cd ~; mv "$PWD/.kiro/crew" /tmp/x')

    def test_an_unrelated_operator_form_assignment_stays_allowed(self) -> None:
        """The property that must NOT regress: an ordinary operator-form
        reference to an unrelated variable, joined with an unrelated path,
        must not be treated as home-hypothesis-worthy just because it is
        unresolved -- the hypothesis must still require the REMAINDER to
        actually name the container."""
        assert not _blocked('p=${BUILD_DIR:0}; mv "$p/artifacts" /tmp/x')


class TestEvalWithAnEscapedDollarIndirectionFailsClosed:
    """GPT review: `H=HOME; eval "\\$$H/.kiro/crew"` spells neither `$HOME` nor
    `.kiro` anywhere in the command AS WRITTEN. Inside the double-quoted
    string, the escaped `\\$` survives the OUTER shell's own expansion as a
    literal `$`, while `$H` is expanded normally to `HOME` -- the OUTER shell
    hands `eval` the literal text `$HOME/.kiro/crew`, and `eval` runs THAT as
    a brand-new command. Every check in this scan reads the command AS
    WRITTEN, so none of them ever see the reconstructed text. Rather than try
    to compute what the indirection resolves to, `eval` combined ANYWHERE
    with this escape shape is refused outright -- the co-occurrence itself
    has no ordinary, benign use worth preserving.
    """

    def test_the_reported_container_relocation_is_blocked(self) -> None:
        assert _blocked(
            'H=HOME; eval "mv \\$$H/.kiro/crew /tmp/stash ' '&& ln -s /tmp/evil \\$$H/.kiro/crew"'
        )

    def test_the_same_trick_spelled_with_a_brace_is_also_blocked(self) -> None:
        """GPT review, second pass: `\\${$H}` is the identical idiom wrapped
        in braces -- `\\$` (escaped, survives as a literal `$`) + `{`
        (literal) + `$H` (expanded to `HOME`) + `}` (literal) assembles into
        the literal text `${HOME}`, which `eval` re-parses exactly like bare
        `$HOME`. The unbraced-only regex never matched the `{` sitting
        between the escaped dollar and the variable name."""
        assert _blocked(
            'H=HOME; eval "mv \\${$H}/.kiro/crew /tmp/stash '
            '&& ln -s /tmp/evil \\${$H}/.kiro/crew"'
        )

    def test_the_same_trick_against_credentials_is_also_blocked(self) -> None:
        assert _blocked('H=HOME; eval "cat \\$$H/.aws/credentials"')
        assert _blocked('H=HOME; eval "cat \\$$H/.ssh/id_rsa"')

    def test_an_ordinary_eval_with_no_indirection_stays_allowed(self) -> None:
        assert not _blocked('eval "echo hello"')
        assert not _blocked('eval "ls -la"')

    def test_the_indirection_shape_without_eval_anywhere_stays_allowed(self) -> None:
        assert not _blocked('echo "\\$$H is just text"')

    def test_eval_with_an_ordinary_direct_reference_stays_allowed(self) -> None:
        assert not _blocked('H=HOME; eval "echo $H"')
