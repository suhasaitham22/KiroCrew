"""Tests for the alternate-traversal pass in ``security.py``.

``find`` is not the only program that factors a fenced path into a root plus a
name and hands the result to a reader. These tests pin the shapes ``fd``,
``grep -r``, ``rg`` and ``du`` can spell, the legitimate forms of each that must
keep working, and the residuals that are deliberately left open.
"""

from __future__ import annotations

import os

import pytest

from kiro_crew import security
from kiro_crew.security import is_sensitive_bash_command

#: A crew-home directory that HOLDS fenced leaves (``.env``,
#: ``token_signing.key``) without being fenced itself -- the root every blocked
#: case below traverses.
CREW = "~/.kiro/crew"

#: The legacy data-home prefix, fenced by the same leaf list.
CREW_LEGACY = "~/.kirocrew"


def _denied(command: str) -> bool:
    return is_sensitive_bash_command(command) is not None


# ── fd: a positional regex, a root, and find's -exec under another name ──


@pytest.mark.parametrize(
    "command",
    [
        # The issue's headline shapes.
        f"fd '^\\.env$' {CREW} -x cat",
        f"fd -e key . {CREW} -X cat",
        # The Debian/Ubuntu binary name for the same tool.
        f"fdfind '^\\.env$' {CREW} -x cat",
        # Long spellings of both exec forms.
        f"fd . {CREW} --exec cat",
        f"fd . {CREW} --exec-batch cat",
        # The reader does not have to be `cat`.
        f"fd . {CREW} -x base64",
        f"fd . {CREW} -x head -c 100",
        # A path-qualified program word.
        f"/usr/bin/fd . {CREW} -x cat",
        # A quoted root, which shlex unwraps.
        f"fd . '{CREW}' -x cat",
        # $HOME instead of a tilde.
        "fd . $HOME/.kiro/crew -x cat",
        # The legacy data-home carries the same leaves.
        f"fd . {CREW_LEGACY} -x cat",
        # The root arrives through a flag rather than as a positional.
        f"fd --search-path {CREW} '^\\.env$' -x cat",
        f"fd --search-path={CREW} nothing --exec-batch cat",
        # No exec flag, but the name list is piped into a reader.
        f"fd . {CREW} | xargs cat",
        f"fd . {CREW} | xargs -0 head -c 100",
        f"fd . {CREW} | parallel cat",
        # xargs flags that take a VALUE put it where the payload would sit, so
        # the payload cannot be found by stopping at the first non-flag token.
        f"fd . {CREW} | xargs -n 1 cat",
        f"fd . {CREW} | xargs -P 4 cat",
        f"fd . {CREW} | xargs -I {{}} cat {{}}",
        # An `env` wrapper hides the program word from a naive first-token read.
        f"env fd . {CREW} -x cat",
        f"env FOO=1 fd . {CREW} -x cat",
        f"env grep -r secret {CREW}",
        # `env`'s own options sit where the program word would, so they have to be
        # skipped as well -- otherwise `-i` is read as the program.
        f"env -i grep -r . {CREW}",
        f"env -i -u FOO grep -r . {CREW}",
        f"env -u FOO grep -r . {CREW}",
        f"env --unset=FOO grep -r . {CREW}",
        # `|&` is ONE operator; consuming only the bar left `&` as the next
        # stage's program and the reader after it was never looked at.
        f"rg --files {CREW} |& xargs cat",
        f"fd . {CREW} |& xargs cat",
        # The workspace root holds the Notes vault's PAT.
        f"grep -r secret {CREW}/workspace",
    ],
)
def test_fd_traversal_into_crew_home_is_denied(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # A listing is not a read: names are not the secret.
        f"fd . {CREW}",
        f"fd '^\\.env$' {CREW}",
        # `cat` on the PIPE prints the name list on stdin; it does not open the
        # files those names point to, so it is not a sink.
        f"fd . {CREW} | cat",
        f"fd . {CREW} | wc -l",
        # An ordinary project tree holds no fenced leaf.
        "fd '^main.py$' ./src -x cat",
        "fd -e py . src",
        "fd -e ts . website/src -x npx prettier --check",
        "fd . ~/Documents",
        "fd . ~/projects/app -x cat",
        # A crew subdirectory that holds no fenced leaf stays readable.
        f"fd . {CREW}/workspace/memory -x cat",
    ],
)
def test_fd_without_delivery_or_fence_is_allowed(command: str) -> None:
    assert not _denied(command), command


# ── grep -r / rg: the reader IS the traversal, so there is no sink to find ──


@pytest.mark.parametrize(
    "command",
    [
        f"grep -r secret {CREW}",
        f"grep -R secret {CREW}",
        # Clustered short flags -- the spelling a person actually types.
        f"grep -rn secret {CREW}",
        f"grep -rl secret {CREW}",
        f"grep -irn secret {CREW}",
        # Long spellings.
        f"grep --recursive secret {CREW}",
        f"grep --dereference-recursive secret {CREW}",
        # grep's aliases, including the one that is recursive with no flag.
        f"egrep -r secret {CREW}",
        f"fgrep -r secret {CREW}",
        f"rgrep secret {CREW}",
        # ripgrep recurses with no flag at all.
        f"rg secret {CREW}",
        # `-l` still opens every file to decide whether to print its name.
        f"rg -l secret {CREW}",
        f"rg --files-with-matches secret {CREW}",
        # `--files` is a pure lister, so it needs a sink -- and here it has one.
        f"rg --files {CREW} | xargs cat",
        f"rg --files {CREW} | parallel cat",
        # Reached through a sequencer rather than as the whole line.
        f"true && grep -r secret {CREW}",
        f"cd /tmp; grep -r secret {CREW}",
        f"grep -r secret {CREW_LEGACY}",
    ],
)
def test_recursive_read_rooted_above_fence_is_denied(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # Not recursive: a single named file is the normalizer pass's business,
        # and this one is not fenced.
        "grep -n secret ~/projects/notes.txt",
        "grep secret ./src/main.py",
        # Recursive, but rooted where no fenced leaf lives.
        "grep -r TODO ./src",
        "grep -r secret ~/projects/app",
        "grep -r secret /tmp/scratch",
        f"grep -r TODO {CREW}/workspace/memory",
        "rg secret ./website/src",
        # A pure lister with no sink discloses nothing.
        f"rg --files {CREW}",
        f"rg --files {CREW} | wc -l",
        "rg --files ./src | xargs cat",
        # The words appear as data, not as a program.
        "echo grep -r",
        f"echo 'grep -r secret {CREW}'",
    ],
)
def test_non_recursive_or_unfenced_reads_are_allowed(command: str) -> None:
    assert not _denied(command), command


# ── A root held in a variable the command itself assigns ──


@pytest.mark.parametrize(
    "command",
    [
        # Each stage is tokenized on its own, so without assignment tracking the
        # `$D` operand stayed literal and the fence was never consulted.
        'D=$HOME/.kiro/crew; rg . "$D"',
        'D=$HOME/.kiro/crew; grep -r secret "$D"',
        'D=$HOME/.kiro/crew; fd . "$D" -x cat',
        # `+=` appends, so a root assembled in two steps resolves too.
        'P=$HOME/.kiro; P+=/crew; rg . "$P"',
        # A declaration keyword assigns just as a bare `NAME=value` does, so the
        # scan has to look past it -- and past its options.
        'export D=$HOME/.kiro/crew; rg . "$D"',
        'readonly D=$HOME/.kiro/crew; rg . "$D"',
        'declare D=$HOME/.kiro/crew; rg . "$D"',
        'declare -x D=$HOME/.kiro/crew; rg . "$D"',
        'typeset D=$HOME/.kiro/crew; rg . "$D"',
        'local D=$HOME/.kiro/crew; grep -r x "$D"',
    ],
)
def test_variable_expanded_root_is_denied(command: str) -> None:
    assert _denied(command), command


def test_variable_expanded_root_outside_the_fence_is_allowed() -> None:
    assert not _denied('D=$HOME/projects; rg . "$D"')
    assert not _denied('export D=$HOME/projects; rg . "$D"')


# ── grep's other recursive switch: the directory ACTION ──


@pytest.mark.parametrize(
    "command",
    [
        f"grep -d recurse . {CREW}",
        f"grep --directories=recurse . {CREW}",
        f"grep --directories recurse . {CREW}",
        f"grep -drecurse . {CREW}",
        # The action flag ends a short-flag cluster, in both spellings.
        f"grep -nd recurse . {CREW}",
        f"grep -ndrecurse . {CREW}",
    ],
)
def test_directory_recurse_action_is_denied(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # `-d skip` and `-d read` are the non-recursive actions.
        f"grep -d skip . {CREW}",
        f"grep --directories=skip . {CREW}",
        "grep --directories skip . ./src",
        # Recursive, but rooted where no fenced leaf lives.
        "grep -n -d recurse pattern ./src",
    ],
)
def test_non_recursive_directory_action_is_allowed(command: str) -> None:
    assert not _denied(command), command


# ── A reader wrapped in a shell ──


@pytest.mark.parametrize(
    "command",
    [
        # The xargs payload is `sh`, and reading only the direct payload called
        # that clean while the `-c` string runs `cat`.
        f"rg --files {CREW} | xargs sh -c 'cat \"$@\"' sh",
        f"fd . {CREW} | xargs bash -c 'cat \"$@\"' bash",
        # The traversal itself inside a shell command string.
        f"sh -c 'grep -r secret {CREW}'",
        f"bash -c 'rg secret {CREW}'",
        # `env -S` carries a whole command the same way `sh -c` does.
        f"env -S 'grep -r secret {CREW}'",
        # `-c` takes a value, so it ends a short-option cluster: `-lc` is the
        # spelling a tool actually emits, and matching the whole token missed it.
        f"bash -lc 'rg . {CREW}'",
        f"sh -lc 'grep -r . {CREW}'",
        f"bash -c'rg . {CREW}'",
        f"rg --files {CREW} | xargs bash -lc 'cat \"$@\"' bash",
        f"rg --files {CREW} | xargs sh -c 'exec cat \"$@\"' sh",
    ],
)
def test_shell_wrapped_traversal_and_sink_are_denied(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # A word meaning "run the thing that follows" sits where the program word
        # would, so the traversal stage matched no rule at all.
        f"command grep -r . {CREW}",
        f"command rg . {CREW}",
        f"command fd . {CREW} -x cat",
        f"command du -a {CREW} | xargs cat",
        f"builtin grep -r . {CREW}",
        f"exec grep -r . {CREW}",
        # `exec -a NAME` takes a value, which would otherwise be read as the
        # program.
        f"exec -a x grep -r . {CREW}",
        # Peeling repeats, so a stacked spelling resolves too.
        f"command env -i grep -r . {CREW}",
    ],
)
def test_execution_wrappers_do_not_hide_the_traversal(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        "command grep -r TODO ./src",
        "exec grep -r TODO ./src",
        "bash -lc 'rg TODO ./src'",
        # `-c` means something else entirely on other programs.
        "head -c 100 ./src/main.py",
        "wc -c ./src/main.py",
    ],
)
def test_wrapped_forms_outside_the_fence_are_allowed(command: str) -> None:
    assert not _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        "sh -c 'grep -r TODO ./src'",
        "rg --files ./src | xargs sh -c 'cat \"$@\"' sh",
        # A shell payload that opens nothing is not a sink.
        f"fd . {CREW} | xargs sh -c 'rm \"$@\"' sh",
    ],
)
def test_shell_wrapped_forms_outside_the_fence_are_allowed(command: str) -> None:
    assert not _denied(command), command


# ── The search PATTERN is text to look for, not a place to look in ──


@pytest.mark.parametrize(
    "command",
    [
        # Searching source for a reference to the crew home is a legitimate read
        # of an ordinary tree; the pattern merely spells a fenced parent.
        'grep -r "$HOME/.kiro" ./src',
        f"grep -r {CREW} ./src",
        f"rg '{CREW}' src/",
        # Pattern only, so the root is the working directory.
        f"rg {CREW}",
    ],
)
def test_a_pattern_naming_a_fenced_parent_is_not_a_root(command: str) -> None:
    assert not _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # With the pattern supplied by a flag, every positional is a root again.
        f"grep -r -e secret {CREW}",
        f"rg -e secret {CREW}",
        # A root arriving through a root-supplying flag occupies the slot the
        # pattern would hold, so it must not be exempted with it.
        f"fd --search-path {CREW} '^\\.env$' -x cat",
        f"fd --search-path={CREW} nothing --exec-batch cat",
        # A short pattern flag takes a value, so it ends a cluster and the value
        # may be glued on. Matching whole tokens saw only `-e secret`, so these
        # spellings fired the exemption and dropped the credential-store root --
        # a false NEGATIVE, which is the direction that actually costs something.
        f"grep -r -esecret {CREW}",
        f"grep -refoo {CREW}",
        f"grep -r -fpatterns.txt {CREW}",
        f"rg -esecret {CREW}",
        # `rgrep` takes a pattern exactly as `grep` does, so it shares the rule --
        # and the root after that pattern is still tested.
        f"rgrep secret {CREW}",
    ],
)
def test_the_pattern_exemption_never_hides_a_root(command: str) -> None:
    assert _denied(command), command


def test_rgrep_shares_the_pattern_exemption() -> None:
    """`rgrep` is recursive with no flag, but its first positional is the pattern."""
    assert not _denied(f"rgrep '{CREW}' ./src")


# ── Wrappers that only change HOW the traversal runs ──


@pytest.mark.parametrize(
    "command",
    [
        # An argv-forwarding program runs the traversal that follows it, so
        # reading the first word as the program matched no rule at all.
        f"nice grep -r . {CREW}",
        f"nohup grep -r . {CREW}",
        f"setsid rg . {CREW}",
        f"ionice rg . {CREW}",
        f"stdbuf -o0 grep -r . {CREW}",
        f"sudo grep -r . {CREW}",
        f"doas grep -r . {CREW}",
        # A wrapper's own positional argument is not the program.
        f"timeout 5 rg . {CREW}",
        f"timeout 1.5m rg . {CREW}",
        f"taskset 0x3 rg . {CREW}",
        f"chrt 10 rg . {CREW}",
        f"nice -n 10 grep -r . {CREW}",
        # Stacked, and mixed with the shell wrappers.
        f"nohup nice rg . {CREW}",
        f"command nice grep -r . {CREW}",
        f"nice env -i grep -r . {CREW}",
        # The delivery rules still apply through a wrapper.
        f"nice fd . {CREW} -x cat",
        f"nice du -a {CREW} | xargs cat",
    ],
)
def test_argv_forwarding_wrappers_do_not_hide_the_traversal(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        "nice grep -r TODO ./src",
        "timeout 5 rg TODO ./src",
        "nohup nice rg TODO ./website/src",
    ],
)
def test_wrapped_traversals_outside_the_fence_are_allowed(command: str) -> None:
    assert not _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # `_program_basename` keeps a Windows suffix on purpose, so this pass has
        # to strip it or every Windows spelling matches no rule.
        f"grep.exe -r . {CREW}",
        f"rg.EXE . {CREW}",
        f"rg.cmd . {CREW}",
        f"fd.exe . {CREW} -x cat",
    ],
)
def test_windows_executable_suffix_is_stripped(command: str) -> None:
    assert _denied(command), command


def test_program_word_strips_only_a_windows_suffix() -> None:
    assert security._alt_program_word("grep.exe") == "grep"
    assert security._alt_program_word("/usr/bin/RG.EXE") == "rg"
    assert security._alt_program_word("rg.cmd") == "rg"
    # A dot that is not an executable suffix is part of the name.
    assert security._alt_program_word("python3.12") == "python3.12"


# ── `--` ends option parsing, so the word after it is the pattern ──


@pytest.mark.parametrize(
    "command",
    [
        # Requiring a non-dash token to be the pattern skipped `-foo` and exempted
        # the ROOT instead, so the recursive read of the crew home read clean.
        f"grep -r -- -foo {CREW}",
        f"rg -- -foo {CREW}",
        f"grep -r -- --foo {CREW}",
        # The ordinary spelling still works.
        f"grep -r -- foo {CREW}",
    ],
)
def test_a_dash_prefixed_pattern_after_end_of_flags_does_not_hide_the_root(
    command: str,
) -> None:
    assert _denied(command), command


# ── A flag-supplied pattern is text to search for, not a place to search ──


@pytest.mark.parametrize(
    "command",
    [
        # The value carries the pattern, so testing it as a root refused an
        # ordinary source search -- the same false positive the positional
        # exemption exists to prevent, reached through the flag spelling.
        'grep -r -e "$HOME/.kiro" ./src',
        'grep -re "$HOME/.kiro" ./src',
        "grep -r --regexp=$HOME/.kiro ./src",
        'grep -r --regexp "$HOME/.kiro" ./src',
        'rg -e "$HOME/.kiro" ./src',
        "grep -r -f $HOME/.kiro ./src",
    ],
)
def test_a_pattern_supplied_by_a_flag_is_not_a_root(command: str) -> None:
    assert not _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # Dropping the VALUE must not drop the root that follows it.
        f"grep -r -e secret {CREW}",
        f"grep -re secret {CREW}",
        f"grep -r --regexp=secret {CREW}",
        f"grep -r --regexp secret {CREW}",
        f"grep -r -f pats.txt {CREW}",
        f"rg -e secret {CREW}",
    ],
)
def test_dropping_the_pattern_value_keeps_the_root(command: str) -> None:
    assert _denied(command), command


def test_pattern_flag_value_removal_reads_both_spellings() -> None:
    strip = security._alt_without_pattern_flag_values
    assert strip(["-r", "-e", "PAT", "/root"]) == ["-r", "/root"]
    assert strip(["-re", "PAT", "/root"]) == ["/root"]
    assert strip(["-r", "--regexp=PAT", "/root"]) == ["-r", "/root"]
    # `--files` is a MODE with no value, so the next word stays a root.
    assert strip(["--files", "/root"]) == ["/root"]
    # `--` is an operand marker, not a pattern flag.
    assert strip(["-r", "--", "/root"]) == ["-r", "--", "/root"]


# ── The working directory is a fallback for a ROOTLESS traversal only ──


@pytest.mark.parametrize(
    "command",
    [
        # Consulting the cwd unconditionally refused every recursive read on a
        # gateway launched from the home directory, including one rooted at a
        # clean tree.
        "grep -r TODO ./src",
        "rg TODO ./website/src",
        "grep -r secret /tmp/scratch",
    ],
)
def test_an_explicit_clean_root_is_not_overridden_by_the_working_directory(
    command: str,
) -> None:
    assert not _denied(command), command


def test_explicit_root_detection_reads_path_shaped_operands() -> None:
    names = security._alt_names_an_explicit_root
    assert names(["./src"])
    assert names(["/tmp/scratch"])
    assert names(["~/projects"])
    # A reader payload and flags are not roots.
    assert not names(["-x", "cat"])
    assert not names(["-r"])


# ── du: a size lister used as a path producer ──


@pytest.mark.parametrize(
    "command",
    [
        f"du -a {CREW} | xargs cat",
        # An intervening stage does not hide the sink.
        f"du -a {CREW} | awk '{{print $2}}' | xargs cat",
    ],
)
def test_size_lister_with_reader_sink_is_denied(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"du -a {CREW}",
        f"du -sh {CREW}",
        "du -a ~/projects | xargs cat",
    ],
)
def test_size_lister_without_sink_or_fence_is_allowed(command: str) -> None:
    assert not _denied(command), command


# ── Residuals: named here so a later change cannot quietly assume coverage ──


@pytest.mark.parametrize(
    "command",
    [
        # `locate` has NO root operand -- the database supplies the path -- so the
        # root-containment clause every rule above rests on has nothing to test.
        # Recognising only the leaf names the fence DECLARES would still miss
        # `id_rsa` (`.ssh` is fenced as a whole directory, so no leaf name is
        # declared for it) while reading as covered, so it is left open and named
        # rather than half-closed.
        "locate id_rsa | xargs cat",
        "plocate id_rsa | xargs cat",
        # A name list delivered through a command substitution rather than xargs.
        f"cat $(fd '^\\.env$' {CREW})",
        # A traversal with NO root operand, after the same line moved into the
        # fenced directory. The root is the shell's working directory, which this
        # pass resolves against the gateway's rather than the shell's. The
        # explicit-root spelling of the same read IS denied, by the cd-taint pass.
        f"cd {CREW}; rg secret",
    ],
)
def test_documented_residuals_are_not_yet_covered(command: str) -> None:
    """Pins the residuals the module's block comment names.

    A failure here is GOOD news -- it means a later change closed the shape. Move
    the case up to the denied set and delete it from the block comment's residual
    list; do not relax the pass to keep this test passing.
    """
    assert not _denied(command), command


# ── Unit-level behaviour of the pass's own helpers ──


def test_reader_sink_requires_the_payload_to_be_a_reader() -> None:
    stages = security._alt_pipeline_stages("fd . x | xargs cat")
    assert security._alt_has_reader_sink(stages)
    stages = security._alt_pipeline_stages("fd . x | xargs rm")
    assert not security._alt_has_reader_sink(stages)


def test_reader_sink_survives_an_xargs_flag_that_takes_a_value() -> None:
    """`-n 1` puts its value where the payload would sit."""
    stages = security._alt_pipeline_stages("fd . x | xargs -n 1 cat")
    assert security._alt_has_reader_sink(stages)


def test_stage_head_skips_assignments_and_an_env_wrapper() -> None:
    program, operands = security._alt_stage_head(["env", "FOO=1", "fd", ".", "/tmp"])
    assert program == "fd"
    assert operands == [".", "/tmp"]
    program, operands = security._alt_stage_head(["FOO=1", "grep", "-r", "x"])
    assert program == "grep"
    assert operands == ["-r", "x"]


def test_bare_pipe_to_a_reader_is_not_a_sink() -> None:
    """`| cat` prints the NAME list, it does not open the named files."""
    stages = security._alt_pipeline_stages("fd . x | cat")
    assert not security._alt_has_reader_sink(stages)


@pytest.mark.parametrize(
    "command",
    [
        # A bare `&` backgrounds what precedes it and starts a new command.
        # `_split_shell_segments` breaks on `&&` but not on one `&`, so anything
        # placed before it made the stage read as that first program and the
        # traversal after it was never examined.
        f"echo start & grep -r secret {CREW}",
        f"true & rg secret {CREW}",
        f"echo start & fd . {CREW} -x cat",
        f"rg --files {CREW} & xargs cat",
        # Trailing `&` keeps the traversal in its own stage.
        f"grep -r secret {CREW} &",
        f"grep -r secret {CREW} & echo done",
    ],
)
def test_a_bare_ampersand_separates_stages(command: str) -> None:
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # An `&` belonging to a redirection is data, not a separator, so the stage
        # it sits in must stay intact.
        f"grep -r secret {CREW} 2>&1",
        f"rg secret {CREW} >&2",
    ],
)
def test_a_redirection_ampersand_does_not_split_the_stage(command: str) -> None:
    assert _denied(command), command


def test_redirect_ampersand_keeps_one_stage() -> None:
    stages = security._alt_pipeline_stages("grep -r x ./src 2>&1")
    programs = [security._alt_stage_head(s)[0] for s in stages]
    assert programs == ["grep"]


def test_bare_ampersand_yields_two_stages() -> None:
    stages = security._alt_pipeline_stages("echo start & grep -r x ./src")
    programs = [security._alt_stage_head(s)[0] for s in stages]
    assert "echo" in programs and "grep" in programs


def test_pipe_with_stderr_is_one_operator() -> None:
    """`|&` must not leave `&` as the next stage's program word."""
    stages = security._alt_pipeline_stages("rg --files x |& xargs cat")
    programs = [security._alt_stage_head(s)[0] for s in stages]
    assert "xargs" in programs
    assert "&" not in programs


def test_command_string_payloads_become_their_own_stages() -> None:
    stages = security._alt_pipeline_stages("sh -c 'grep -r x ./src'")
    programs = [security._alt_stage_head(s)[0] for s in stages]
    assert "sh" in programs and "grep" in programs


def test_nested_shell_recursion_is_depth_bounded() -> None:
    """A shell inside a shell resolves; an unbounded walk is not on offer."""
    nested = "sh -c 'sh -c 'sh -c ''cat x''''"
    assert security._alt_pipeline_stages(nested) is not None


def test_assignments_are_collected_across_stages() -> None:
    stages = security._alt_pipeline_stages("D=/a/b; P=/c; P+=/d; rg . $D")
    assignments = security._alt_assignments(stages)
    assert assignments["D"] == "/a/b"
    assert assignments["P"] == "/c/d"


def test_env_options_are_skipped_before_the_program_word() -> None:
    program, operands = security._alt_stage_head(["env", "-i", "grep", "-r", "."])
    assert program == "grep"
    assert operands == ["-r", "."]
    program, _rest = security._alt_stage_head(["env", "-u", "FOO", "grep", "-r"])
    assert program == "grep"


def test_execution_wrappers_are_peeled_before_the_program_word() -> None:
    for wrapper in ("command", "builtin", "exec"):
        program, operands = security._alt_stage_head([wrapper, "grep", "-r", "."])
        assert program == "grep", wrapper
        assert operands == ["-r", "."], wrapper
    # `exec -a NAME` takes a value.
    program, _rest = security._alt_stage_head(["exec", "-a", "x", "grep", "-r"])
    assert program == "grep"
    # Peeling repeats across stacked wrappers.
    program, _rest = security._alt_stage_head(["command", "env", "-i", "grep", "-r"])
    assert program == "grep"


def test_shell_c_payload_is_read_from_a_cluster() -> None:
    assert security._alt_command_string_payloads(["bash", "-lc", "cat x"]) == ["cat x"]
    assert security._alt_command_string_payloads(["sh", "-c", "cat x"]) == ["cat x"]
    assert security._alt_command_string_payloads(["bash", "-c cat x"]) == [" cat x"]
    # `-c` on a non-shell program is not a command string.
    assert security._alt_command_string_payloads(["head", "-c", "100"]) == []


def test_env_split_string_payload_is_read() -> None:
    assert security._alt_command_string_payloads(["env", "-S", "cat x"]) == ["cat x"]
    assert security._alt_command_string_payloads(["env", "--split-string=cat x"]) == ["cat x"]


def test_pattern_supplying_detection_reads_glued_and_clustered_flags() -> None:
    assert security._alt_pattern_is_flag_supplied(["-e", "secret"])
    assert security._alt_pattern_is_flag_supplied(["-esecret"])
    assert security._alt_pattern_is_flag_supplied(["-refoo"])
    assert security._alt_pattern_is_flag_supplied(["-fpatterns.txt"])
    assert security._alt_pattern_is_flag_supplied(["--regexp=secret"])
    # Uppercase only chooses a regex dialect; it supplies no pattern.
    assert not security._alt_pattern_is_flag_supplied(["-F", "-E", "secret"])
    assert not security._alt_pattern_is_flag_supplied(["-rn", "secret"])
    # Everything after `--` is an operand.
    assert not security._alt_pattern_is_flag_supplied(["--", "-e"])


def test_root_operands_exempt_the_pattern_but_not_a_root_flag_value() -> None:
    # Exactly one operand is dropped -- the pattern. Flags stay, because a flag's
    # value can itself be a root and testing a flag only ever answers "no".
    assert security._alt_root_operands("grep", ["-r", "PAT", "/root"]) == [
        "-r",
        "/root",
    ]
    # `du` names only roots, so nothing is exempted there.
    assert security._alt_root_operands("du", ["-a", "/root"]) == ["-a", "/root"]
    # A pattern-supplying flag means nothing is exempted.
    assert "/root" in security._alt_root_operands("grep", ["-r", "-e", "PAT", "/root"])
    # A root-supplying flag's value survives the exemption.
    assert "/root" in security._alt_root_operands(
        "fd", ["--search-path", "/root", "PAT", "-x", "cat"]
    )


def test_pipeline_split_respects_quoting() -> None:
    stages = security._alt_pipeline_stages("grep -r 'a|b' ./src")
    assert len(stages) == 1
    assert security._alt_stage_head(stages[0]) == ("grep", ["-r", "a|b", "./src"])


def test_grep_recursion_is_read_off_clustered_short_flags() -> None:
    assert security._grep_is_recursive(["-rn", "secret", "."])
    assert security._grep_is_recursive(["--recursive", "secret", "."])
    assert not security._grep_is_recursive(["-n", "secret", "."])
    # Everything after `--` is an operand, not a flag.
    assert not security._grep_is_recursive(["--", "-r", "."])


def test_root_check_accepts_a_flag_value_as_a_candidate_root() -> None:
    """A root can arrive as a flag's value, so every operand is tested.

    Tracking which flags take a value would need a table per tool, and each
    omission from such a table would be a MISS.
    """
    home = os.path.expanduser("~")
    assert security._alt_root_reaching_fence([f"--search-path={home}/.kiro/crew"], {})
    assert security._alt_root_reaching_fence([f"{home}/.kiro/crew"], {})
    assert not security._alt_root_reaching_fence(["--max-depth", "2", "secret"], {})


def test_root_check_resolves_a_root_held_in_an_assignment() -> None:
    home = os.path.expanduser("~")
    assignments = {"D": f"{home}/.kiro/crew"}
    assert security._alt_root_reaching_fence(["$D"], assignments)
    assert not security._alt_root_reaching_fence(["$D"], {"D": f"{home}/projects"})


def test_pass_is_reachable_from_the_public_gate() -> None:
    """The pass must be wired into ``is_sensitive_bash_command``, not just defined."""
    reason = is_sensitive_bash_command(f"grep -r secret {CREW}")
    assert reason is not None
    assert "recursive traversal" in reason


# ── Program identification: the traversal is found by NAME, not by position ──


@pytest.mark.parametrize(
    "command",
    [
        # `eval` takes the command as ordinary operands, so quoting the whole
        # thing left the stage holding one opaque word.
        f"eval 'rg --hidden . {CREW}'",
        f'eval "grep -r secret {CREW}"',
        f"eval grep -r secret {CREW}",
        # Stacked shells: one payload per level, deeper than a shell-in-a-shell.
        f'sh -c "sh -c \\"sh -c \\\\\\"rg . {CREW}\\\\\\"\\""',
        # A dispatcher that takes the real program as its first operand.
        f"busybox grep -r . {CREW}",
        f"busybox rg . {CREW}",
        # A wrapper whose own option takes a NON-numeric value, which sat exactly
        # where the program word does.
        f"stdbuf -o L grep -r . {CREW}",
        f"timeout -s KILL 5 rg . {CREW}",
        f"timeout --signal=KILL 5 rg . {CREW}",
        f"ionice -c 3 grep -r secret {CREW}",
    ],
)
def test_a_word_in_front_of_the_program_cannot_hide_it(command: str) -> None:
    """Whatever precedes the traversal, the traversal is still found.

    Enumerating what may sit in front of a program is unbounded -- a builtin, a
    wrapper, an applet dispatcher, a wrapper option's value -- so the program is
    matched by its own name wherever it appears in the stage.
    """
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f'R=rg; "$R" --hidden . {CREW}',
        f'G=grep; "$G" -r secret {CREW}',
        f'R=rg; "${{R}}" . {CREW}',
        f"export R=rg; $R . {CREW}",
        f'F=fd; "$F" . {CREW} -x cat',
    ],
)
def test_a_program_held_in_a_variable_is_resolved(command: str) -> None:
    """The program slot resolves through the command's own assignments.

    The same indirection the ROOT operands already resolve through, applied to the
    program word -- reading it literally saw ``$R`` and matched no rule.
    """
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # getopt_long accepts any unambiguous prefix, so each of these recurses.
        f"grep --recurs . {CREW}",
        f"grep --recursi . {CREW}",
        f"grep --rec . {CREW}",
        f"grep --der . {CREW}",
        f"grep --direct=recurse . {CREW}",
        f"grep --dir recurse . {CREW}",
        # fd's exec flags and its root-supplying flag abbreviate the same way.
        f"fd . {CREW} --exe cat",
        f"fd --sear {CREW} . -x cat",
    ],
)
def test_an_abbreviated_long_option_means_what_it_abbreviates(command: str) -> None:
    """A GNU long option matches by unique prefix, not as a whole token."""
    assert _denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        # A traversal program's NAME as ordinary text. Scanning every token for a
        # program name must not turn any of these into a traversal.
        "which rg",
        "which fd",
        "type du",
        "command -v rg",
        "man grep",
        "cat ~/bin/rg",
        "ls -la ~/.local/bin/fd",
        "sudo cp rg /usr/local/bin/",
        "chmod +x ./bin/rg",
        "cargo install ripgrep fd-find",
        "echo rg",
        # The search PATTERN happening to be a program name.
        "grep -r rg ./src",
        "rg du ./src",
        "grep -rn fd ./test",
    ],
)
def test_mentioning_a_traversal_program_is_not_running_one(command: str) -> None:
    """A name-scan reading needs an EXPLICIT root that reaches the fence.

    Without that, every command that merely names ``rg`` would be refused whenever
    the gateway happens to run from a directory holding the crew home -- the
    working-directory fallback belongs to the program POSITION alone.
    """
    assert not _denied(command), command


def test_long_flag_matching_accepts_a_prefix_but_not_an_ambiguous_one() -> None:
    candidates = frozenset({"--recursive", "--dereference-recursive"})
    assert security._alt_long_flag_matches("--recursive", candidates)
    assert security._alt_long_flag_matches("--recurs", candidates)
    assert security._alt_long_flag_matches("--rec", candidates)
    # Below the floor: `--r` stands for nothing.
    assert not security._alt_long_flag_matches("--re", candidates)
    assert not security._alt_long_flag_matches("--r", candidates)
    # A short flag is answered exactly -- clusters are read letter by letter.
    assert not security._alt_long_flag_matches("-r", candidates)
    # Longer than the candidate is not a prefix OF it.
    assert not security._alt_long_flag_matches("--recursively", candidates)
    assert not security._alt_long_flag_matches("--directories", candidates)


def test_program_word_resolves_through_an_assignment() -> None:
    assert security._alt_resolved_program_word("$R", {"R": "rg"}) == "rg"
    assert security._alt_resolved_program_word("${R}", {"R": "/usr/bin/rg"}) == "rg"
    # No assignment reaches a traversal name, so the literal reading is returned --
    # which is what `_program_basename` makes of the token, `$` and all.
    assert security._alt_resolved_program_word("$R", {"R": "cat"}) == "r"
    assert security._alt_resolved_program_word("cat", {}) == "cat"


def test_stage_readings_give_the_cwd_fallback_to_the_program_position_only() -> None:
    """The head reading may assume the working directory; a name-scan one may not."""
    head = security._alt_stage_readings(["nice", "rg", "secret"], {})
    assert ("rg", ["secret"], True) in head
    scanned = security._alt_stage_readings(["busybox", "rg", "secret"], {})
    assert ("rg", ["secret"], False) in scanned
    assert not any(program == "rg" and cwd for program, _ops, cwd in scanned)


def test_stage_collection_is_bounded_by_the_stage_budget() -> None:
    """Payload extraction branches, so depth alone does not bound the walk."""
    wide = " | ".join(["echo x"] * (security._ALT_MAX_STAGES + 200))
    assert len(security._alt_pipeline_stages(wide)) <= security._ALT_MAX_STAGES


def test_a_wrapper_hidden_traversal_with_no_root_is_a_documented_residual() -> None:
    """Pins the residual the block comment names, without needing a fenced cwd.

    The traversal IS found -- that is the point of the name scan -- but the reading
    is not in the program position, so it may not assume the working directory. A
    failure here means the fallback was widened; re-read why it is narrow before
    relaxing this.
    """
    readings = security._alt_stage_readings(["busybox", "rg", "secret"], {})
    rg_readings = [r for r in readings if r[0] == "rg"]
    assert rg_readings, "the traversal must still be found"
    assert not any(may_assume_cwd for _p, _o, may_assume_cwd in rg_readings)
