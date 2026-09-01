"""Target inference: what a monitor instruction says it is about.

The refusal cases carry the weight here. Failing to infer costs today's plain
timer; inferring the WRONG pull request costs a loop that is silent about its own
subject and chatty about a stranger. So the ambiguity tests are the point of the
file, not an afterthought.
"""

from __future__ import annotations

import json

from kiro_crew.probes import GH_PR
from kiro_crew.probes.targets import infer


def test_a_pr_url_is_inferred():
    target = infer("Babysit https://github.com/kirodotdev/KiroCrew/pull/7491 to green.")
    assert target is not None
    assert target.kind == GH_PR
    assert target.subject == "kirodotdev/KiroCrew#7491"
    assert json.loads(target.message) == {
        "repo": "kirodotdev/KiroCrew",
        "pr": 7491,
        # Pinned because the URL CARRIED the host: without it the probe addresses
        # a bare slug and an ambient enterprise GH_HOST resolves it elsewhere.
        "host": "github.com",
    }


def test_an_unconvertible_pr_number_is_refused_not_raised():
    """Inference runs on the ARMING path, so it must never raise.

    ``\\d+`` is unbounded and CPython refuses to convert a decimal string past its
    digit limit, so a pathological run of digits has to decline the match. Raising
    here would fail to arm the loop at all rather than merely decline to gate it.
    """
    huge = "9" * 5000
    target = infer(f"watch acme/widgets#{huge} until green")
    assert target is None

    # A real subject beside the pathological one is still found.
    target = infer(f"ignore acme/widgets#{huge}, watch kirodotdev/KiroCrew#7491")
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7491"


def test_a_shorthand_subject_is_not_host_pinned():
    """A bare owner/name#123 names no host, so inference must not invent one.

    Pinning it would be worse than the drift it guards against: on a machine
    whose gh is configured for an enterprise server, the subject the user meant
    is never observed, and a same-numbered PUBLIC pull request being closed would
    retire the loop reporting SUCCESS while the real one stayed open. Omitted, it
    resolves through the operator's own gh configuration, which is where this
    codebase already puts that choice.
    """
    target = infer("watch kirodotdev/KiroCrew#7491 until it is green")
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7491"
    assert json.loads(target.message) == {"repo": "kirodotdev/KiroCrew", "pr": 7491}


def test_the_shorthand_a_babysit_instruction_carries_is_inferred():
    target = infer("BABYSIT kirodotdev/KiroCrew#7435 (fix/knowledge-sync) to green.")
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7435"


def test_the_url_and_shorthand_for_one_pr_are_one_subject():
    """Both spellings of the SAME pull request must not read as ambiguity."""
    target = infer(
        "Drive kirodotdev/KiroCrew#7491 -- "
        "https://github.com/kirodotdev/KiroCrew/pull/7491 -- to review-ready."
    )
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7491"


def test_two_distinct_pull_requests_refuse_rather_than_pick_one():
    """The real shape this protects against: a PR plus the PR it waits on.

    Picking the first mention would arm the watch on the blocker, which then
    reports the blocker's CI while the loop's own PR goes unwatched.
    """
    assert (
        infer(
            "PR kirodotdev/KiroCrew#4327 is gated on kirodotdev/KiroCrew#4137 "
            "merging first. Wait for it."
        )
        is None
    )


def test_two_repositories_refuse():
    assert infer("watch acme/widgets#1 and acme/gadgets#1") is None


def test_text_with_no_pull_request_returns_none():
    assert infer("Keep checking the deployment until the canary is healthy.") is None


def test_a_bare_issue_number_is_not_a_target():
    """``#7527`` alone names no repository, so it cannot be observed."""
    assert infer("gh-autofix issue #7527, keep an eye on it") is None


def test_an_enterprise_host_is_not_treated_as_github_com():
    assert infer("https://github.example.com/acme/widgets/pull/9") is None


def test_pr_zero_is_refused():
    assert infer("https://github.com/acme/widgets/pull/0") is None


def test_a_source_path_with_a_line_ref_is_not_a_target():
    """``src/kiro_crew/autonudge.py#1751`` names a code location, not a PR.

    Babysit instructions cite source locations constantly, and this shape reads
    as owner/repo#number to a naive pattern. Inferring it would arm the watch on
    a repository that does not exist, so the loop would go quiet about its own
    subject and every tick would burn a failed gh call.
    """
    assert infer("fix the guard at src/kiro_crew/autonudge.py#1751") is None
    assert infer("see website/src/pages/ChatPage.tsx#698") is None


def test_a_real_target_still_infers_when_a_path_ref_is_nearby():
    target = infer(
        "Babysit kirodotdev/KiroCrew#7491; the guard lives at " "src/kiro_crew/autonudge.py#1751."
    )
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7491"


def test_empty_and_non_string_input_return_none():
    assert infer("") is None
    assert infer(None) is None  # type: ignore[arg-type]


def test_a_real_babysit_instruction_infers_its_own_pr():
    """Verbatim shape of a live loop's armed message (trimmed)."""
    text = (
        "BABYSIT PR #7542 (kirodotdev/KiroCrew, branch refactor/delete-dead-fence-"
        "helpers, worktree /home/u/oss/kirocrew-fix-4919, Closes #4919, follow-up "
        "#7540).\n\nEXIT: when 0 red checks, PR Readiness passed and MERGEABLE -- "
        "post a final message whose first line is `GREEN: PR #7542 "
        "https://github.com/kirodotdev/KiroCrew/pull/7542`"
    )
    target = infer(text)
    assert target is not None
    assert target.subject == "kirodotdev/KiroCrew#7542"
