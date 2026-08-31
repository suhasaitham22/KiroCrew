# Security Deep Dive

The security **architecture**: what Kiro Crew defends against, where its trust
boundaries sit, and how the layers compose. Mechanism detail (exact rule tables,
regex shapes, per-function algorithms) lives in the module specs and is linked
from here rather than restated:

- [`../system-specs/modules/security.md`](../system-specs/modules/security.md)
  is the mechanism spec for every control below.
- [`../system-specs/modules/governance.md`](../system-specs/modules/governance.md)
  is the two-level Policy ∩ Profile model.
- [`../system-specs/modules/platform-context.md`](../system-specs/modules/platform-context.md)
  is the edition seam that lets a companion ADD (never remove) deny rules.
- [`resource-protection.md`](resource-protection.md) covers the DoS/resource
  ceilings (cgroup scope, RLIMIT, file descriptors).

Counts are deliberately absent from this document. Every posture count is
derived at runtime by `security_posture.py` and rendered in Settings → Security
from `GET /api/security/posture`; a number written into prose goes stale silently
while the code it describes keeps changing.

## Threat model

Kiro Crew runs an LLM agent with filesystem and shell access on the operator's own
machine. The dominant threat is **prompt injection from content the agent reads**
(web pages, repository files, Slack thread history, imported documents): text
that is data as far as the operator is concerned, but that the model may follow as
instructions. The two payloads that matter are credential exfiltration and
destructive local action.

Three properties shape every control:

1. **The model is untrusted input, not a trusted caller.** Anything the model
   chooses (a tool title, a file path, a command string) is attacker-controllable
   in the injection case. Controls therefore key on ground truth (the real
   `tool_input` command, the resolved filesystem path) and never on model-authored
   display text alone.
2. **The operator is trusted, the agent is not.** The operator may widen their
   own posture; the agent must not be able to widen it for them. That asymmetry is
   what the keystone (below) enforces.
3. **No single layer is assumed to hold.** A credential read has to defeat the OS
   sandbox, the path gate, the command gate, and output redaction; they fail in
   different ways and are not correlated.

The per-threat mitigation table (XPIA credential theft, WebSocket hijack, CSRF,
DNS rebinding, unauthenticated remote access, and the rest) is in
[`security.md` § Threat Model](../system-specs/modules/security.md).

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforced by |
|---|---|---|---|
| Gateway process ↔ agent subprocess | Kiro Crew gateway | `kiro-cli` + every tool/MCP descendant | OS sandbox (`sandbox.py`), env scrub, cgroup scope |
| Agent tool request ↔ execution | the PreToolUse gate's decision | the tool call as the model phrased it | `hooks.py:HookManager.on_tool_call` |
| Operator ceiling ↔ agent | keystone files under the data home | every agent read/write path | `security.is_sensitive_path` / `is_sensitive_write_path` |
| Agent output ↔ any human or external service | nothing | all agent-derived text | `redact_credentials` / `redact_exfiltration_urls` / `StreamRedactor` |
| Browser ↔ dashboard | authenticated session | any other origin or host | token auth, CSRF Origin check, Host allowlist |
| Slack workspace ↔ gateway | owner + allowlisted users | every other Slack sender | owner lock, `is_allowed_user`, Enterprise Grid check |

The single most important structural property: **the PreToolUse gate is
Kiro Crew's own gate, not the agent's.** Denied commands and the governance
ceiling are evaluated in `hooks.py` and are never written into a `kiro-cli` agent
JSON, so an agent config that omits or edits its own deny list cannot weaken the
ceiling.

## How the layers compose

```
Layer 5  Audit ........ SEL event log (HMAC-chained, verifiable)
Layer 4  Output ....... credential redaction + URL exfil scan + streaming redactor
Layer 3  Validation ... typed MCP tool schemas, unicode normalization, length caps
Layer 2  Command ...... denied-command rules + sensitive-bash + exfil shapes
Layer 1  Filesystem ... resolved-path gate (read block + wider write block)
Layer 0  OS sandbox ... namespace (Linux) / Seatbelt (macOS), opt-in

Across all layers: request auth (dashboard tokens, CSRF, Host allowlist),
                   Slack owner lock + workspace origin check,
                   governance ceiling (Policy ∩ Profile), SEL audit
```

Layers 1 through 4 are always on and are the reason Layer 0 can be optional.
Layers 1, 2 and the governance ceiling all evaluate at the same chokepoint
(`on_tool_call`), in a fixed order that matters: sensitive-path and deny checks
run **before** any auto-approve or trust fast-path, so a user trust decision or an
active YOLO grant can never route around a hard deny.

## Layer 0: OS-level sandbox (`sandbox.py`)

Confines the `kiro-cli` subprocess tree with platform-native isolation, hiding
credential directories by bind-mount (Linux user + mount namespaces) or file-read
denial (macOS Seatbelt), and scrubbing credential-bearing environment variables
on the way in. Windows has no Kiro Crew OS wrapper, so positively identified
official Kiro CLI spawns delegate to the CLI's built-in sandbox; their environment
is scrubbed by the parent before spawn. The parent gateway process is unaffected.

**`agent.sandbox` defaults to `"auto"`, engaging OS-level isolation
(namespace on Linux, sandbox-exec on macOS).** The only alternative value is
`"off"` (`config/loader.py`, `AgentConfig.sandbox`, `enum=["auto", "off"]`;
the same two-value enum gates the dashboard config editor in
`dashboard/handlers/core.py`). `"off"` skips Kiro Crew's own sandbox but still
delegates to `kiro-cli`'s internal agent sandbox on macOS when it is enabled,
which cannot nest inside Kiro Crew's
Seatbelt wrap (the macOS kernel returns EPERM even under an allow-all outer
profile), so exactly one layer can own isolation per spawn. Setting `"auto"`
re-enables Kiro Crew's own sandbox.

`wrap_argv`'s internal tier vocabulary is wider than the config enum: `standard`
(what `auto` resolves to), `cc`, `strict` and `off`. Those extra tiers are reached
by internal callers and by the governance `sandbox.min_level` ordinal floor
(`_ORDINAL_SCALES["sandbox"] = ("off", "standard", "cc", "strict")`), which clamps
a requested mode **up** before resolution, so an enterprise floor confines even a
`mode="off"` call. They are not values an operator writes into `agent.sandbox`.
Per-tier hidden paths, the empirical backend probes, the nested-passthrough rule
and the fail-closed/fail-open flags are specified in
[`security.md` § OS-Level Sandbox](../system-specs/modules/security.md).

Two properties are load-bearing at the architecture level:

- **Failure is refusal, not degradation.** With no sandbox backend available and
  a mode other than `off`, `wrap_argv` raises rather than spawning unconfined.
  Running unconfined is an explicit opt-in (`agent.sandbox_allow_unsandboxed_exec`);
  a separate flag (`agent.sandbox_allow_no_isolation`) only demotes the warning's
  log level and does not permit execution. The opt-in's default is
  **platform-independent** — a platform-derived default would grant unconfined
  execution on every backend-less host with no operator having declared it — so
  the discoverable path is instead a consent step in `kirocrew setup`, which
  prompts (default no) when `detect_backend()` reports `"none"` and writes the
  key only on an explicit yes.
- **Windows Kiro delegation is not a global fail-open.** `is_kiro_cli=True` from a
  reviewed official-Kiro spawn site delegates directly to Kiro's built-in sandbox
  before backend probing. A Kiro-looking filename is insufficient on Windows.
  Third-party ACP backends, scripts, hooks and other subprocesses still take the
  normal no-backend refusal and require the explicit opt-in above.
- **Delegation is audited, never silent.** When `kiro-cli`'s internal sandbox owns
  isolation for a spawn, the decision is config-driven (never a reaction to a wrap
  failure), logged once per process, and SEL-audited on an audit-or-deny basis: if
  the audit cannot be written, the delegation is refused. Kiro Crew's own Seatbelt
  takes the spawn on macOS; Windows returns to its no-backend fail-closed policy.

**Launcher shims are deliberately not bypassed on the delegated path.** On that
path the shim is part of `kiro-cli`'s own sandbox mechanism, so resolving past it
would defeat the delegated layer. Where an edition needs a managed launcher
replaced with the executable it ultimately invokes, that goes through the
`PlatformContext.agent_executable` resolver, whose result is always placed
*inside* the same namespace/Seatbelt wrapper. The capability probe never runs an
edition-resolved or user-writable target; it runs a fixed trusted system binary.

### Why the default is defensible

The sandbox is the only optional layer, so the credential-read threat has to be
covered without it. It is, three times over, at different altitudes:

- A tool read of `~/.aws` or `~/.ssh` is refused by the resolved-path gate
  (Layer 1), which follows symlinks before deciding.
- A shell read of the same paths is refused by `is_sensitive_bash_command`
  (Layer 2), which tokenizes and normalizes the command rather than pattern-
  matching raw text, so quoting and expansion tricks do not evade it.
- Anything that still reaches tool output is caught by redaction (Layer 4) before
  it reaches a human or an external service.

`SSH_AUTH_SOCK` is scrubbed whenever a Kiro Crew sandbox tier is active, so
ssh-agent forwarding is unavailable inside a confined spawn. Operators who depend
on passphrase-protected keys or hardware tokens use key files directly or leave
`agent.sandbox` at `off`.

## Layer 1: Filesystem gate (`security.py` + `hooks.py`)

`is_sensitive_path()` is the shared read+write block, and
`is_sensitive_write_path()` is its strict superset: it adds paths that stay
readable but must not be modified by an agent tool (the data home's `config.json`
/ `config.local.json`, which carry resource ceilings, and the data-home migration
marker, whose mere presence is a trust signal). Path matching checks the fully
symlink-resolved target as well as the lexically normalized and raw forms, so a
workspace symlink into a blocked directory is refused through the link.

`hooks.safe_read_file()` is the guarded read used by Kiro Crew's own non-tool file
access: it re-checks the resolved target and then opens the canonical path with
`O_NOFOLLOW`, which closes the TOCTOU window where the final component is swapped
for a symlink after the check.

### The keystone: the agent cannot read or rewrite its own ceiling

The governance trust root (`security_policy.json`, `profiles/`,
`admission_policy.json`), the denied-command opt-out state
(`denied_commands.json`), the SEL HMAC key and event log, the dashboard token
signing key, and the channel credential `.env` all sit on the read+write block.
This is a single mechanism with an outsized consequence: it is what makes the
enterprise ceiling **un-disableable from inside the agent**. An agent that could
read these could forge tokens or impersonate internal callers; one that could
write them could set `disable_all: true` and neuter the deny gate after a
restart. Every legitimate reader and writer opens these paths directly rather
than through the shared gate, so real functionality is unaffected.

Each leaf is registered under every known data-home prefix, so a not-yet-migrated
legacy home is fenced identically to the current `~/.kiro/crew`.

#### The container the leaves sit in

Every leaf above is identified by its **path**, which silently assumes the directory
holding it stays where it is. It did not. `rm -rf ~/.kiro/crew` was already refused,
but relocation was not, so

```
mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew
```

left every fence naming a file that is no longer there, and the next write to
`security_policy.json`, `profiles/`, `admission_policy.json` or `computer_use.json`
followed the link. A bypass of the ceiling itself, not of one feature.

`is_unreplaceable_container` closes it. Two properties are load-bearing:

- **Exact, not prefix.** The leaf matcher is prefix-based, so adding the data home to
  `_SENSITIVE_HOME_DIRS` would fence `sessions/`, `memory/`, `skills/` and `logs/`
  and cut the agent off from its own working data. Only the container itself is
  refused; everything under it stays as reachable as it is today.
- **Verb-independent, with no exemptions at all** — an enumerated write-verb
  allowlist is bypassable (`mv`, `ln`, `cp`, `rsync`, a novel verb, a Python
  `os.rename`), so the refusal is on *naming* the container.

  There was briefly a `cd`/`pushd` carve-out, on the reasoning that entering a
  directory cannot relocate it. It is gone. Identifying the operand meant inspecting
  the preceding token, so `mv cd ~/.kiro/crew` claimed the exemption by containing the
  word `cd`; and `cd` is a builtin that a function or alias can shadow, so even a
  correct parse would not have been evidence. Deciding what a token *means* in a shell
  needs a shell. The cost of removing it is bounded by the match being exact — only
  `~/.kiro/crew` itself, never anything beneath it.

**Shell expansion is normalized before either gate matches.** Bash expands an operand
before the command runs and the matcher did not, so `~/.kiro/cr{e..e}w` arrived as a
literal matching no protected path and reached bash as `~/.kiro/crew`. This was never
specific to the container gate — the **leaf** gate had the identical hole, so
`cat ~/.kiro/cr{e..e}w/security_policy.json` read the trust root. Brace expansion
therefore lands in the shared candidate generator, where both gates inherit it, and a
glob carrying `*`/`?`/`[…]` is refused when it *could* name a protected path, since a
gate cannot resolve one without the filesystem.

The expander models bash, and four divergences from it were each a bypass: a
**descending** range (`{w..e}`) produced an empty span where bash produces `crew`; an
**oversized** brace was truncated, dropping the tail so a 65-item list with `crew` last
expanded to `crew` in bash and to everything-but-`crew` here (it now fails closed); a
**shadowed** `cd` (`cd(){ mv "$1" /tmp; }`) inherited the navigation carve-out, so
defining or aliasing one of those verbs now withdraws it; and a **custom
`KIROCREW_HOME`** was invisible to the raw scan, which is the only layer that sees an
interpreter payload — the configured root is now its own branch, and the compiled
pattern is cached per value rather than pinned at first call.

None of that makes the matcher a shell parser, and it is not meant to: the floor under
it is the sandbox hide list above, which a shadowed builtin or a runtime-assembled
payload cannot reach past.

Brace ranges take bash's optional step (`{a..z..2}`); without it the whole range
matched nothing and the token read as clean. And `*` does not match a leading dot
**unless the command enables it** (`shopt -s dotglob`, `setopt globdots`), under which
`~/*` names `~/.kiro` — detected in the command text, which is the scope a per-command
matcher has. An option set in a startup file is outside it, which is one more reason
the hide list above is the floor and this is not.

Glob matching is **component-wise**, not `fnmatch` over the whole path: `fnmatch`'s `*`
crosses `/`, which denied a bare `ls *`, and it ignores the dotfile rule, which matched
`~/*` against `~/.kiro`. Bash's rules are what keep an ordinary home listing out of the
gate while `ls ~/.kiro/*`, which names the container, stays refused. Expansion is
bounded — past the cap the token is left unexpanded and the metacharacter arm still
refuses it.

It runs in all three passes — raw regex, normalizer, and the `cd`-resolved segment
walk — because the gate beside it does. Wired into only one, it missed the
`cd`-relative, variable, and interpreter-payload forms the leaf gate had caught for
a long time; `TestItIsNoWeakerThanTheLeafGateBesideIt` asserts that parity
form-by-form so the two cannot drift apart again.

#### A subprocess is not constrained by a command gate

The command gate reads command **text**. `./script.sh`, `make install` and `npm run
build` are each one opaque token to it, and whatever they write internally is never
inspected — so the path fence refuses
`echo x > ~/.kiro/crew/security_policy.json` and says nothing about a script
containing that exact line. The fence was never the layer that stopped a subprocess.

The sandbox's hide lists are, on **every** mode:

| what | where | which modes |
|---|---|---|
| `profiles/` | `_STRICT_DIRS`, `_STANDARD_DIRS`, `_CC_DIRS` | **every** mode |
| `security_policy.json`, `admission_policy.json`, `computer_use.json`, `crons.json`, `autonudge.json`, `denied_commands.json` | `_KEYSTONE_FILES` | **every** mode |
| `.npmrc`, `.netrc`, `.git-credentials`, `.env` | `_CC_FILES` | `cc` and `strict` only |

**`variables/` was in this table for several rounds and was removed
(First Principles review).** The store it names has no creator and no
reader anywhere in this tree — `#4371`, still unmerged, is what adds it.
Hiding a directory nothing writes to protects nothing; it is dead
defensive code carried ahead of the feature it defends, and grepping
`crew/variables`/`kirocrew/variables` across `src/kiro_crew` turned up
only this PR's own now-removed hide-list lines. `#4371` ships the entry
together with the store, the same commit that makes it load-bearing.

`denied_commands.json` (`disable_all` / `disabled_ids` / `user_added`, read by
`hooks.read_denied_commands_config`) joined this list rather than shipping
unhidden: it is the SAME class of control as the three trust-root files above it —
the command gate refuses a tool call NAMING it, which is the tool-mediated half,
and a subprocess never goes through that gate. An approved opaque script writing
`"disable_all": true` would have defeated every deny rule after the next reload,
the identical bypass this list already exists to close for the other three.

The keystone files live in a list of their own precisely so that last row cannot pull
them along. An earlier revision put them in `_CC_FILES`, and this document argued the
result was an acceptable incomplete floor on the grounds that `standard` "has no
file-level hiding mechanism at all". **That was wrong.** The mechanism is there — the
launcher hides whatever `files` contains on any tier — and the only thing excluding the
default tier was the selection expression choosing an empty list for it
(`files = _CC_FILES if sandbox_level in ("cc", "strict") else []`). Since
`_SANDBOX_MODE_ALIASES` maps the default `auto` onto `standard`, the effect was that
the governance ceiling was readable to an agent subprocess in the shipped
configuration, while this document described that as a considered trade.

It is worth naming the failure mode, because it is the one this whole section warns
about: the gap was **documented**, and a test pinned the documented behaviour, so both
halves of the usual safety net agreed with each other and neither noticed the floor had
a hole in it. Writing a limitation down is not the same as deciding it.

The credential files keep the `cc`/`strict` split, which is the posture this repo
already chose for them; widening that is a separate decision with its own reasoning.

Hiding rather than merely denying is safe because nothing in the subprocess needs to
read any of the keystone files: variable expansion happens in the gateway before the
prompt is built, and the ceiling is deliberately not the agent's to read.

The two platforms enforce this through different mechanisms and had to be fixed in
different places — Linux bind-mounts an empty file over each path, macOS emits Seatbelt
rules — so coverage on one says nothing about the other. On macOS the keystone files are
denied `file-read*`, `file-link` **and `file-write*`**: hiding the ceiling from a
subprocess is worth little if the same subprocess can overwrite it, and forging
`computer_use.json` is how an agent would grant itself the operator's own opt-in. The
credential files keep read-only denial, because npm and git write to `.npmrc` and
`.git-credentials` legitimately.

**One gap remains, and it is a property of the file-hiding mechanism rather than of
this list.** Linux bind-mounts over a path only `if os.path.isfile(target)`, so a
keystone file that does not exist yet is not covered and an approved opaque script can
CREATE it. This applies to every file entry, not only these — `.npmrc` and `.env` have
always behaved this way. The obvious fix, creating a placeholder so the mount has
somewhere to land, is not obviously safe: it leaves an empty file in the operator's data
home, and while an empty `computer_use.json` reads as disabled
(`enable_state.py` treats a failed load as off — the safe direction), an empty
`security_policy.json` would need the same check made for each loader before anyone
could rely on it. Doing that per loader, or inverting the data home to a read-only mount
with the writable subtrees bound back in, is the real fix and belongs in its own change.

This is recorded as an open gap, not as a decision — the distinction the previous
paragraph exists to make.

### The container entry, not just its contents

Every list above hides CONTENTS. None of them stops the container being **moved**, and
content-hiding cannot: after `mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil
~/.kiro/crew`, each leaf rule names a path the attacker has already emptied, and the
next gateway write follows the link. `security.is_unreplaceable_container` refuses that
as a *command*, but a subprocess is one opaque token to the command gate — `./script.sh`
containing those two lines is never inspected — which is the same reason the hide lists
exist at all.

So the sandbox protects the directory ENTRY, by a different mechanism on each platform:

| platform | mechanism | why it works |
|---|---|---|
| Linux | bind the container onto itself | a bind over itself is transparent, but the directory becomes a mount point, and the kernel refuses to rename one (`EBUSY`) |
| macOS | `(deny file-write* (literal …))` | Seatbelt's `file-write*` covers the unlink/create a rename needs |

`literal`, never `subpath`, and a self-bind rather than an empty-dir bind: the agent's
own `sessions/`, `memory/` and `logs/` live inside this directory and must stay readable
and writable. Fencing the subtree would cut the agent off from its own working data —
the same false positive the container gate is exact-match to avoid.

The two halves live in different modules with no shared symbol — `security.py` names
the fenced leaves, `sandbox.py` names what is hidden — so a leaf added to one and not
the other is protected only against the spelling nobody uses.
`TestTheFencedPathsAreHiddenFromSubprocesses` asserts the coupling rather than either
list.

**Do not weaken this when editing the path or bash matchers.** Write and extract
verbs must stay covered: a bash command that merely *names* a write-protected
leaf is refused, verb-independently, because an enumerated write-verb allowlist is
inherently bypassable (quoted redirects, `cp`, a Python `open(..., 'w')`, or any
novel verb).

### Ancestors, and what a self-bind cannot protect

The container's ANCESTORS are protected the same way, not just the container itself:
`mv ~/.kiro /tmp/stash && ln -s /tmp/evil ~/.kiro` carries `~/.kiro/crew` away without
ever naming it. For a nested custom `KIROCREW_HOME` this walks every ancestor, not a
fixed depth — a fixed depth only moves the goalpost, since renaming ANY ancestor and
replacing it with a symlink completes the same relocation attack regardless of nesting
depth. The walk stops at whichever comes first: the filesystem root (protects nothing
in particular) or `Path.home()` (excluded on its own account, matching
`_SENSITIVE_LEAF_PARENT_DIRS`'s existing rule that a single-segment entry whose parent
is home is excluded so as not to taint `cd ~`). This is safe to be broad about because
the mechanism denies RENAMING the literal directory entry only — every file inside
every ancestor, at every level, stays fully readable and writable, and only the
sandboxed agent subprocess is bound by it.

The command gate (`security.py`) carries its own copy of this walk, independent of the
sandbox's. It matters when the sandbox is disabled, or on a platform it does not cover:
the text gate is then the *only* defense, and a fixed-depth version of it would leave
the same class of gap the sandbox side closed.

**Ancestors must be self-bound SHALLOWEST first, not in whatever order the walk
produces them.** `MS_BIND` without `MS_REC` copies only the mount at that point, not
the submounts beneath it — the same reasoning behind self-bind-before-masking earlier
in this section. Binding a deep directory and then binding one of ITS ancestors a
moment later produces a fresh view of the ancestor that does not carry the deeper bind
forward, silently undoing it. The ancestor walk collects entries deepest-first (it
starts at the immediate parent and moves outward) and reverses them before returning,
so the self-bind loop — which consumes this list in order — always establishes an
ancestor's mount before any descendant's.

**A symlinked container defeats the Linux self-bind, and there is no bind-based fix.**
`os.path.isdir()` follows a symlink, so the self-bind loop would happily bind through
one. `mount(2)` resolves the symlink target the same way `open()` does, landing the
bind on the directory the link points to — not on the link's own directory-entry slot,
which stays exactly as replaceable as before: `rm ~/.kiro/crew && ln -s /evil
~/.kiro/crew` swaps the link out from under a mount still faithfully protecting the OLD
target. Protecting the link's own slot would mean write-denying the *parent's*
contents, which is the subtree-fencing this whole mechanism deliberately does not do.
So the Linux launcher detects a symlinked container with `os.path.islink()` *before*
the bind and refuses the spawn, matching every other control in this file: a control
that cannot be established blocks rather than degrades open.

macOS does not share this gap. Verified empirically against real `sandbox-exec`: a
literal `(deny file-write* (literal …))` rule on a symlink's own path blocks `rm` /
`ln -s` replacing it, because Seatbelt's literal-path match denies operations *at that
pathname* rather than following the link the way a bind-mount target does. No fix is
needed there, and none should be added — the two platforms differ here for a real
reason, not an oversight.

**A symlinked custom home is a second, distinct case of the same gap.** `config_dir()`
resolves any symlink in `KIROCREW_HOME` before returning, so the self-bind protection
above landed on the RESOLVED target. But `config_dir()` is consulted once per process,
not once per read of the env var — a restart re-reads the raw `KIROCREW_HOME` and
re-resolves it fresh, so if the *configured* path is itself a symlink, protecting only
the old resolved target never covers a replacement made in the meantime:
`rm <symlinked KIROCREW_HOME> && ln -s /evil <same path>` swaps what the *next*
resolution follows, and nothing named the symlink's own path to protect it. The
unresolved, expanded (but not `.resolve()`-d) override is now added to the same
protected list in its own right — appended *after* the resolved leaf and its
ancestors, matching the shallowest-first ordering invariant, since in the common
non-symlink case this entry equals the resolved leaf exactly and dedup collapses it.
If it turns out to be a symlink, the same `os.path.islink()` check above catches it
and refuses the spawn.

**The ancestor walk also stops at the system temp root, and getting that stop
condition wrong is its own regression class.** This project's own test suite pins
`KIROCREW_HOME` under the system temp directory for isolation (see
[testing-conventions](../system-specs/common/testing-conventions.md)), so an
ancestor walk with no temp exclusion reaches the bare temp root itself and starts
treating it as a protected container — refusing every ordinary command that merely
*names* it, `cd /tmp && cat notes.txt` included. This was invisible in a bare local
run (nothing sets `KIROCREW_HOME` there) and visible only in CI, where the pinned
home is nested under `/tmp`.

The fix is not "stop at the first ancestor that happens to be *under* the temp
root" — that overshoots. `_is_system_tmp_root()` (`config/paths.py`) has to answer
true only exactly *at* the boundary — under-or-equal a temp root (`tempfile.
gettempdir()` or, on POSIX, literal `/tmp`, both resolved) while its *parent* is
not — because an intermediate ancestor between the leaf and the temp root is a
uniquely-identifying directory the walk must still protect, not shared territory
like the root itself. Stopping at the first under-match instead un-protects every
intermediate ancestor, silently reopening the exact gap this walk exists to close.

`tempfile.gettempdir()` itself can raise (`OSError`, when it exhausts its candidate
list without finding a writable directory) — rare, but `_under_system_tmp` is now
reached from the per-command ancestor walk, not only its original gateway-start
callers, so an uncaught raise there would crash whatever is deciding whether to
allow a command rather than return a decision. The call is wrapped and falls back
to skipping that root (still trying the POSIX `/tmp` literal, or an empty root list
on Windows) — discovery failure fails toward "not a recognized temp root", the same
direction `_under_system_tmp`'s existing per-candidate `.resolve()` failures already
fail.

**The stop is asymmetric between the two copies of the walk, on review feedback.**
`security.py`'s text gate is verb-independent matching, so reaching the temp root
there refuses every command merely *naming* it — it has to stop early, as above.
`sandbox.py`'s `_unrenamable_containers` self-bind costs nothing comparable: it
denies *renaming* one literal directory entry, nothing else, so there is no
usability reason to give a user- or environment-selected `$TMPDIR` a pass there.
Leaving it out was an unforced gap — a `KIROCREW_HOME` nested under a writable
custom temp root had that boundary's own directory entry left unprotected, the same
exposure as any other unwalked ancestor — so only `security.py` calls
`_is_system_tmp_root`; the sandbox walk stops at `Path.home()` and the filesystem
root only, same as before the temp-root case existed.

**The raw regex was not the only matcher checking against a custom home's
ancestors, and the other two were never told about them.** `security.py` carries
three independent operand checks beyond the raw regex — a substitution scanner
(`_substitution_could_name_container`, for `~/.k$(printf i)ro/crew`-shaped
obfuscation), a glob scanner (`_raw_glob_could_name_container`, for
`~/@(.kiro)/crew`), and the cd-relative segment walk's exact-match check
(`is_unreplaceable_container`) — and each built its own target set from
`_UNREPLACEABLE_CONTAINER_DIRS` alone. The ancestor walk was added only to the raw
regex's own branches, so `mv ~/comp$(echo any)/dept /tmp/x` and, with extglob
enabled, `mv ~/comp@(any)/dept /tmp/x` both named a real ancestor exactly as their
literal form does, yet reached none of the other three checks — a real, reproduced
bypass. `_container_target_groups()` now builds the shared target sets once (the
anchored `_UNREPLACEABLE_CONTAINER_DIRS` entries plus every ancestor from
`_custom_home_ancestors()`, the same walk `_build_container_regex` itself now
calls) and all four consumers read from it — `_container_targets()` returns the
two combined, for `is_unreplaceable_container`'s exact-match check — so an
ancestor added to the walk cannot silently go missing from three of its four
checkers again.

Closing the glob-scanner gap surfaced an adjacent, narrower bug in extglob
widening. `_glob_could_name` widens an extglob group (`@(.kiro)`, `!(x)`) to `.*`
so the result can still name a dotfile target — deliberate, since bash's
`*`-without-`dotglob` rule would otherwise make the widened form miss the very
`.kiro`-shaped targets an extglob group is most useful for hiding. But `.*` is a
GLOB pattern, where `.` is a literal character, not "any character" — so it widens
correctly only when the group sits at the very start of a component
(`@(.kiro)` → `.kiro`-shaped, a literal dot the dotfile-prefixed target also has).
Embedded mid-component (`comp@(any)` → `comp.*`), the literal dot has to appear
literally in the target too, and an ordinary, non-dot-prefixed ancestor name like
`company` has none — so the widened pattern never matched it, even though the
extglob group is meant to name "anything here". `_UNREPLACEABLE_CONTAINER_DIRS`
entries are all dot-prefixed (`.kiro`, `.kiro/crew`, `.kirocrew`), so this never
surfaced before a custom home's plain-named ancestors joined the target set.
Fixed by building a second, plainly-widened reading (`*` in place of the group)
alongside the dot-preserving one and checking both — the two overlap on plenty of
tokens, which only widens the match, never narrows either reading.

**Feeding ancestors into the glob and substitution scanners introduced its own
false-positive class, caught by CI rather than by review.** `ls -la /tmp/*` — an
ordinary, harmless command this project's own CI matrix runs constantly — started
reading as naming a `KIROCREW_HOME` ancestor that happened to sit directly under
`/tmp`. A bare `*` legitimately matches ANY non-dot path component in bash glob
semantics, and once ancestor names (plain, installation-specific strings like a
pytest tempdir's own name) joined the target set, a bare wildcard component
matched one of them by construction — there was no way for it not to. The fixed
container dirs never had this problem: `.kiro`/`.kiro/crew`/`.kirocrew` are all
dot-prefixed, and bash's dotfile rule already keeps a bare `*` (without
`dotglob`) from matching them at all — the false-positive risk was latent in the
matcher the whole time, just never triggered because every existing target
happened to carry protection the bare-wildcard case doesn't.

The fix distinguishes the two target kinds by risk rather than merging them:
`_container_target_groups()` returns `(fixed, ancestor)` separately, and a match
against an ancestor additionally requires the operand's own LEAF component to
retain at least one literal character (`_pattern_component_has_literal_anchor`,
threaded through as `_glob_could_name`'s `require_leaf_literal`) — `/opt/comp*`
still matches an ancestor named `company` (the leaf "comp*" carries "comp"), but
bare `/tmp/*` does not (the leaf "*" carries nothing). The fixed targets keep
their existing, more permissive matching unchanged, including the extglob
dotfile-widening case above, which legitimately relies on a fully-widened `.*`
leaf matching without any literal anchor of its own.

**The leaf-anchor leniency above was UNCONDITIONAL, and did not distinguish a
read from a write (GPT review).** `require_leaf_literal`'s exemption exists so
`ls -la /opt/*` stays allowed when an ancestor happens to sit under `/opt` — but
the same exemption, applied with no regard for the containing command's VERB,
also let `mv /opt/* /tmp/x` and `ln -s /evil /opt/*` through: a bare-wildcard
leaf against an ancestor's shape was simply never counted as a match, REGARDLESS
of whether the command could only read what it names (safe) or could relocate or
replace it (not safe). `ls -la /opt/*` merely lists whatever the wildcard
expands to; `mv /opt/* /tmp/x` relocates it, `/opt/company` included.

Fixed by scoping the exemption to `bare_trust_root_read` — set only when the
caller has independently confirmed the containing command is a bare, program-
allowlisted READ. That reuses `_is_bare_trust_root_read`'s existing allowlist
(`ls`, `stat`, `du`, `readlink`, `basename`, `dirname`, `wc`), but its own
inertness gate (`_SHELL_INERT_COMMAND_RE`) rejects any command containing `*`,
`?` or `[` outright — by design, for the exact-match check it was written to
serve — so it could not itself distinguish the two cases either; gating on it
directly would have reopened the exact `ls -la /tmp/*` false positive above.
`_is_bare_trust_root_read` gained an `allow_glob` parameter that widens ONLY the
inertness charset to also tolerate `*?[]`, without touching shell-composition
characters (`;`, `&&`, `|`, backtick, `$(`) that genuinely could chain an
additional command — a wildcard alone introduces no such risk, so tolerating it
here does not weaken the "no shell metacharacter" guarantee that gate exists to
give.

When the leaf lacks an anchor and the command is not a proven-safe read, the
match now fails CLOSED instead of being silently skipped — but only once the
token's PREFIX has already been confirmed to align with a specific target's
shape (checked inside the per-target loop, not before it): an unrelated command
like `mv /home/user/downloads/* /archive/` never reaches this decision at all,
since its wildcard does not structurally match any configured ancestor to begin
with. Checking the prefix-target alignment FIRST is what keeps this narrow —
the alternative, failing closed on any write-capable bare wildcard regardless of
what it is near, would refuse ordinary, everyday commands with no relationship
to the data home whatsoever.

One more distinction the fix had to make: an extglob group widened for
AMBIGUITY (`@(comp|other)` → a bare `*` leaf, since neither alternative is
resolvable to one exact string) is not the same kind of uncertainty as an
operand's own literal bare wildcard. `@(comp|other)` can only ever be `comp` or
`other` — a small, specific, enumerable set — never `company`, so failing closed
on this WIDENED reading specifically would block `mv /opt/@(comp|other) /tmp/x`
even though neither alternative can ever equal the ancestor's name. Each reading
`_glob_could_name` considers is now tagged as either the operand's own literal
text (or a PROVEN exact substitution, `_extglob_exact_alternative`'s output) or
a vague widening; only the former participates in the new fail-closed direction,
matching the SAME reasoning `_extglob_exact_alternative` itself was built on —
an ambiguous alternation is not a wildcard's "could be anything," it is a
disjunction over a KNOWN, finite set that this ancestor's name is not a member
of.

**The write-verb fix surfaced a Windows-only false positive in this file's
OWN test suite, not in the production code.** `test_without_dotglob_an_
ordinary_home_listing_is_untouched` asserts `mv ~/* /tmp/x` stays allowed
without `dotglob` — the same dotfile protection `ls ~/*` already relies on,
now exercised for a write-capable verb. The test does not set `KIROCREW_HOME`
itself, so it inherits whatever the autouse test-isolation fixture pinned it
to — nowhere near a real `.kiro`-shaped home. On POSIX that pinned path lives
under the system temp root, a tree disjoint from `$HOME`, so it never
interacts with `~/*` at all. On Windows it does not: `%TEMP%` (`C:\Users\
<user>\AppData\Local\Temp\...`) is NESTED inside the user's own profile
directory, so walking up from the pinned home lands on an ancestor one level
under `$HOME` — `AppData` — that, unlike a real KIROCREW_HOME's `.kiro`-
shaped ancestors, is not dot-prefixed. It therefore carries none of the
dotfile protection this test means to exercise, and `mv ~/* /tmp/x`
legitimately (and correctly, per the fix above) matched it. Confirmed by
directly simulating the shape (`KIROCREW_HOME` under `<home>/AppData/Local/
Temp/...`) rather than guessing: the production logic is doing exactly what
it is supposed to, given that input — a real user's data home is always
`.kiro`-shaped by this project's own convention, so this coincidence can only
arise from test infrastructure, never from a real installation. Fixed by
stubbing `_custom_home_ancestors` to return nothing for the one assertion
that meant to test fixed-container-dir behavior in isolation, rather than by
weakening the production check that correctly caught it.

**Indirect expansion resolves the configured home through an opaque second
variable, with no literal name of its own to match.** `N=KIROCREW_HOME; mv
"${!N}" /tmp/x` renames whatever `$KIROCREW_HOME` holds without the operand
ever spelling that name — bash's `${!NAME}` expands to the value of the
variable NAMED BY `NAME`'s own value, one hop further than `${NAME}`. The
same shape reaches the default home too: `N=HOME; mv "${!N}/.kiro/crew"
/tmp/x`. Neither is caught by the substitution scanner's existing
masking-then-glob check: `${!N}` masks to a bare `*` (whole-operand) or
`*/.kiro/crew` (embedded), and `_glob_could_name` requires the masked reading
to already look like a path — start with `/` or `~` — before checking it
against anything, so both readings were silently dropped rather than refused.
`_indirect_expansion_could_name_container` closes this as its own check,
matched anywhere in the text rather than only as a whole operand: unlike a
command substitution, the literal text surrounding `${!NAME}` is no anchor at
all here, since indirect expansion's whole point is resolving through a
variable this matcher cannot see the value of. Excludes bash's unrelated
`${!prefix*}`/`${!prefix@}` variable-name-listing constructs, which end in
`*`/`@` rather than closing straight after the name.

**The brace-overflow prefix heuristic's "same parent" check silently
mismeasured one of its two prefix shapes, independent of what root set it
searched.** `_overflow()` decides whether a brace expression too large to
enumerate could complete a protected path by checking its literal prefix
against a root's own directory. Two different prefix shapes need two
different "landing directory" answers: `~/.ki{r,r}o/crew`'s prefix `~/.ki`
EXTENDS a partial component, landing in that component's own parent (one
`dirname()` call). `/opt/{arm0,…,company}`'s prefix `/opt/` already ends at a
separator — the brace starts an entirely FRESH component, landing directly
inside `/opt`, not inside `dirname("/opt")` == `/`. Reusing one `dirname()`
call for both shapes silently mismeasured the second, so a brace-overflow
spelling out a protected root's own leaf name — with nothing after it, no
separator in the brace body — never matched, regardless of which roots were
searched: `mv /opt/{x0,…,x69,company} /tmp/x` (71 arms, one spelling the
ancestor `/opt/company` exactly) was allowed even with the ancestor already
in the checked root set. Fixed by computing the landing directory from
whichever shape the prefix actually is, and — separately — the root set
itself now includes `_container_targets()` (ancestors included), where
before it checked only the fixed container dirs and the sensitive-path dirs.

Correcting the landing-directory math for the trailing-separator case
reopens exactly the false positive the "same parent, not any ancestor"
comment above describes, the moment a `KIROCREW_HOME` sits directly under the
system temp root: `ls /tmp/{a..z}{a..z}`'s prefix `/tmp/` now lands in `/tmp`
correctly, and if the crewdata leaf's own parent is *also* `/tmp` (this
project's own test-isolation convention), the two would spuriously match. The
sibling check is therefore additionally guarded by
`not _is_system_tmp_root(Path(os.path.dirname(r)))` for the SAME reason
`_custom_home_ancestors` stops its own walk there — a root whose immediate
parent is shared, general-purpose territory cannot be treated as narrowly
identifying as an ordinary ancestor's parent is.

**An exact, single-alternative extglob is not vague, and the widened readings
threw that away.** `@(company)` names EXACTLY `company` — bash's extglob
"one of these alternatives" operator applied to a single, literal choice.
`_glob_could_name`'s two widened readings (`.*`, `*` in the group's place)
exist so an AMBIGUOUS or wildcard-shaped group can still be recognized, but
applied to `@(company)` they discard the one piece of information the group
actually carries: `mv /opt/@(company)` widened to a bare `.*`/`*` leaf, which
`require_leaf_literal` then correctly refused to treat as naming a
`KIROCREW_HOME` ancestor — correctly for a genuinely vague group, wrongly for
one that names something exactly. A third reading
(`_extglob_exact_alternative`) substitutes a single-alternative,
glob-syntax-free group with its own text rather than a wildcard; an
alternation (`@(a|b)`) or a group holding its own glob syntax is left widened,
since it genuinely has no one answer.

**A multi-alternative extglob group is not "no one answer" the way a genuine
wildcard is — it is a disjunction over a small, KNOWN, finite set, and the fix
above threw that away too (GPT review).** `@(a|b)` correctly stays widened by
`_extglob_exact_alternative`, since neither `_glob_could_name` nor bash itself
can pick ONE of the two — but the widened `*` reading this produces is tagged
as a `is_vague_widening` reading (see the leaf-anchor fail-closed section
above),
which means NEITHER alternative was ever checked against a target
individually. `@(foo|SomeRepo)` names `SomeRepo` exactly as much as it names
`foo`, and `mv /home/runner/work/@(foo|SomeRepo)` — the shape a real CI
runner's own checkout path takes — relocated an ancestor literally named
`SomeRepo`, because the ONLY reading that reached the fail-closed check was
the widened one, correctly exempted as vague. `_extglob_alternative_readings`
closes this: for a multi-alternative group, each alternative is substituted
in turn as its OWN exact (non-vague) reading, alongside the existing widened
one — bounded to the first group found, since nested or multiple simultaneous
groups combinatorially explode and the widened reading already covers those
defensively, and an alternative that is itself glob-shaped (`@(comp*|other)`)
is skipped, since it is not one exact string either.

**A singleton bracket expression is the same shape of exactness, and
`_pattern_component_has_literal_anchor` threw it away the same way.**
`[c]` names EXACTLY the character `c` — bash's bracket-class syntax applied
to a class of one. The literal-anchor check strips every bracket expression
unconditionally (`\[[^\]]*\]`) before asking whether any literal text
survives, on the reasoning that a bracket class is as vague as a bare `*` —
true for `[abc]` or `[a-z]` (each genuinely admits more than one character),
false for `[c]`: `mv /opt/[c][o][m][p][a][n][y] /tmp/stash` against a
`KIROCREW_HOME` nested under `/opt/company` spells the ancestor's name
letter-for-letter, glob syntax and all, and stripping every bracket left no
literal text for the check to find — `require_leaf_literal` then correctly
refused to treat a leaf with no literal anchor as naming the ancestor,
correctly for a genuinely vague class, wrongly for seven brackets that
together spell one exact word. `_debracket_singleton` now substitutes a
bracket's own text only when its content is exactly one character and not a
negation or range marker (`!`, `^`, `-`) — those keep their ordinary vague
reading, stripped to nothing, since a negated or ranged class genuinely
admits more than one character and treating it as a fixed literal would be
a false NARROW reading, the opposite direction from what this check ever
allows itself to be wrong in.

**`_debracket_singleton` preserving a non-alphanumeric character correctly
was only half the fix — the FINAL check still discarded it.** After
de-bracketing, `_pattern_component_has_literal_anchor`'s last line was
`any(ch.isalnum() for ch in stripped)`, so a de-bracketed `[_]` — kept as
the literal character `_` by the fix above — still read as carrying no
anchor, because `"_".isalnum()` is `False`. An ancestor genuinely named
`_` (or containing one as its only surviving character after other
stripping) is not a contrived edge case; `_` and `-` are ordinary filename
characters with no reason to be excluded. Replaced the alnum test with
plain non-emptiness — by construction, everything reaching that line
already had every wildcard and vague bracket class stripped out, so any
character still present is literal text — with ONE deliberate exception:
a stripped result made ENTIRELY of `.` characters is still excluded, not
folded into the general rule. `@(.kiro)`'s dotfile-widened reading
(`_glob_could_name`'s `.*` substitution) is literally the character `.`
with the trailing `*` stripped away by this same function, so a bare `.`
surviving here is that widening marker leaking through as if it were
identifying text — and no filesystem permits a directory literally named
`.` or `..` either, so excluding an all-dot remainder costs nothing on the
legitimate side while closing the one case where "non-empty" would have
been wrong in the opposite, over-narrow direction this whole mechanism
exists to avoid.

**The raw glob scanner's word-splitting broke on the one whitespace bash
itself does not treat as a separator.** `_raw_glob_could_name_container`
isolated glob-bearing words with a plain `text.split()`, which cuts on
every whitespace run — including a backslash-escaped one. `my\ dir` is a
SINGLE path component to bash (the backslash escapes the space), but
`str.split()` produces two fragments, `my\` and `dir`, and neither alone
matches an ancestor whose real name contains that space:
`bash -c 'mv /opt/my\ d[i]r /tmp/x'` against `KIROCREW_HOME` under
`/opt/my dir` relocated the ancestor through the one code path — the raw
scan reading inside an opaque `-c` payload — that a quoted interpreter
argument reaches at all. Fixed by splitting with `(?:\\.|\S)+` (an
escaped character stays glued to its neighbors, so `\ ` is part of the
same word rather than a boundary) and then un-escaping ONLY the
whitespace that split protected — not every backslash in the word, which
would start reimplementing bash's whole escaping grammar rather than
closing this one reported gap.

**Several of this file's own tests hardcoded the literal POSIX `/tmp` as a
`KIROCREW_HOME` prefix to exercise `_is_system_tmp_root`'s POSIX-`/tmp`-
literal fallback, and that fallback — unlike `tempfile.gettempdir()`'s
result — has no Windows equivalent.** Windows has no `/tmp` directory and no
reason to treat that string as special; the fallback exists specifically for
POSIX platforms where `tempfile.gettempdir()` might not itself return `/tmp`
(a custom `TMPDIR`) but `/tmp` should still be recognized regardless. Under a
`KIROCREW_HOME` built on that literal, the affected tests assert that an
ordinary command naming `/tmp` (`cd /tmp && cat notes.txt`, `ls -la /tmp/*`)
stays allowed — true on POSIX, where `/tmp` is the recognized boundary, but
false on Windows, where the literal `/tmp` is just an ordinary, unrecognized
ancestor of the configured home and the command IS refused, exactly the
class of failure this document's account of the temp-root exemption exists
to prevent. Confirmed on CI (`Backend Tests (Windows)`): the five affected
tests now carry `@pytest.mark.skipif(not platform_compat.IS_POSIX, ...)`,
matching this file's own established pattern for a POSIX-only mechanism
(the same shape as the `_build_launcher_script`-calling tests guarded
earlier in this PR's history) — the mechanism itself needs no code change;
only the tests that hardcode it needed the platform guard.

**A second, more subtle Windows gap survived that round: three tests used
`tmp_path` (pytest's own fixture) rather than a hardcoded literal, and
still failed on Windows CI, because `tmp_path` and this project's own
redirected `tempfile.gettempdir()` are SIBLINGS under this test suite's
own scaffolding, not one nested inside the other — a relationship that
only coincidentally looks like nesting on POSIX.** The root conftest's
`_isolate_tempfile_base` fixture reads `tempfile.gettempdir()` for its
`parent`, creates a sibling directory (`kc-pytest-<user>-<pid>`) next to
whatever pytest's own `tmp_path_factory` already created there, and THEN
redirects `tempfile.gettempdir()` to point at that sibling. So `tmp_path`
(built from pytest's OWN, pre-redirect basetemp) and the POST-redirect
`tempfile.gettempdir()` value are two different directories with a common
ancestor, not one contained in the other. Walking up from `tmp_path`
looking for an ancestor `_is_system_tmp_root` recognizes will only ever
reach that common ancestor — which `_under_system_tmp` also has to
recognize for the walk to succeed.

On Linux, that common ancestor genuinely IS `/tmp` (`tempfile.gettempdir()`
returns `/tmp` there natively), so the POSIX-literal fallback catches it.
On macOS, this repo's own `conftest.py` forces `TMPDIR=/tmp` at
`pytest_configure` time (`_prefer_short_tmp_base`, documented in this
file's own comments as an AF_UNIX-socket-path-length workaround) —
BEFORE pytest computes its own basetemp — so the common ancestor is
ALSO `/tmp` there, for an unrelated reason that happens to produce the
same outcome. Windows has neither: `_prefer_short_tmp_base` is gated to
`sys.platform == "darwin"` only, so pytest's basetemp and the redirect
sibling both land under the TRUE, un-shortened `%TEMP%`, and `_under_
system_tmp` on Windows has no POSIX-literal fallback to fall back on —
its only candidate is the POST-redirect `tempfile.gettempdir()`, which is
never an ancestor of `tmp_path` there. Two tests (`test_the_sandbox_
protects_the_temp_root_itself`, `test_the_boundary_helper_directly`) now
build their probe path from `tempfile.gettempdir()` directly instead of
`tmp_path`, matching the pattern `test_the_ambient_tmpdir_is_still_exempt`
already used correctly for the identical reason.

**A third, unrelated Windows failure in the same CI run**:
`test_the_default_kiro_pair_is_also_ordered_correctly` compared
`sandbox._unrenamable_containers()`'s entries with a bare `.endswith(
"/.kiro")` — a forward-slash literal that never matches a Windows path,
which is backslash-separated, so the generator it fed found nothing and
`next()` raised `StopIteration` instead of returning a verdict. Its
sibling `test_every_ancestor_precedes_its_descendants` had the identical
bug in its own ancestor/descendant comparison, but in a form that failed
SILENTLY rather than loudly: the mismatched separators meant its `if`
condition was simply never true on Windows, so the `assert` inside it
never ran and the test passed without checking anything. Both now compare
`/`-normalized paths, the same fold this file's own `security.py` already
applies when comparing paths that may cross this separator boundary.

**An attempt to narrow the temp-root exemption to only a FIXED boundary was
itself wrong, and reopened the original regression on one real CI platform.**
The reasoning looked sound: `_is_system_tmp_root`'s exemption exists because a
general-purpose, OS-designated directory cannot be treated as part of a data
home's identity, and that reasoning does not obviously extend to a root an
operator explicitly pointed via `TMPDIR`/`TEMP`/`TMP` — a deliberately chosen
location, no different from any other ancestor this walk exists to protect.
An `only_fixed_boundaries` parameter was added to `_under_system_tmp`, used
only by `_is_system_tmp_root`: when any of those three variables was set,
`tempfile.gettempdir()`'s result was excluded from the candidate roots
entirely, leaving only the POSIX `/tmp` literal.

The premise was that an operator setting `TMPDIR` signals deliberate intent.
**macOS does not let that premise hold**: `launchd` sets `TMPDIR` for every
process on the system, unconditionally, to a per-user, per-boot sandboxed
directory (`/var/folders/.../T/`) — there is no "unset" state to distinguish
from an operator's deliberate choice, so `env_overridden` was `True` for
every macOS process, always, regardless of who set anything. The narrowed
exemption therefore excluded `tempfile.gettempdir()`'s result on macOS
unconditionally, which reopened the EXACT regression this exemption exists to
prevent, on a platform where it matters concretely: `Gateway Tests (macOS)` is
a real CI job, and the rootdir `conftest.py`'s autouse `_isolate_kirocrew_home`
fixture pins `KIROCREW_HOME` under `tempfile.gettempdir()`-derived paths for
every test — so an ordinary test command naming a path under the pinned home
started reading as naming a protected ancestor again, this time only on macOS,
where the previous, broader exemption had already been hiding the bug from
every other platform's CI run.

This was self-found during unrelated test debugging, not by a reviewer, and
is recorded here rather than left implicit because the code it corrects had
already shipped to this PR's head and this document had already described it
as the reasoned, deliberate answer. **The fix is a full revert, not a
platform-aware patch.** `_under_system_tmp` no longer takes an
`only_fixed_boundaries` parameter; `tempfile.gettempdir()`'s result is
unconditionally a candidate boundary again, exactly as it was before the
narrowing attempt, regardless of whether `TMPDIR`/`TEMP`/`TMP` is set or by
whom. A platform-aware version (distinguishing an operator's own `TMPDIR` from
launchd's ambient one) was considered and rejected: there is no reliable
cross-platform signal for "who set this", and a wrong signal here fails in the
refuse-ordinary-commands direction, which is a functional regression, not a
safe fail-closed one.

The narrower gap this leaves — an operator who deliberately points
`KIROCREW_HOME` beneath a *custom*, non-ambient `TMPDIR` they themselves
control — is accepted as declined, not silently reopened: `sandbox.py`'s own
ancestor walk (`_unrenamable_containers`) already closes it unconditionally,
at zero usability cost, because self-binding a directory entry costs nothing
comparable to refusing an ordinary command that merely names a shared root.
The asymmetry between the two copies of the walk described two subsections
above — `security.py` stops at the temp root for usability reasons that do
not apply to `sandbox.py` — already made this the intended division of labor;
the narrowing attempt tried to close the gap on the wrong side of that
division, where the safe answer for that side was never available in the
first place.

**Extracting the ancestor walk into a function shared by four matchers turned
one blocking syscall per configured home into one per command.**
`_custom_home_ancestors` calls `os.path.realpath()` — potentially slow, or
outright stalling, against a network-backed data home — and unlike
`_build_container_regex`'s own callers, which only ever ran through
`_get_container_re`'s TTL-cached wrapper, its three other callers (the
substitution scanner, the glob scanner, `is_unreplaceable_container`) had no
caching of their own. Gained a TTL cache mirroring `_home_dir_targets`'s
(`_custom_home_ancestors_cache`, 0.1s, keyed on the raw `KIROCREW_HOME`
value) — bounding the cost back down to roughly what it was before the walk
was shared, rather than multiplying it by the number of newly-sharing
call sites.

**Command-substitution output is not subject to bash's dotglob rule, and the
substitution scanner's masking treated it as if it were.** `_glob_component_
matches` refuses to let a bare `*` match a dot-prefixed target component
unless `dotglob` is set — correct for an actual shell glob the shell itself
expands, where that really is bash's rule. But `_substitution_could_name_
container` masks UNKNOWN SUBSTITUTION OUTPUT to that same `*`, and command
substitution splices its output in literally: `$(printf .kiro)` really does
yield `.kiro`, no dotfile exemption of its own. Checking the mask without
`dotglob=True` let `~/$(printf .kiro)` mask to `~/*`, which then silently
failed to match every fixed container — `.kiro`, `.kiro/crew`, `.kirocrew`
are all dot-prefixed under `$HOME`, so this exempted the whole scanner from
ever catching a substitution-supplied leading dot. Both `_glob_could_name`
calls in `_could_name` now pass `dotglob=True` unconditionally; the ancestor
call stays safe from a bare `/tmp/*` regardless, since `require_leaf_literal`
independently demands the operand's own leaf component retain a literal
character no matter what `dotglob` is set to.

**Two more call sites built their glob target set from the fixed container
dirs alone, missing the same ancestor-target gap the raw regex, the
substitution scanner, and the exact-match check were each fixed for above.**
The normalizer pass's own glob check (~line 9521) and the cd-relative glob
branch (~line 9801) both called `_home_dir_targets(sorted(
_UNREPLACEABLE_CONTAINER_DIRS))` directly, predating `_container_target_groups()`
— so `mv /opt/comp*/dept /tmp/x` against a `KIROCREW_HOME` nested under
`/opt/company` reached neither check with the ancestor `company` in its
target set, the same bypass shape already closed for the other three
consumers. Fixed by extracting a shared `_glob_could_name_container(candidate,
**glob_modes)` helper — built once from `_container_target_groups()`, checking
the fixed dirs with the existing, more permissive matching and the ancestor
dirs with `require_leaf_literal=True`, matching the risk-based split above —
and switching both call sites to it, so an ancestor added to the shared group
builder cannot silently go missing from a fifth and sixth checker either.

**A purely literal path built by string concatenation, with no substitution
inside it, was never checked at all.** `_substitution_could_name_container`
existed specifically to catch a target spelled through command or variable
substitution, so it returned early whenever `_OUTPUT_SUBSTITUTION_RE` found
no substitution in the text — reasonable for the masking-then-glob machinery,
which has nothing to mask without one. But the SAME function also carries a
concatenation check, for the `"lit" + "eral"`-joined-strings idiom several
spawned interpreters share, and that check does not need a substitution to
be present — `"~/.ki" "ro/crew"` (two adjacent literals, no substitution)
reconstructs a full container path through pure concatenation, and the early
return skipped it before it ever reached that check. Fixed by removing the
early return and gating only the substitution-specific masking and per-word
loop on `_OUTPUT_SUBSTITUTION_RE.search(text)`, leaving the concatenation
check reachable unconditionally. Closing that gap surfaced an adjacent one:
`_could_name`'s own glob check (`_glob_could_name`) early-exits on a
candidate with no glob metacharacters at all, so a reconstructed candidate
that is already fully literal (`~/.kiro/crew`, no `*`/`?`/`[`) was silently
dropped rather than checked. `_could_name` gained a separate exact-match
branch — expand `~`, require an absolute path, casefold-and-normalize, and
compare directly against the same fixed-and-ancestor target union — reached
only when the candidate carries no glob syntax for `_glob_could_name` to
widen in the first place.

### A symlinked intermediate ancestor, on the sandbox side

The sandbox's ancestor walk (`_unrenamable_containers`) was built on the
RESOLVED leaf only. A symlinked LEAF was already covered — the unresolved
override is appended as its own entry, per the symlinked-custom-home case
above — but a symlinked INTERMEDIATE ancestor had no equivalent:
`KIROCREW_HOME=/opt/symlinked-dept/crewdata` where `symlinked-dept` is itself
a symlink protects the resolved chain (`/real/dept`, ...) but never
`/opt/symlinked-dept` itself, since that path never appears in the resolved
chain at all. `rm /opt/symlinked-dept && ln -s /evil /opt/symlinked-dept`
repoints every future resolution exactly the way a symlinked leaf swap
already does.

Fixed by walking BOTH spellings — the resolved leaf and the unresolved,
expanded override — merging their ancestor chains into one shallow-first
list. The two chains can diverge partway (exactly where the symlink sits)
and later reconverge onto a shared ancestor further up; a shared `seen` set
across both walks means a chain that merges into one already walked simply
stops contributing NEW entries at the merge point, and everything before
that point in its own chain is by construction strictly deeper than the
merge point — so appending each walk's own shallow-first-reversed segment,
in turn, keeps every ancestor ahead of its own descendants for BOTH chains
at once, without needing a global sort across the two.

### A relative override is anchored to the child's cwd, not the gateway's

The unresolved-override entry above (`expanded_override`) was built with
`Path(override_raw).expanduser()` alone — no `.resolve()`, deliberately, since
resolving would follow the symlink this entry exists to protect. But
`.expanduser()` only ever touches a leading `~`; a `KIROCREW_HOME` with neither
that nor a leading `/` (`KIROCREW_HOME=../dept/crewdata`) stayed a RELATIVE
string, embedded as-is into the launcher script and evaluated by the SPAWNED
CHILD's own `os.path.islink`/`isdir`/`mount(2)` calls against **its own** cwd —
not the gateway's (GPT review). A task spawned with a different `cwd=`
resolved the "protect this override" entry to an unrelated path, and the
self-bind protection silently checked nothing there: the exact bypass this
entry exists to close, reopened by one relative path.

Fixed with `os.path.abspath` — lexical only (join against `os.getcwd()` and
normalize), never `.resolve()`, so a symlink component in the spelling stays a
symlink rather than being followed away. Computed ONCE, before the spawn, so
it captures the GATEWAY's cwd regardless of what cwd the eventual child runs
with; reused for both the ancestor walk and the final unresolved-override
entry rather than re-derived a second time, so a future edit cannot silently
reopen the gap in one of the two spellings while fixing it in the other.

### An absent keystone FILE got no hiding mount at all

`_KEYSTONE_FILES` is hidden by bind-mounting an empty tmpfs file OVER each
one, and `mount(2)` requires the target to already exist — so a keystone file
this box never configured (`computer_use.json` on most fresh installs, since
it is operator opt-in only; equally `admission_policy.json`, `denied_commands
.json`, `crons.json`, `autonudge.json` on any box that never touched that
setting) got no mount at all, gated on `os.path.isfile`. Nothing then stopped
a sandboxed subprocess from CREATING the file directly — `computer_use.json`
with `{"enabled": true, ...}` flips the primary enable for full desktop
observation and input synthesis — the exact "an opaque script defeats the
tool gate" bypass this list exists to close, just for a file that happens not
to exist yet (GPT review).

The fix materializes a placeholder BEFORE the mount, when the file is absent
AND registered — but which content is safe to materialize is NOT uniform
across these six files, and getting it wrong is worse than the original gap:

- **`computer_use.json`, `denied_commands.json`, `crons.json`,
  `autonudge.json`** each fail-soft an ABSENT, EMPTY, or invalid file to the
  identical "nothing configured" outcome (`enable_state.load_state`,
  `hooks.load_denied_commands_state`, `CronService._load`, and autonudge's own
  `_locked_file`, which already self-materializes an equivalent default on
  first read) — so `{}` reads byte-identically to absence through every
  consumer, and is the placeholder for all four.
- **`security_policy.json` has NO safe placeholder at all.** Absence returns
  `None` from `platform.governance.load_security_policy` — ungoverned
  standalone defaults, boot succeeds. But ANY present file, valid or not,
  raises `PlatformCompositionError` and ABORTS BOOT: `{}` is syntactically
  valid JSON, so it reaches `parse_policy`, which fails the `version == 1`
  check; unparseable content hits the same unguarded raise one line later.
  There is no content this file can hold that means "treat me as absent" —
  existing is what triggers the strict-or-nothing contract by design, so this
  file is excluded from the placeholder map entirely and keeps the
  pre-existing isfile-gated (no mount when absent) behavior.
- **`admission_policy.json` is the mirror image, and gets a DIFFERENT
  placeholder, not none.** Absence fails CLOSED
  (`platform.admission._fail_closed_policy()`, deny-all) — but `{}` is valid
  JSON, and `AdmissionPolicy.from_dict({})` fails OPEN (every field its
  dataclass default: `mode=MODE_OPEN`, no signature required), the opposite
  direction from absence. UNPARSEABLE content, though, hits the SAME
  `except Exception` branch `load_admission_policy` already uses for a
  present-but-unreadable file, which returns the identical
  `_fail_closed_policy()` absence does — so this one file's placeholder is
  empty bytes, not `{}`, specifically so it stays unparseable.

The materialize step itself is exclusive-create (`open(target, "x")`): a
genuine race with the file's real writer loses to that write rather than
silently overwriting it, and any `OSError` (including "already exists") falls
through to the pre-existing `os.path.isfile` check unchanged.

### A symlinked keystone FILE stayed replaceable through the hiding mount

`os.path.isfile` follows a symlink and reports True for one pointing at a real
file, so the mount loop above happily bind-mounted THROUGH a symlinked
keystone file exactly the way `mount(2)` on a symlinked path resolves like
`open()` does (GPT review): the bind lands on the file the link points to,
hiding its CONTENT from the sandboxed process, but the link's own directory
entry — `.kiro/crew/security_policy.json` itself, as a name in that directory
— stays exactly as replaceable as it always was. `rm .../security_policy.json
&& ln -s /evil/weaker-policy.json .../security_policy.json` swaps what the
link points to from inside the sandbox the mount was supposed to be
protecting, and the NEXT boot — a freshly-spawned sandbox, or the unsandboxed
gateway process itself reading the file directly — follows the untouched link
straight to the attacker's weaker policy.

This is the identical shape of gap `UNRENAMABLE_DIRS`'s own `os.path.islink`
check already closes for the CONTAINER directories, for the identical reason:
there is no bind-based way to protect the link's own directory-entry slot
without write-denying the PARENT directory's contents, which is the
subtree-fencing this whole mechanism deliberately does not do (every file
inside every ancestor stays writable). So a symlinked keystone file now
refuses the spawn instead of silently protecting the wrong thing — the same
fail-closed answer a symlinked container directory already gets, applied to
the file-hiding loop that never had it.

Scoped to `isfile()` as well as `islink()`, not `islink()` alone:
`SENSITIVE_FILES` also carries DIRECTORY entries folded in from `hidden_dirs`,
and a symlinked directory is a real, unrelated pattern some operators use for
`~/.aws`/`~/.ssh` dotfile management — `isfile()` is already False for a
directory regardless of symlink status, so gating the refusal on it too keeps
a symlinked directory out of this FILE-scoped control entirely, leaving it to
whatever directory-level mechanism already covers it.

**`_sensitive_file_placeholders` broke its own Windows CI test the same way
`_home_dir_targets_uncached` already had to fix once.** Each dict key was
built with `os.path.join(home, entry)`, where `entry` is a MULTI-SEGMENT,
POSIX-`/`-separated string (`.kiro/crew/computer_use.json`) — `os.path.join`
does not split its later arguments, so on Windows the result kept a literal
`/` after the native-separator `home` prefix
(`C:\Users\x\.kiro/crew/computer_use.json`), which no correctly-joined
spelling of the same path (`C:\Users\x\.kiro\crew\computer_use.json`) ever
equals as a string. Fixed by splitting each entry on `/` before joining, in
both the `~`-relative and the custom-home-re-anchored halves of the function
— the same fix `_home_dir_targets_uncached`'s own `_anchor` needed for the
identical shape of entry.

### Two more failure directions in the ancestor-target machinery, both fail-open

**A fixed-point budget that stops without converging leaves matching syntax
behind, and every check downstream reads it as an unrelated literal.** Both
`_substitution_could_name_container`'s masking loop and `_glob_could_name`'s
extglob-widening loop are bounded (`_MAX_SUBSTITUTION_MASK_PASSES`,
`_MAX_EXTGLOB_SUB_PASSES`) — deliberately, an absurd nesting depth cannot
mean unbounded work on the event loop. But the ORIGINAL comments claimed
"stopping early only ever narrows the match, never widens it," and that
claim is wrong for the case that actually matters: a nesting depth chosen
specifically to outlast the budget leaves unresolved `$(...)` or `@(...)`
syntax in the result, and neither `_glob_could_name` nor `fnmatch` reads that
residue as the wildcard it should represent — it reads as an unrelated
literal string, so the whole check silently returns "no match," a full
bypass, not a narrower one. Both loops now use `for...else`: if the loop
never hit its `break` (never converged) AND matching syntax still remains
after the last pass, the function returns `True` immediately — the same
fail-closed answer every other bounded scan in this module already gives on
overflow.

**`_BRACE_RANGE_RE`'s endpoints were exactly one character wide, so a
multi-digit numeric range was never recognized as a range at all.** Bash
brace ranges support multi-digit, signed, and zero-padded numeric endpoints
(`{10..10}`, `{-2..2}`, `{001..003}`), but the pattern's `(\w)` capture
groups only ever matched a single character. This is not "expanded wrong" —
`company{10..10}` never matched the regex in the first place, so
`_expand_braces` returned the token completely unchanged, and neither the
normal expansion path nor the belt-and-braces overflow check (which
searches with the SAME regex) ever saw a brace to expand or refuse. An
ancestor literally named `company10` was reachable through
`mv /opt/company{10..10}/dept ...` with nothing downstream recognizing
anything unusual. Widened the pattern to `[+-]?\d+|[A-Za-z]` per endpoint —
the numeric-range branch already used `int()` rather than `ord()`
internally, so multi-digit values were always handled correctly once they
could be captured at all. Endpoint length is now bounded the same way the
optional step already was (`_MAX_BRACE_STEP_DIGITS`), since a signed,
multi-digit endpoint carries the identical unbounded-`int()`-parse risk.
Zero-padding — bash pads every generated term to the WIDEST endpoint's digit
count when either begins with `0` — is implemented too, since
`company{001..001}` and the literal ancestor name `company001` would
otherwise still fail to line up.

**Widening the endpoints to multi-digit created a second, more serious bug:
the numeric branch materialized its ENTIRE span before any cardinality bound
ran.** `_MAX_BRACE_STEP_DIGITS` bounds the endpoints' DIGIT COUNT (so
`int()` never chokes on an absurdly long literal), not the SPAN those digits
describe — a 31-digit endpoint parses instantly and is nowhere near that
guard, but `{1..99999999999999999999999999999}` still spans roughly 10**31
terms. The list comprehension building `span` ran unconditionally, and the
`len(grown) > _MAX_BRACE_EXPANSIONS` cardinality check that exists
specifically to bound this kind of explosion only ran AFTER each piece was
appended — so for the numeric branch, the comprehension itself was the
unbounded work: a short command stalls the PreToolUse gate's synchronous
event-loop thread trying to materialize a list no runtime could hold,
functionally indistinguishable from a hang.

The fix computes the term count from plain `int` arithmetic on the already-
parsed `lo`/`hi`/`step` — `abs(hi - lo) // abs(step) + 1` — and checks it
against the SAME `_MAX_BRACE_EXPANSIONS` budget before either list
comprehension runs. The obvious alternative, `len(range(...))`, was tried
first and rejected: CPython's `len()` protocol must return a value that fits
a C `Py_ssize_t`, and a range this large makes `len()` raise `OverflowError`
rather than return a count — which would have traded the original
uncaught-stall bug for an uncaught-crash one, still leaving the gate
answering nothing rather than failing closed. Plain Python `int` subtraction
has no such ceiling. The alpha branch (`[A-Za-z]` endpoints, `ord()`/`chr()`)
was not touched: a single-letter endpoint bounds `hi - lo` to at most 25
by construction, so it was never exposed to this failure mode.

**A MIXED numeric/alpha endpoint pair reached that same alpha branch and
crashed it outright.** The branch choosing numeric-vs-alpha handling tests
only digit-ness (`start_digits.isdigit() and end_digits.isdigit()`), not
length, so `{10..a}` — a multi-digit numeric `start` paired with a
single-letter `end` — falls to the `else` branch on the (correct) grounds
that not both endpoints are digit strings, and that branch unconditionally
calls `ord(start)`. `ord()` requires an exactly-one-character string;
`ord("10")` raises `TypeError`, which propagated straight out of
`is_sensitive_bash_command` and aborted the tool-authorization decision
entirely — not a wrong verdict, no verdict at all. Bash itself does not
treat a mixed numeric/alpha pair as a range either — `{10..a}` is left
unexpanded — so the fix refuses it the same way other unrecognized brace
syntax is already refused: `len(start) != 1 or len(end) != 1` routes a
mixed pair to `_overflow(token)` before `ord()` ever runs, matching both
bash's own behavior and this gate's existing convention of failing closed
on what it cannot expand.

**The synchronous `os.path.realpath()` call in `_custom_home_ancestors_
uncached` is a reviewed, accepted trade-off, not an oversight — documented
in the function's own docstring rather than left to a PR comment,** since a
disposition that lives only in PR history is invisible to a review that
re-reads the diff fresh on every push. This module already carries roughly
a dozen pre-existing `os.path.realpath()`/`.resolve()` calls on the exact
same synchronous command-gate path — `_home_dir_targets`'s own cache exists
for the identical shape of cost — so this call is one more instance of an
already-accepted, module-wide architectural decision, not a new one made
here. The TTL cache added earlier in this document's account of the
ancestor-walk sharing bounds it to at most one such call per configured
home per cache window, and because that walk replaced four previously-
independent, uncached call sites, this round's change *lowers* the number
of blocking calls one command can trigger rather than raising it. Moving
path resolution off the synchronous gate entirely is a change to how the
whole module authorizes commands, not to this one call, and is out of
scope for this PR.

**A brace step's sign was only ever recognized as a MINUS, so an explicit
PLUS made the whole brace-range regex fail to match at all.** Bash accepts
a leading `+` on a brace-range step (`{a..z..+2}`) the same way it does on
either endpoint, but `_BRACE_RANGE_RE`'s optional step group was `-?\d+` —
an optional minus, never a plus. `{e..e..+1}` therefore did not match the
regex at ANY position: the step group is required once a second `..`
starts it, and `+1` does not fit `-?\d+`. Because the belt-and-braces
overflow check searches with this SAME regex, it found nothing to refuse
either, so a degenerate single-value range like `cr{e..e..+1}w` — which
bash still expands to `crew` regardless of the step's sign, since the two
endpoints are equal — passed through completely unexpanded and unchecked.
Widened the step group to `[+-]?\d+`, matching the two endpoints it always
should have.

**`shopt -s` takes a space-separated LIST of option names, and every
glob-mode detector required its target to be the only one.**
`_DOTGLOB_ENABLED_RE`, `_GLOBSTAR_ENABLED_RE`, and `_EXTGLOB_ENABLED_RE`
each matched `shopt -s <target>` literally — `dotglob`, `globstar`, or
`extglob` had to appear immediately after `-s`. But bash's `shopt -s`
accepts multiple option names in one invocation: `shopt -s nullglob
dotglob` enables both, with `dotglob` as the SECOND argument. `shopt -s
nullglob dotglob; mv ~/* /tmp/x` left `dotglob` undetected — the mode
regex found no match, `_glob_modes` reported it disabled, and the
leading-dot exemption an undetected `dotglob` still grants let `~/*` miss
the `.kiro` ancestor it should have matched under bash's real, dotglob-
enabled semantics. All three regexes now allow any number of OTHER option
names between `-s` and the target (`(?:\s+\S+)*`), so the target is found
regardless of where in the list it sits — before, after, or surrounded by
unrelated options.

**An assignment whose value is the container, later trimmed through a
parameter-expansion OPERATOR, reconstructs it in a way the substitution
scanner's masking cannot see (GPT review).** `H=$HOME/.kiro/crewXXXX; mv
"${H%XXXX}"` assigns `H` a value that is the container path plus a literal
suffix, then trims exactly that suffix off with bash's `%` (shortest-suffix
trim) operator — landing back on `$HOME/.kiro/crew`. `_OUTPUT_SUBSTITUTION_
RE` matches `${H%XXXX}` (any `${...}` span) and masks it to a bare `*`, the
same treatment a bare `${H}` or a `$(...)` command substitution gets — but
unlike those, `${H%XXXX}`'s result is not unknowable: `H`'s value was
assigned in plain text two tokens earlier in the SAME command. Masked to a
content-less `*`, the operand carries no leading `/` or `~` for the "looks
like a path" gate even to see, so it was silently dropped rather than
checked.

The fix does not try to compute bash's actual trim result: `%`, `%%`, `#`,
`##`, and a `/pattern/replacement` substitution each transform the string
differently, and the trimmed RESULT is not always literally present in the
assigned value's own text the way an exact-match check would need.
`_assignment_feeds_container_via_operator` instead asks a narrower, safely
over-broad question — does a plain `NAME=value` assignment's value already
CONTAIN a container or a configured home's ancestor as a substring, and is
that SAME `NAME` later referenced through ANY operator-form parameter
expansion (`${NAME%...}`, `${NAME#...}`, `${NAME/.../ ...}`, `${NAME:...}`,
`${NAME^...}`, `${NAME,...}`) — and refuses the command outright when both
hold, regardless of which specific operator runs or what it computes. The
operator's mere PRESENCE is what makes the assigned text alone insufficient
to clear the command: there is no operator in bash's repertoire this scan
can safely assume narrows every case away, so the conservative, fail-closed
reading is to refuse rather than to guess which trims are safe. A bare
`${NAME}` reference (no operator) is unaffected — that is the ALREADY-
handled substitution case above, where the value genuinely is unknowable
without the operator's help pointing at a plausible, known origin.

**A declaration builtin in front of the assignment hid it from
`_SIMPLE_ASSIGNMENT_RE` (GPT review).** `export H=$HOME/.kiro/crewXXXX; mv
"${H%XXXX}"` is the IDENTICAL assignment `H=$HOME/.kiro/crewXXXX` is, merely
exported for a child process to see too — but the regex's statement-boundary
anchor expected `NAME=` to begin right after `;`/`&&`/`|`/the text's own
start, and `export ` sitting between the boundary and `H=` meant the capture
never started where it looked, so the assignment went unrecorded and the
operator-form reference above found nothing to match against. Widened to
allow an optional declaration builtin (`export`, `declare`, `local`,
`readonly`, `typeset`) between the statement boundary and the assignment
itself.

**A NESTED parameter expansion inside a `$HOME` reference broke both the raw
regex and the substitution mask, for the identical reason `$(...)` needed
one level of balanced-paren tolerance (GPT review).** `${HOME:0:${#HOME}}`
is real bash syntax — a nested expansion supplying the substring LENGTH —
and evaluates to plain `$HOME`. Both `_build_container_regex`'s `home_var`
alternative and `_OUTPUT_SUBSTITUTION_RE`'s `${...}` alternative matched
with `[^}]*`, which stops at the FIRST closing brace: the INNER expansion's
own `}`, leaving the OUTER one stray right before whatever container
spelling followed. The raw regex then failed to match at all (the trailing
`}` where it expected `/.kiro/crew` to begin directly), and the substitution
mask left the same stray `}` in the masked result, breaking the "looks like
a path" reading exactly the way an unconsumed inner-substitution artifact
already does elsewhere in this scan. Both gained the SAME one-level
balanced-brace allowance `_OUTPUT_SUBSTITUTION_RE`'s `$(...)` alternative
already had (`(?:[^{}]|\{[^{}]*\})*` in place of `[^}]*`), rather than a
bespoke fix for each — the shape of the problem, and its resolution, are
identical to the parens case one alternation branch over.

**The operator-form assignment fix above broke on Windows CI, in a way no POSIX
run could surface.** `_assignment_feeds_container_via_operator` resolved a
textual `$HOME` reference by calling `os.path.expandvars`, which only expands
`$HOME` when the literal `HOME` environment variable is actually set — true on
POSIX, but Windows resolves the user's home through `USERPROFILE` instead and
does not reliably set `HOME` (`Path.home()` already knows this; see the note
above `_resolved_root_key`). Left unexpanded, `$HOME` stayed literal text that
could never match a resolved container path, so finding 29's own PoC stopped
being caught — on Windows only. Fixed by resolving a textual `$HOME`/
`${HOME...}` reference (`_HOME_TEXT_REF_RE`, with the same balanced-brace
tolerance as above) against `Path.home()` directly, ahead of the general
`expandvars` fallback. The expanded value is then `normpath`-ed before the
substring check: the assigned text is authored with POSIX `/` separators, but a
target anchored on Windows is all-backslash (`_home_dir_targets_uncached`
re-anchors its own `home_dirs` entries for the identical reason), so an
unnormalized value would never compare equal even once `$HOME` itself resolves
correctly. The `Path.home()` half is pinned by a test that deletes `HOME` from
the environment and confirms detection survives without it. The `normpath` half
cannot be isolated by any test this suite can run locally — every entry in
`_UNREPLACEABLE_CONTAINER_DIRS` is a prefix of a longer one (`.kiro` of
`.kiro/crew`), so a value containing `.kiro/<anything>` already matches the bare
`.kiro` target regardless of what separator follows, on the one platform this
suite runs on outside CI. Verified instead by exercising `ntpath.normpath`
directly (stdlib, available on any host) against a simulated
`USERPROFILE`-only environment and confirming the mixed-separator value it
produces fails the substring check without `normpath` and passes with it — the
fix only widens matching, so it cannot introduce a false positive, the same
reasoning the nested-brace fix above already rests on.

**That `normpath` fix broke a DIFFERENT existing test on Windows CI, because it
normalized only the value.** `test_an_ancestor_reached_the_same_way_is_also_
blocked` — finding 29's own ANCESTOR-target test, unrelated to `$HOME` — set
`KIROCREW_HOME=/opt/company/dept/crewdata` and asserted `H=/opt/companyXXXX;
mv "${H%XXXX}"` is blocked. It was, before the `normpath` fix landed; it
stopped being, on Windows only, after. The assigned value normalizes to
`\opt\companyXXXX` there, but the ANCESTOR target it needs to match does not
reliably get the same treatment: `_custom_home_ancestors` walks the
AS-CONFIGURED spelling of `KIROCREW_HOME` (forward slashes, exactly as an
operator typed them) alongside two normalized spellings (`abspath`,
`realpath`), and the as-configured one is never forced to native separators —
unlike a FIXED container target, which is always built through
`os.path.join(Path.home(), ...)` and so is already native-separator by
construction. Normalizing only the assigned value assumed every target
already matched its treatment; an ancestor target is the one case that does
not. Fixed by normalizing each TARGET too, at the point of comparison
(`os.path.normpath(target)`), rather than assuming its spelling already
matches the platform's separator convention. Verified by injecting a target
with a redundant `./` segment (`/opt/./company`) via a monkeypatched
`_container_target_groups` — a case that exercises the identical
both-sides-must-normalize property on any platform, since an un-normalized
target with a redundant segment is not a literal substring of the normalized
value either, for the same underlying reason a backslash-vs-forward-slash
target is not on Windows.

### The raw scan approximates a shell grammar, and keeps needing to approximate more of it

The container-naming raw scan (`_names_unreplaceable_container_raw`) compares command
TEXT, because it is the only pass that sees inside an un-tokenizable interpreter
payload (`python3 -c "..."`). Text comparison means it inherits every way a shell can
make two spellings equivalent without looking equivalent as strings, and each one
found so far has been closed as its own narrow, justified addition rather than
declared out of scope by default — separator runs the filesystem collapses to one
(`~//.kiro/crew` and `~/.kiro//crew` are the same path everywhere the pattern needs to
recognize a container, not only after the home prefix), quoting forms that vanish at
resolution time (`$'…'`, `$"…"`, ANSI-C escapes), expansions that produce nothing
(unset variables, empty command substitution, positional and special parameters like
`$1`/`$*`), and glob or extglob syntax that resolves to the container without ever
spelling it (`dotglob`, `globstar`, `GLOBIGNORE`, a *nested* `@(...)` group, which one
substitution pass cannot fully resolve and now runs to a fixed point), and a
*deeply nested* command or variable substitution (`$(echo $(echo $(printf i)))`),
which the masking pattern's one extra level of balanced parens — the most a
fixed-width regex can express for nesting at all — cannot fully consume in a single
pass either, and which now runs to the same kind of fixed point for the same reason.

**Detecting a glob mode is not the same as USING it.** `_glob_modes` reads `dotglob` /
`globstar` / `extglob` from the raw command text, but the operand check that applies
those modes runs on the normalizer pass's candidates — and a quoted `-c '...'` payload
is one opaque token to that pass, same as any other embedded interpreter script. A
mode detected with perfect accuracy still protected nothing if the glob-shaped operand
it applies to was never extracted. The raw scan carries its own glob-word check for
exactly this reason: no masking is needed first (an extglob or bracket pattern
contains no whitespace of its own, so it isolates as its own word on a plain split),
but the modes have to be read from THIS SAME raw text — a mode detected from the outer
command and not threaded through would silently narrow the check back to unmodified
glob semantics. Mode detection itself is quote-normalized first, for the same reason
the container match is: `ext""glob` is `extglob` once bash tokenizes it, and a regex
comparing the raw text alone read the option as absent.

One class is handled differently on principle: a substitution embedded between two
adjacent quoted string literals joined by `+` — a common concatenation idiom shared by
several interpreters Kiro Crew spawns payloads through — is reconstructed explicitly,
because the alternative is genuinely unbounded (parsing an arbitrary interpreter's full
expression grammar has no natural stopping point). This is the deliberate line: a
finite, well-known idiom gets a targeted fix; an interpreter's general grammar does
not, and the gap is why the sandbox mount protection above is the floor rather than
this scan.

### A declaration builtin's own flags hid the assignment a second time

Finding 31 widened `_SIMPLE_ASSIGNMENT_RE` to tolerate a declaration builtin
(`export`, `declare`, `local`, `readonly`, `typeset`) between the statement
boundary and `NAME=value`, so `export H=$HOME/.kiro/crewXXXX; ...` is
recognized as the SAME assignment `H=$HOME/.kiro/crewXXXX` is. But
`declare -x H=$HOME/.kiro/crewXXXX; ...` still slipped past (GPT review):
the widened regex still expected `H=` to follow the builtin word IMMEDIATELY,
and `-x ` sitting in between defeated the match the same way the missing
declaration word itself did — the fix closed one obfuscation and left the
builtin's OWN option flags (`-x`, `-xr`, `-p`, `-i`, ...) as an identical
second one. Widened again to tolerate any number of `-flag` groups between
the builtin and the assignment.

### A doubled separator defeated the container-rename check specifically

The Pass 1b separator-collapse retry (`_separator_collapsed_variants`, #6350)
reruns the sensitive-path matcher, the trust-root extraction check, and the
relative-traversal matcher over every separator-collapsed spelling of a
command — closing the gap where Win32 collapses a repeated separator run
(`%LOCALAPPDATA%\\kiro-cli` opens what `%LOCALAPPDATA%\kiro-cli` names) but
the raw patterns spell only one separator. The container-naming check
(`_names_unreplaceable_container_raw`) was the FOURTH pass-1 matcher and was
never added to that retry loop, despite the comment directly above it already
claiming "ALL THREE pass-1 checks are repeated" (GPT review) — a doubled
interior separator (`mv $HOME\.kiro\\crew /tmp/x`, collapsing to the exact
container on Win32) named the container in a spelling this scan's raw-text
patterns never wrote, matched no branch at all, and the unobfuscated
single-backslash form's own refusal gave no hint the doubled form slipped
through. Added to the retry loop with the same `_is_bare_trust_root_read`
exoneration the original check applies, checked against the collapsed
spelling for consistency with the other three re-checks in the same loop.

### A second extglob group left raw syntax where a component was expected

Finding 28 (`_extglob_alternative_readings`) enumerates each alternative of a
multi-alternative extglob group as its own exact, non-vague reading, so
`@(foo|SomeRepo)` is caught when `SomeRepo` is the ancestor even though `foo`
is not — but it was bounded to the FIRST group found, on the theory that the
widened `.*`/`*` reading covers additional groups defensively. It does not
(GPT review, second pass): `/opt/@(foo|company)/@(bar|dept)` against
`KIROCREW_HOME=/opt/company/dept/crewdata` left the SECOND group's raw
`@(bar|dept)` text sitting in every reading the first group's own expansion
produced (`/opt/company/@(bar|dept)`), and `_components_could_match` does not
itself understand extglob syntax — none of those readings ever structurally
matched the ancestor. The fully-widened reading (`/opt/*/*`) DID structurally
match, but was exempted as a vague widening (a "small, known set" of
alternatives) — which stopped being an accurate description the moment a
SECOND independent choice was folded in: two 2-alternative groups is a set of
four, not one.

Every group is now expanded TOGETHER, as the cartesian product of each
group's own alternatives, bounded to `_MAX_EXTGLOB_ALTERNATIVE_COMBINATIONS`
(64) total combinations. When the product would exceed that bound, NO
readings are enumerated (a PARTIAL enumeration would silently under-cover the
combinations it left out — the same silent-truncation failure this module
refuses everywhere else it has a budget) and the plain-widened reading loses
its vague-widening exemption instead: "provably a small set, checked
exhaustively" is exactly the property that stopped holding, so a structural
match against that reading now fails closed rather than being waved through.

**A group with a MIX of exact and glob-shaped alternatives was reported as
fully enumerated once the glob-shaped ones were dropped — they should never
have counted toward "exhaustive" at all (GPT review, third pass).** An
alternative that is itself glob-shaped (`comp*` inside `@(foo|comp*)`) is
filtered out of that group's own alternative list, correctly — it is not one
exact string either. But filtering it out is different from ACCOUNTING for
it: the surviving exact alternatives (`foo`) still got enumerated and
`overflowed` still came back `False`, exactly as if the group had genuinely
been `@(foo)` alone. `@(foo|comp*)` against `KIROCREW_HOME=/opt/company/dept/
crewdata` enumerated only `/opt/foo`, reported success, and the widened
reading kept ITS vague-widening exemption on the strength of that false
signal — even though `comp*` can also equal the ancestor `company`, and
nothing ever checked it. `mv /opt/@(foo|comp*) /tmp/x` relocated the
ancestor.

`overflowed` is now set the moment ANY alternative anywhere — in any group —
could not be enumerated exactly, independent of whether OTHER alternatives
in the same or a different group could be. The exact alternatives that WERE
found are still returned alongside it (`foo` is a genuine reading and stays
useful for exact matches), but the caller now withholds the vague-widening
exemption for this token exactly as if the whole enumeration had overflowed
the combination budget above — the two failure shapes get the identical
fail-closed treatment, because both mean the same thing to a caller deciding
whether to trust "this group's full alternative set has been checked."

### `$PWD`/`$OLDPWD`/`~+`/`~-`/`$(pwd)` named a `cd` target the segment walk already knew

The NORMALIZER pass's `cd`-tracking segment walk (`_check_sensitive_via_
normalizer`) already records where a preceding `cd` moved to (`base_dirs`) and
what it moved FROM (`prev_bases`, restored by `cd -`), and resolves an
ordinary relative operand against those tracked bases. `$PWD` never went
through that resolution at all: it is not an ordinary variable this scanner's
assignment tracking can resolve — `$PWD` is set by the SHELL itself on every
`cd`, never by the command's own text — so `_expand_known_vars`'s "unassigned
→ leave literal" rule left it as literal text `$PWD`, which starts with `$`
rather than `/` or `~` and so was never even recognized as path-like.
`cd ~; mv "$PWD/.kiro/crew" /tmp/x` matched no branch, even though `base_dirs`
already held exactly the directory `$PWD` names (GPT review). The same held
for `${PWD}`, `~+` (bash's own "current directory" tilde form), `$OLDPWD`/
`${OLDPWD}`/`~-` (the previous directory), and `$(pwd)`/`` `pwd` `` (the
command-substitution spelling of the same thing).

Two different fixes for two different reasons the text stays unresolved:

- **The four literal forms** (`$PWD`, `${PWD}`, `~+`, and their OLDPWD/`~-`
  counterparts) are recognized directly in the operand loop
  (`_pwd_alias_readings`): a token starting with one of these five spellings
  gets one EXTRA reading per tracked base, substituting the alias for the base
  the same way an ordinary relative operand resolves against it — added
  alongside the existing readings, so nothing already recognized is narrowed.
- **`$(pwd)`/`` `pwd` `` never reaches the operand loop as literal text at
  all** — command substitutions are masked to numbered placeholders
  (`_mask_substitutions_valued`) BEFORE segment-splitting even runs, and the
  general vouching function for what a masked substitution's placeholder
  might mean (`_substitution_path_guess`) explicitly does NOT guess for
  `$(pwd)`: its own docstring names it as an example that "ends on a word
  that is not a path, and gets no guess at all" — a bare command name is not
  itself a path, and that function has no access to the segment walk's
  tracked state to know what `pwd` would actually print. Fixed by threading
  the current tracked base into the masking call as an explicit `pwd_value`,
  used only when a substitution's WHOLE body is `pwd` (optionally `-L`/`-P`).

**That first `$(pwd)` fix used only the FIRST tracked base — provably not
enough, and GPT's own second-pass PoC showed why (GPT review, round 3).**
`D=x; cd ${D:+$HOME}; mv "$(pwd)/.kiro/crew" /tmp/x` still went unrecognized.
An operator-form `cd` target produces MULTIPLE readings in `_expansion_
readings`, in this order: the naive "value" reading (`${D:+$HOME}` read as if
it evaluated to `D`'s own value, `x` — wrong for `:+` semantics, kept anyway
per that function's own "resolving to the recorded value catches one bypass,
leaving it literal catches the other" reasoning), then the unresolved-literal
reading (home-hypothesis-resolved to the real `$HOME` path), then the
extracted-operand reading (`$HOME`, ALSO home-hypothesis-resolved to the same
real path, deduplicated against the previous one). `base_dirs[0]` -- what the
first `$(pwd)` fix read -- is the `x`-derived value from the FIRST reading,
not the real `$HOME` path sitting two slots later in the same list. Using
only the first base is exactly the same class of narrowing the literal
`$PWD`/`~+` forms were already fixed to avoid.

Fixed by tracking WHICH masked placeholder names are `$(pwd)`-shaped
(`_mask_substitutions_valued` now returns that set alongside its value map)
and, in the operand loop, generating one EXTRA reading per tracked base for
each such placeholder (`_pwd_placeholder_readings`) — the identical
one-reading-per-base treatment the literal forms already get, applied to the
masked spelling instead of literal text. `values[name]` still holds only the
first base (used by the ordinary `_expansion_readings` substitution path),
but the extra per-base readings now cover the rest, so no single incorrect
tracked base can hide a real one sitting later in `base_dirs`.

**Two additional hardening changes rode along with this fix, applied
proactively rather than confirmed against a directly-reproduced failure** —
Windows CI flagged the literal `~+`/`~-` tests specifically (not `$PWD`/
`$OLDPWD`/`$(pwd)`/`` `pwd` ``, which passed) after this round's push, and the
mechanism could not be fully pinned without direct Windows access. Both
changes are independently defensible regardless of whether either is the
precise cause:

- `_pwd_alias_readings`'s substitution now joins the base and the operand's
  tail through `os.path.join` on the SPLIT tail, instead of raw string
  concatenation — the identical separator-mixing class finding 42 already
  fixed for `_sensitive_file_placeholders`. `is_unreplaceable_container`'s own
  `_candidate_forms` already normalizes either spelling to the same
  `casefold`+`normpath` form before comparing, so this alone was verified NOT
  to change whether a match succeeds — kept anyway as the correct, established
  idiom rather than relying on a downstream normalization step to paper over
  an avoidable mixed-separator intermediate.
- The RAW, unexpandable alias text (`~+/.kiro/crew` itself, before
  substitution) is no longer checked ALONGSIDE the resolved per-base readings
  when a token IS alias-shaped — REPLACED rather than merely supplemented. The
  alias regex anchors at the token's start and cannot half-match, so the raw
  spelling can never independently name anything real: `os.path.expanduser`
  either leaves it unchanged (POSIX; harmless but useless) or, for `~+`/`~-`
  specifically, misinterprets the `+`/`-` as a username character it then
  looks up (Windows' pure-Python `ntpath.expanduser` does this WITHOUT
  verifying the user exists first, unlike POSIX's `pwd.getpwnam` lookup, which
  fails safely). Checking that reading added no detection value on any
  platform, so removing it costs nothing and closes off one more unknown as a
  possible contributor.

**Neither hardening change was the cause.** A follow-up Windows CI run showed
the identical `~+`/`~-` failures unchanged after both landed, which ruled out
both hypotheses above and meant the actual mechanism lived somewhere neither
change touched. Tracing the full path from raw command text to
`_pwd_alias_readings` — rather than continuing to patch at the same layer —
found it: `normalize_shell_command`, the shared tokenizer `is_sensitive_
bash_command`'s normalizer pass calls BEFORE `_pwd_alias_readings` ever runs,
has its own, older, unconditional tilde-expansion step (`if token.startswith
("~"): token = os.path.expanduser(token)`). `os.path.expanduser` does not
implement `~+`/`~-` at all — it treats the `+`/`-` as the first character of
a USERNAME (`~user` syntax) instead. On POSIX that lookup fails
(`pwd.getpwnam` finds no user literally named `+`) and the token is left
unchanged, harmlessly — which is exactly why the local suite, running on
POSIX, could not reproduce the failure. `ntpath.expanduser`'s simpler
heuristic does not verify the "user" exists first, though, so on Windows it
silently constructs a WRONG sibling-directory path — mangling `~+`/`~-`
inside `normalize_shell_command` itself, before `_pwd_alias_readings`
downstream ever saw the original token. `$PWD`/`${PWD}`/`$OLDPWD`/`${OLDPWD}`/
`$(pwd)` do not start with `~` and so never entered this step at all, which
is exactly the asymmetry Windows CI showed: those four forms passed from the
first round, while only the two tilde spellings kept failing across both
prior fix attempts.

Fixed at the actual source: `normalize_shell_command`'s tilde-expansion step
now excludes any token `_PWD_ALIAS_RE` or `_OLDPWD_ALIAS_RE` matches, leaving
`~+`/`~-` untouched through tokenization so `_pwd_alias_readings` sees the
original alias text and resolves it against the segment walk's own tracked
`cd` bases, same as every other alias form. This is a Windows-only bug in a
POSIX-only-testable local environment: it cannot be revert-verified red/green
outside Windows CI itself, so confidence here rests on tracing the data flow
and on `ntpath`'s own (POSIX-importable) pure-Python logic confirming the
mechanism directly, not on a local red/green cycle.

### An operator-selected `TMPDIR` is unprotected when sandboxing is off

`_is_system_tmp_root`'s exemption in `security.py`'s own ancestor walk
(`_custom_home_ancestors_uncached`) explicitly defers the cost of protecting
an operator-selected `TMPDIR` to `sandbox.py`'s own ancestor walk — see
`_is_system_tmp_root`'s own docstring: "a caller that needs to distinguish an
operator-selected root takes the cost on its own side instead — `sandbox.py`'s
ancestor walk protects one unconditionally, since doing so there is free."
That deferral is accurate only while OS-level sandboxing actually runs:
`sandbox.py`'s ancestor walk exists only as part of building the
namespace-sandbox launcher script, so with `agent.sandbox="off"` it never
executes at all (GPT review). A `KIROCREW_HOME` placed directly under an
operator-selected `TMPDIR` then had no protection from EITHER layer — the
command gate exempted it as shared temp space on the assumption that
`sandbox.py` covers it, and `sandbox.py` never ran to cover it.

Fixed by conditioning the exemption itself on
`sandbox.configured_sandbox_mode()`, read once per call inside the same
TTL-cached function (mirroring the accepted-cost reasoning already documented
there for its `os.path.realpath()` call): with sandboxing off, the walk no
longer stops at the temp root, so it is protected as an ordinary ancestor —
exactly as a non-temp-rooted custom home already is. This narrowing does not
repeat the mistake a prior, reverted round made trying to solve a related
problem: that attempt keyed on "is `TMPDIR` set", which macOS's launchd sets
unconditionally for every process regardless of operator intent, so the
exclusion fired even for the platform's own ambient default and broke
ordinary temp-directory commands on `Gateway Tests (macOS)`. `agent.sandbox`
carries no such per-platform ambient default — it ships `"auto"` and becomes
`"off"` only through an explicit, binary operator opt-out already used
throughout `sandbox.py` for identical policy branching (the `SECURITY:
agent.sandbox='off'` warnings logged at spawn time) — so honoring it here
cannot reintroduce that regression, and no test in this project's own suite
sets `agent.sandbox="off"`.

### An operator-form assignment reconstructs the container unmasked

`p=${HOME:0}; mv "$p/.kiro/crew" /tmp/x` names neither `$HOME` nor `.kiro` in
a form any `is_unreplaceable_container` call site resolved (GPT review).
`${HOME:0}` is bash's substring expansion (offset 0 — the whole value,
unchanged), an OPERATOR-form reference `normalize_shell_command`'s own
`$HOME`/`~` expansion cannot touch (it only expands bare `$HOME`/`${HOME}`),
and the segment walk's assignment tracking cannot resolve it either — the
assigned VALUE is the operator expression itself, not a literal path. Every
one of the three `is_unreplaceable_container(cand)` call sites in
`_check_sensitive_via_normalizer` (Pass A's flat token scan, the segment
walk's own candidate check, and its cd-relative join) checked only the
literal candidate text, which still read `$p/.kiro/crew` — never equal to the
container.

Fixed the same way an unresolved variable already gets a second look for
CREDENTIAL paths (`_sensitive_under_unresolved_var`, which already calls
`_unresolved_home_hypothesis`): a new `_unresolved_container_hypothesis`
tests whether the unresolved part could name a home directory, applied at
all three call sites. Deliberately its own wrapper rather than a direct call
to `_unresolved_home_hypothesis`: doing so naively regressed a bare
`$PWD`/`$OLDPWD` with no tracked `cd` base — an already-decided case (see the
`$PWD`/`$OLDPWD`/`~+`/`~-`/`$(pwd)` section above) that must keep reading as
an ordinary unresolved literal, since `_pwd_alias_readings` is what already
owns resolving those two forms correctly once a base IS tracked, and the
generic hypothesis test has no concept of a tracked base at all.
`_unresolved_container_hypothesis` therefore returns `None` outright for any
token `_PWD_ALIAS_RE`/`_OLDPWD_ALIAS_RE` matches, leaving every other
unresolved expansion (`$V`, `${V:0}`, `$(...)`) to reach the generic test
unchanged.

### A quoted assignment value truncated at its first space

`H=" $HOME/.kiro/crewXXXX"; mv ${H%XXXX} /tmp/stash` (GPT review) starts the
assigned value with a literal space inside double quotes. `_SIMPLE_ASSIGNMENT_RE`
captured that value with `(\S+)` — deliberately crude, matching this scanner's
own convention of comparing text rather than re-parsing it — but `\S+` stops at
the FIRST whitespace character, so the capture ended after the opening `"`
itself, losing `$HOME/.kiro/crewXXXX` entirely. `_assignment_feeds_container_via_operator`
never saw the real value, so its substring check against `H`'s later
operator-form reference (`${H%XXXX}`, the same shape the section above
addresses) never fired.

The value is not lost to bash the way it was to the matcher. A double-quoted
string keeps its leading space as literal content, and the command references
`$H` UNQUOTED — `${H%XXXX}` has no surrounding quotes — so bash's own
word-splitting on the expanded value treats that leading space as an IFS
separator and discards it, leaving `$HOME/.kiro/crew` as the sole `mv`
argument. The relocation is real; only the detector was blind to it.

Fixed by widening the value alternation to a double-quoted span, a
single-quoted span, or a run of bare non-whitespace-non-quote characters,
repeated (`(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'])+`) — a quoted token is now
captured whole, whitespace included, rather than truncated at its first
space. The quotes themselves are captured too, deliberately left unstripped:
`_assignment_feeds_container_via_operator`'s containment check matches a
substring anywhere inside the (normalized) value, so a surrounding quote
character never prevents a real match, and correctly stripping quotes
(nesting, escapes, adjacent concatenated quoted/bare runs) would be exactly
the kind of re-parsing this scanner avoids everywhere else.

### A dangling symlink bypasses both keystone-file protections at once

The dangling-symlink refusal above (`islink(target) and isfile(target)`)
follows the same `isfile()` blind spot finding 41 already closed for an
ordinary symlink-to-a-real-file, but for a DIFFERENT input: `isfile()`
answers False for a symlink whose target does not exist — a DANGLING
symlink — exactly as it does for a genuinely absent path, since `isfile`
resolves through the link and asks whether what it points to is a regular
file (GPT review). That let a dangling symlink at a registered keystone-file
location (`computer_use.json`, GPT's own PoC) fall through BOTH protections
at once, not just the one already fixed:

- The absent-file placeholder loop's own `open(target, "x")` (`O_CREAT |
  O_EXCL`) silently no-ops on ANY symlink, dangling or not — POSIX
  guarantees `O_EXCL` against a symlink fails closed with `EEXIST`
  regardless of the link's target, and the loop's `except OSError: pass`
  swallows exactly that failure without noticing it.
- The symlink refusal itself never fired either, since `isfile(target)` is
  False for a dangling link the same way it is for an absent path.

Neither mechanism touched it, leaving the link — and whatever a later write
inside the sandboxed subprocess makes it point at — completely unprotected.
Fixed by widening the refusal from `islink(target) and isfile(target)` to
`islink(target) and not isdir(target)`: a symlinked directory (the real,
unrelated `~/.aws`/`~/.ssh` dotfile-management shape the original `isfile`
gate was scoped to exclude) still passes with `isdir(target)` True, but a
dangling symlink — neither a verified file nor a verified directory — now
fails closed on the same "cannot confirm this is a directory" reasoning
already applied to a file-pointing symlink.

### Brace zero-padding measured the wrong endpoint's width

"Does this range zero-pad at all" and "how wide" are separate questions.
Bash decides the first from whether EITHER endpoint begins with `0`, but
answers the second from the WIDER of the two endpoints regardless of which
one carries the leading zero — `{01..100}` pads to width 3 (`001`...`100`),
taken from `100`, not from `01`. The width computation answered both
questions from only the endpoints that themselves began with `0` (Opus
review): `{01..100}` correctly decided to pad (`01` qualifies), but then
measured width from `01` alone (2), producing `01`...`100` with `099` never
generated. `KIROCREW_HOME=/opt/node099/crew` reached by `mv /opt/node{01..
100} /tmp/x` therefore relocated the ancestor without this scan ever
emitting the candidate (`node099`) that would have matched it — bash's own
output and this scan's candidate set disagreed on what a zero-padded,
mixed-width range even contains.

Fixed by separating the two questions explicitly: `qualifies` (does either
endpoint start with `0`) decides WHETHER to pad; `width` is `max(len(start_
digits), len(end_digits))` whenever it does, regardless of which endpoint is
the wider one. `{01..100}` itself is not a usable regression test on its
own: 100 terms exceeds `_MAX_BRACE_EXPANSIONS` (64), so both the buggy and
the fixed code already refuse it via the unrelated overflow-fails-closed
path (`is_unreplaceable_container` treats the overflow sentinel as "assume
the worst"), masking the width bug entirely. A stepped range
(`{01..999..300}`) reaches the identical narrow-then-wide shape in only 4
terms, under the budget, isolating the width computation as the only thing
that can change the verdict. Verified against the `braceexpand` package (a
widely-used, faithful reimplementation of bash's own brace-expansion
algorithm) across a dozen zero-padding shapes, not against a real bash: this
project's own dev/CI hosts ship bash 3.2, which predates brace zero-padding
entirely and could not have caught this bug — or verified the fix — by
hand-testing either.

### `eval` can reconstruct a protected path from text no check ever sees

`H=HOME; eval "mv \$$H/.kiro/crew /tmp/stash && ln -s /tmp/evil \$$H/.kiro/
crew"` spells neither `$HOME` nor `.kiro` anywhere in the command AS WRITTEN
(GPT review). Inside the double-quoted string, `\$` is an escaped dollar sign
that survives the OUTER shell's own expansion pass as a literal `$`
character, while the immediately-following `$H` IS expanded normally — to
`HOME`, the value `H=HOME` assigned. The OUTER shell therefore hands `eval`
the literal text `$HOME/.kiro/crew`, and `eval` runs THAT as a brand-new
command. This is bash's classic "variable variables" idiom (indirect
variable expansion), and every check in this scan — the raw container match,
the sensitive-credential regex, the normalizer's operand walk — reads the
command AS WRITTEN, never the string `eval` reconstructs from it. The same
trick bypassed credential access too: `H=HOME; eval "cat \$$H/.aws/
credentials"` was equally unrecognized.

Computing what an arbitrary indirection resolves to would mean tracking
every assignment AND re-implementing `eval`'s own re-parse of a
dynamically-constructed string — the same unbounded direction every other
"refuse outright" case in this module already declines. Instead, `eval`
combined ANYWHERE in the command with the escaped-dollar-then-variable shape
(`_EVAL_INDIRECT_VAR_RE`) is refused outright, checked FIRST — before every
other Pass 1 check — since the danger is not specific to the container or to
credentials, it is that the command's REAL target is unknowable from its
written text at all. The co-occurrence itself, not the precise resolved
value, is the signal: `eval` paired with this escape shape has no ordinary,
benign use worth preserving, the same reasoning
`_assignment_feeds_container_via_operator` already applies to an
unresolvable operator-form reference.

**A braced spelling of the identical trick was still unrecognized** (GPT
review, second pass): `H=HOME; eval "mv \${$H}/.kiro/crew ..."` builds the
same reconstructed text through a different sequence of literal characters —
`\$` (escaped, survives as a literal `$`) + `{` (literal) + `$H` (expanded to
`HOME`) + `}` (literal) — which the outer shell assembles into `${HOME}`,
and `eval` re-parses exactly like bare `$HOME`. `_EVAL_INDIRECT_VAR_RE`
matched only the unbraced form (an escaped dollar directly followed by a
variable name); the `{` sitting between the escaped dollar and the variable
name defeated it. Widened to `\\\$\{?\$[A-Za-z_][A-Za-z0-9_]*\}?` — an
escaped dollar, optional opening brace, the variable reference, optional
closing brace — covering both spellings with the same co-occurrence
reasoning as before.

### Python's implicit adjacent-literal concatenation was unrecognized

`_concatenated_literal_candidates` reconstructs the common `'a' + 'b'`
string-concatenation idiom shared by the interpreters Kiro Crew spawns
payloads through, continuing a run of quoted literals only when the text
between two of them (after masking substitutions) is exactly `+`. Python
also concatenates two ADJACENT string literals with nothing but whitespace
between them — no operator at all — and this is at least as common an
idiom as the explicit `+` form: `os.path.expanduser('~/.k' 'iro/crew')` is
ordinary Python, identical in effect to `'~/.k' + 'iro/crew'` (GPT review,
second pass). The `between.strip() == "+"` check answered `False` for a
whitespace-only gap (an empty string after stripping, not `"+"`), so the
run stopped after the first literal and `~/.kiro/crew` was never
reconstructed — `expanduser('~/.k' 'iro/crew')` relocated the container
without this scan ever seeing a candidate that named it.

Fixed by widening the continuation test to `between.strip() in ("+", "")`:
an empty (whitespace-only) gap now continues the run exactly like an
explicit `+` does. The risk this reopens — concatenating two UNRELATED
quoted arguments that happen to sit near each other with only a space
between them, "manufacturing" a path nobody wrote — is bounded by what
comes next: the reconstructed candidate still has to pass `_could_name`
(does it actually look like the container or a sensitive path), so an
ordinary multi-argument command (`mv 'foo' 'bar'`) is unaffected unless its
adjacent literals genuinely concatenate into something sensitive, which no
realistic command does by accident.

### macOS's Seatbelt profile left the governance profiles directory renamable

`_build_seatbelt_profile` emits `(deny file-read* (subpath ...))` for every
entry in `_STRICT_DIRS`/`_STANDARD_DIRS` — hiding CONTENT — but only adds the
matching `(deny file-write* (subpath ...))` for the two directories
`_is_policy_cache_dir`/`_is_voice_runtime_dir` recognize as execution/trust
roots. `.kiro/crew/profiles`, the per-surface governance profiles directory,
was not one of them (GPT review), even though its own comment already
establishes it as the identical class of trust root as the policy cache:
"the ceiling is deliberately not the agent's to read." On Linux this
asymmetry does not exist — bind-mounting an empty directory over the target
IS the hiding mechanism, and a mount point cannot be renamed (`EBUSY`), so
every hidden directory gets anti-rename protection for free. Seatbelt's
declarative deny rules have no such bundling: hiding content and denying
writes are two independent rules, and only the ones actually emitted apply.
Without the write deny, a sandboxed `os.rename(".../profiles", ...)` makes
the directory disappear, and whatever on this host hot-reloads governance
profiles could read that absence as "no restrictions configured" rather
than failing closed — the same shape of gap the container self-bind and the
policy-cache write-deny already close for their own trust roots, just not
yet extended to this one.

Fixed with a new `_is_profiles_dir` (matched on the leaf name, mirroring
`_is_policy_cache_dir`, so it holds for every spelling the dir lists carry
without a filesystem call on the spawn path) added alongside the other two
in the write-deny condition. Deliberately NOT widened to every entry in the
dir lists — `.aws` and similar credential directories legitimately refresh
their own state, and turning that into a hard failure is the same separate
decision `_is_policy_cache_dir`'s own comment already declines to make.

### The "for free" premise above was wrong for a directory that starts out symlinked

The fix above states the Linux side needs nothing extra because "every
hidden directory gets anti-rename protection for free" once bind-mounted.
That is true only when the mount actually lands ON the sensitive path
(GPT review). `_build_launcher_script`'s `SENSITIVE_DIRS` loop mounts an
empty directory over each entry with `if os.path.isdir(target):` — and
`isdir()` follows a symlink, reporting True for one pointing at a real
directory. `mount(2)` resolves the same way `open()` does: the bind lands
on the directory the symlink points to, hiding ITS content for the
session, while the symlink's own directory-entry slot — a distinct
filesystem object in its parent directory — is never touched and stays
exactly as replaceable as before. A sandboxed script can `rm
~/.kiro/crew/profiles && ln -s /tmp/evil ~/.kiro/crew/profiles`, and
whatever hot-reloads governance profiles next reads the attacker's
directory as if it were the real one — a directory-level version of the
identical bypass the container's own `UNRENAMABLE_DIRS` loop already
guards against with an `islink` check before its bind, for the exact
same reason (see that loop's own comment, a few sections up).

Fixed the same way: a new `TRUST_ROOT_DIRS` list — computed in
`_build_launcher_script` from `hidden_dirs` filtered through the same
three predicates (`_is_policy_cache_dir`, `_is_voice_runtime_dir`,
`_is_profiles_dir`) the macOS write-deny condition above already uses —
is embedded into the launcher, and the `SENSITIVE_DIRS` loop refuses the
spawn when a target is BOTH a symlink AND a `TRUST_ROOT_DIRS` member,
mirroring `UNRENAMABLE_DIRS`' own refusal message. Scoped to those three
leaves rather than every `SENSITIVE_DIRS` entry for the identical reason
the macOS fix already gives: `.aws`, `.gnupg`, `.docker`, and similar
credential directories are legitimately symlinked by dotfile managers
(stow, chezmoi), and aborting every sandboxed spawn for an operator with
one of those symlinked would be an availability regression with no
compensating security gain — the write-deny/bind-refuse reasoning these
three directories exist for never applied to ordinary credentials.

### An absent `security_policy.json` is unprotected on Linux — accepted, not fixed

`security_policy.json` has no entry in `_KEYSTONE_FILE_ABSENT_PLACEHOLDERS`
by design: any present content either fails a version check or raises,
unlike absence's clean, ungoverned boot. When it is absent, the
placeholder-creation loop skips it and the bind-mount loop has nothing to
mount over, so the sandboxed subprocess has ordinary write access to
`.kiro/crew/` (its own working data home) and nothing stops it creating the
file directly (GPT review). On the next boot, `platform/policy_distribution
.py` resolves policy tiers env var → central distribution → companion
bundle → `<data-home>/security_policy.json` → ungoverned, first-present
winning — so a planted, malformed file at this last on-disk tier gets read
and crashes with `PlatformCompositionError`, by the SAME design that makes
every other tier "fail like any other tier" on bad content at boot.

Investigated rather than fixed. A loader-side fix (tolerate invalid
tier-4 content) would be a real regression: an operator whose legitimately
configured tier-4 file is corrupted by disk failure or a partial write
would silently widen to ungoverned exactly where failing closed is
correct — this project does not treat "we could not tell" as "run
unbounded" anywhere else either. A sandbox-side fix (materialize a
placeholder to protect the absent path) reopens the identical bypass: Linux
`mount(2)` requires an existing target, so any placeholder created to bind
over persists on disk after the sandbox session ends and becomes the real
file the next boot reads — the same crash, just introduced by the fix. And
refusing to spawn the sandbox whenever this file happens to be absent is
also unsafe as a blanket rule: absence is the normal, correct state for any
fleet using env-var or central-distribution governance (which wins by
precedence regardless of what tier 4 contains), and refusing unconditionally
would break those deployments outright. A correctly-scoped refusal would
need to know whether the upstream tiers are already satisfied — visibility
`sandbox.py`'s synchronous launcher-construction path does not have today,
and building it safely is a larger, separate change. Recorded via
`/ai-review override` rather than left silently unaddressed.

### Audited internal carve-out

`safe_read_file_internal(read_id)` permits a small hardcoded allowlist of
system-internal reads of otherwise-sensitive paths. It re-verifies
`is_sensitive_path()` (a path that has stopped being sensitive means the
configuration drifted, so it refuses rather than silently widening), opens with
`O_NOFOLLOW` on a single descriptor, SEL-audits every outcome, and fails closed:
a `success` whose audit cannot be persisted returns `None`, because a log warning
is not an audit event and the carve-out's validity depends on every successful
read producing one. `read_id` is never constructed from untrusted input.

## Layer 2: Command gate (`security.py` + `hooks.py`)

Three independent checks run on every shell-bearing tool call, each against the
model's title **and** the raw command:

- **Denied-command rules** (`BUILTIN_DENIED_RULES`): first-class
  `DeniedCommandRule` records (stable `id`, regex `pattern`, `category`,
  human `description`) covering credential exfiltration, destructive
  infrastructure and data operations, publishing to a protected branch, and
  self-protection (the agent disabling Kiro Crew or minting its own dashboard
  token). Default-ON, user-configurable from Settings → Security; the governance
  `commands` scope is the enterprise force-pin that cannot be opted out of
  (tightest-wins).
- **Sensitive-bash detection** (`is_sensitive_bash_command`): refuses commands
  that read credential paths, reach the cloud metadata endpoint under any IP
  encoding, or dump credential environment variables. Regex fast-path first, then
  a tokenizing pass that resolves quoting, empty-string concatenation, `$HOME`
  and tilde before routing path-like tokens through `is_sensitive_path()`.
- **Exfiltration shapes** (`audit_bash_exfiltration`): data-egress and
  reverse-shell forms, narrowly scoped so it can be a hard deny at the gate
  without blocking benign local commands.

`SUSPICIOUS_BASH_PATTERNS` / `audit_bash_command()` are a **separate, advisory**
surface: they back the `kirocrew security audit` history scan and the posture
count, and are not enforced at the gate. The gate enforces the narrower checks
above. Conflating the two is the historical error here, so keep the distinction
explicit.

Rule-table contents, the two-pass whole-string/per-segment evaluation, the
verb-anchored git-publish detector, the protected-branch and force-push
semantics, the argv-structural self-protection floor, and the linear-time
ReDoS-safe matcher are all specified in
[`security.md` § Denied Commands](../system-specs/modules/security.md).

Every denial emits a `deny_event` SEL record; an exception grant emits
`deny_exception` fail-closed (if the audit cannot be written, the exception is not
granted).

## Layer 3: Input validation (`validation.py`)

Every MCP tool call is checked against a declarative `FieldSpec` + `ToolSchema`
before the handler sees it: NFC unicode normalization with hidden-character
stripping (control, format, private-use and surrogate code points, preserving
`\n`/`\r`/`\t`), enum allow-lists, regex patterns for identifiers, range checks,
unknown-field rejection, tiered length caps (`MAX_TOOL_NAME_LEN` 256,
`MAX_SHORT_STRING` 500, `MAX_MEDIUM_STRING` 5 000, `MAX_LONG_STRING` 50 000, and
the field-specific `MAX_CRON_MESSAGE` 50 000 for the cron `message` — a task
prompt, enforced on the MCP schemas, both REST cron endpoints, and the
`CronService` persistence chokepoint), and
response truncation at `MAX_RESPONSE_LEN` (100 000 chars) so unbounded tool output
cannot be a DoS vector.

The schema count is a runtime-derived posture value (`tool_schemas` in
`security_posture.py`), surfaced in Settings; it is not stated here.

## Layer 4: Output redaction

Redaction runs at **every** boundary where agent-derived output reaches a human or
an external service. The authoritative list is the `redaction_paths` control in
`security_posture.py`, whose registry is kept honest by an omission-detecting
test: every redactor call site in the package must be either a registered sink or
on an explicit non-egress allowlist, so a new egress path cannot be added without
someone deciding which bucket it belongs in.

- `redact_credentials()` recognizes credential families in plaintext and
  base64-encoded form (it decodes base64-looking chunks and re-checks the decoded
  bytes), including cloud access keys and secrets, private-key headers, chat and
  forge tokens, package-registry tokens, and database connection URIs carrying
  embedded credentials. Key-value matching is JSON-aware and value classes are
  bounded at JSON structural delimiters, so a match in compact JSON cannot
  over-capture and mask the next credential.
- `redact_exfiltration_urls()` / `scan_exfiltration_urls()` are
  **domain-agnostic**: they flag the payload, not the destination. A credential in
  a URL is an unconditional floor; long query strings, base64 blobs and heavy
  URL-encoding are heuristics. A flagged URL is replaced with a redaction marker.
- `redact()` composes both in order for a single call site.
- `StreamRedactor` handles the case per-chunk redaction structurally cannot: a
  credential split across a streaming boundary, where neither fragment matches on
  its own. It withholds the trailing run of credential-class characters until a
  non-credential terminator arrives or the stream ends, emitting only the
  confirmed-safe prefix, with a bounded hold-back so latency and memory stay
  bounded on a pathologically long unbroken run.

Two ordering rules generalize beyond this layer and are worth stating once:
**screen after decode, not before** (screening an encoded form and then writing
the decoded value makes every escape a bypass), and **redact before truncate**
(truncating first can slice a credential so neither fragment matches).

## Layer 5: Audit (SEL)

The Security Event Log is append-only and HMAC-chained, so tampering is
detectable rather than merely discouraged; `GET /api/sel/verify` reports the
chain's integrity and `GET /api/sel/events` returns recent records. Every event
carries a `source` inferred from the session key (`sel._infer_source`, published
via `sel.audit_sources()`), and a call site may stamp a more specific source, so
the inferred set is a floor rather than a total.

The audit log is itself a user-facing, *durable* surface: string fields are
redacted before they are written or forwarded. A leak into the SEL persists in a
way a response body does not. See
[`../system-specs/modules/sel.md`](../system-specs/modules/sel.md).

Several security decisions are audit-or-deny rather than best-effort: a sandbox
delegation, a deny exception, and an internal sensitive read all refuse to
proceed when their audit cannot be written. The one documented exception is the
nested-sandbox passthrough, which has no safe alternative (the kernel denies a
re-wrap by design) and would otherwise couple every in-sandbox spawn to SEL
health; it logs loudly and proceeds, still confined by the outer boundary.

## Governance: the enterprise ceiling

Governance is a second, orthogonal axis to the layers above:
`effective = POLICY ∩ PROFILE`, tightest-wins. Level 1 POLICY is loaded at boot
from the trust-root path and is never merged from `config.json`; Level 2 PROFILE
is a per-surface, narrow-only ceiling. Both are enforced at Kiro Crew's own
PreToolUse gate, which is what lets a policy deny a tool or MCP call **even when
the `kiro-cli` agent config granted it**.

Architecturally the important properties are that the evaluator is
scope-name-agnostic (adding a scope is a `SCOPE_CATALOG` data change, never an
evaluator edit), that governance runs before the auto-approve path so it cannot be
bypassed by a trust decision, and that its trust-root files are on the keystone
floor so the agent cannot read or rewrite its own ceiling. Archetypes,
composition algebra, scope boundaries and the signed-policy authenticity model
are in [`../system-specs/modules/governance.md`](../system-specs/modules/governance.md).

**Computer use is deliberately not governed.** It is one operator opt-in on a
keystone file, with refusals enforced in band on the tool dispatch path rather
than at the fail-open PreToolUse gate. See
[`../system-specs/modules/computer-use.md`](../system-specs/modules/computer-use.md).

## Authentication and authorization

### Dashboard requests

HMAC-signed tokens with dual expiry: a short link-click window
(`LINK_WINDOW_SECS`, 5 minutes) and a longer cookie session TTL capped at
`MAX_SESSION_TTL_SECS` (20 hours), IP-pinned on first use. Every request requires
a valid token, with a small set of deliberate, secret-free exceptions: static
assets and same-origin vendored JS (the SPA and sandboxed-iframe bootstrap), the
local-bootstrap endpoints that authenticate with a loopback peer plus a
filesystem secret, the three liveness probes, and self-authenticating external
webhooks that validate their own signatures.

Supporting controls: per-session logout via a cookie nonce recorded in a revoked
set (so one session is revoked without affecting others); app tokens confined to
their manifest-declared API allowlist, deny-by-default even on internal paths; a
path-restricted refresh cookie so the app self-recovers after access-cookie
expiry; and the `Secure` cookie attribute when the gateway is behind TLS.

### CSRF and DNS rebinding are two different barriers

Origin/Referer validation covers state-changing methods. The `Host`-header
allowlist runs on **every** method, because GET-based exfiltration is the
DNS-rebinding payload, and it deliberately does **not** trust a loopback
`request.remote`: a rebound request *is* loopback at the socket while its `Host`
carries the attacker's domain. Both derive their allowlists from one source
(`check_origin` / `check_host` over `allowed_origins`, plus a canonical-loopback
floor from `build_allowed_hosts`) so the two layers cannot drift. Host validation
is deny-by-default (an empty `allowed_origins` denies, never fails open) and
rejects with 403 plus a SEL event. The sole exemption is the three liveness
probes, whose handlers compensate by stripping build-identity fields unless the
caller is direct-local, so a rebound request learns only the liveness bit.

### Slack

Deny-by-default owner lock: socket mode refuses to connect without an owner id,
and event handling rejects messages when it is missing. Trust and YOLO buttons
are DM-gated and suppressed in group channels, with a non-owner receiving an
ephemeral rejection.

Slack messages are processed **inline** and reach the agent directly, gated by
`is_allowed_user` and the workspace origin check. There is no challenge-and-
redirect interception; `send_channel_challenge()` does not exist and must not be
reintroduced on an upstream sync. The generic signed-token helpers remain and
back the explicit `/kirocrew dashboard` link command.

Enterprise Grid validation is a two-layer, **default-open** control: with no
`slack.allowed_enterprise_ids` configured, every reachable workspace is allowed.
`auth.test` caches the workspace `team_id` (plus the org-level enterprise id on
Grid) at startup, and each inbound event's `team` is compared against the cached
allowlist. A governance `channels.posture` policy is the agent-unweakenable
ceiling on top of the operator-editable config allowlist. A corrupt `config.json`
does not reopen the control: because `KiroCrewConfig.load()` degrades a torn
config to defaults rather than raising, the module positively detects that case (a
config file that exists but does not parse) and fails CLOSED, keeping the allowlist
enforced and admitting NO origin -- not even the just-validated workspace,
since which authenticated workspace is allowed is exactly what the unreadable
allowlist would have decided -- rather than reverting to default-open.

### Interactive trust escalation

Dashboard tool approvals offer four decisions, in widening scope: `trust_command`
(this exact command, session-scoped), `trust_base` (the base command glob, e.g.
`ls *`, plus the bare binary, session-scoped), `trust_reads` (read-only bash for
the slot), and `trust` (all tools for the slot). `yolo` is the global escalation.

The security-relevant property is what the pattern is derived from: the **actual
command in `tool_input`**, not the model-authored display title. Trust patterns
are per-slot fnmatch globs; a multi-command title yields one pattern per binary.
Trust never outranks a deny: the gate's deny and governance checks run before the
trust and auto-approve paths.

### Auto-approve (YOLO) has one duration

Auto-approve is time-bounded by a **single** duration shared by every ad-hoc
surface (`agent.yolo_duration`, default `6h`, hard ceiling 24 h, or
`until_shutdown` for an in-memory grant with no timed expiry that a restart
clears). There are deliberately no per-surface TTLs: giving the same grant a
different lifetime depending on which surface enabled it is unpredictable for the
operator without buying any security.

The duration is resolved from live config at activation time, so a value saved in
Settings applies to the next activation without a restart. A 5-minute grace
window after expiry allows renewal instead of a fresh activation.

The one non-expiring grant is `agent.dangerously_skip_permissions` in
operator-owned config: a standing instruction, deliberately config-file-only with
no dashboard toggle, re-established and re-audited on every startup. An
enterprise policy can deny it via the `yolo_duration` scope's `permanent` member,
which downgrades it to the ordinary ad-hoc duration.

Every lifecycle transition (`activate`, `renew`, `expired`, `deactivate`) is
SEL-audited. The transitions that create or extend auto-approval authority
(`activate`, `activate_scoped`, `renew`) audit **fail-closed**: the SEL event is
written before the grant is committed, and if the write fails the grant (or the
extension) is refused — auto-approval authority never exists without an audit
record. Fleet-visibility endpoints expose the live state
(`/api/status` reports `yolo_active` / `yolo_expires_at`;
`/api/admin/compliance/yolo-status` carries the full override status).

## Context isolation

Observe-mode channel history is gated on sender authorization: only owner or
allowlisted messages are recorded, so a non-owner cannot influence LLM context by
posting into shared channel traffic. Slack thread-root content, which any thread
participant can author, is injection-screened and dropped on match, and surviving
text is framed as explicitly untrusted data with a SEL event on every drop.

## Frontend

| Control | Implementation |
|---|---|
| XSS prevention | DOMPurify on all rendered HTML content |
| Safe DOM APIs | `createElement` + `textContent` for error fallbacks |
| Mermaid | `securityLevel: 'strict'` (iframe sandbox), so an injected diagram cannot execute JS |
| No `innerHTML` | React text children rather than HTML string construction |
| No regex linkification | React elements via `.split()` |

## Credential file handling

`load_credentials()` tightens `~/.kiro/crew/.env` to owner-only mode at load time
and warns if it cannot (for example when the file is owned by another user). The
file is also on the keystone read+write block, so the agent cannot reach it
through any tool or shell form regardless of its filesystem mode: owner-only
permissions do not isolate another process running as the same uid, which is
exactly the agent's situation.

---

## Known gaps

Each gap below is a real residual, stated with why the obvious fix is not already
in place.

**No network egress control by default.** The sandbox hides credential files but
does not restrict outbound network access, so a compromised agent can post
non-credential data to an arbitrary host. Redaction blunts the credential case
and the `network.egress` governance scope can bound hosts where a policy is
configured, but there is no default-on egress boundary. A network namespace
(Linux) or host firewall rules with a trusted-destination allowlist would close
it.

**Regex and tokenizer command matching is not a shell parser.** The command gate
normalizes aggressively (quoting, empty-string concatenation, `$HOME`/tilde,
mid-word empty substitutions, local assignment inlining, literal interpreter
payloads) and adds argv-structural floors for the self-protection rules, which
closes the well-known evasion families. It is still not a bash AST: a payload
assembled at runtime (string concatenation, a base64 blob, an indirect `eval
"$CMD"`) contains nothing for a pattern to find. The un-disableable guarantee for
the signing credential is the keystone path floor, which these rules do not
replace.

**No audit dashboard.** SEL events are queryable over the API
(`/api/sel/events`, `/api/sel/verify`) but there is no UI to browse, filter or
alert on them, so tamper detection and anomaly spotting are manual.

**No in-agent sandbox-escape detection.** The gateway decides fail-closed whether
a backend exists before spawning, but nothing verifies from *inside* the agent
process that confinement actually took effect (for example by attempting to read
a canary that should be hidden). A confinement that loads but does not enforce
would not be noticed.

**Base64 credential detection has a floor.** Only base64 chunks at or above the
minimum length are decoded and re-checked, so a shorter encoded fragment, or one
split across messages, can pass. Cross-message correlation and entropy-based
detection would extend it.

**Write protection covers Kiro Crew's own trust root, not the user's shell
startup files.** Credential directories and the keystone are read+write blocked,
and `config.json` plus the migration marker are write-blocked, but ordinary
persistence targets such as `~/.bashrc` or `~/.zshrc` are not: they are not
credential stores, and blocking the whole home directory would make the agent
useless for its normal work. An agent write there is therefore a real persistence
vector, mitigated only by the approval gate and the destructive-command rules.

**Resource ceilings depend on the platform.** The cgroup v2 scope that bounds
fork bombs and memory balloons requires Linux with cgroup delegation; where it is
unavailable (macOS, older Linux, no user session) it is a no-op with a loud
warning and only the file-descriptor limit applies. See
[`resource-protection.md`](resource-protection.md).
