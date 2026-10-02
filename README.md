# Lantern

A native security assessment agent for small Linux hosts. Lantern runs a
scoped, fully audited assessment from the command line: a six-role agent
(orchestrator, planner, researcher, coder, pentester, reflector) drives
in-process tools and an allowlist of host binaries, keeps everything it
learns in SQLite, and writes a deterministic markdown report.

> **New here?** [GETTING_STARTED.md](GETTING_STARTED.md) walks from a fresh
> clone to a written report - build, setup, the first run, and what the
> numbers at the end of a run mean.

> ### ⚠️ Safety
>
> **Only assess systems you are authorised to test.** Everything Lantern does
> is bounded by the `--scope` you declare; targets outside it are refused
> before any socket opens, and that refusal reads a target's own DNS-resolved
> address, not just the name you typed (see [Scope](#scope-hostnames-cidr-and-dns-drift)).
>
> **There is no shell.** Tools take structured arguments and run via `execve`
> argument arrays only - never `sh -c`, never string-built commands.
>
> **Active testing is opt-in twice.** `sqlmap`, `hydra`, `nuclei`, `amass`,
> `msfconsole` and `john` refuse to run unless the flow was started with
> `--offensive` *and* the target is in scope. A natural-language instruction
> (`lantern ask`/`chat`) can narrow that gate, never grant it.
>
> **Everything is audited.** Binary, full argv, cwd, exit code, duration,
> output size, resolved IP - every invocation lands in SQLite and a JSONL
> trace file before the next one runs.

---

## What this is, and isn't

A CLI, not a service: one process per invocation, one SQLite database as the
single source of truth, no listener, no web UI. Isolation on the host side
comes from an executable allowlist, a cleared environment, a restricted
`PATH`, `setrlimit` (CPU/AS/FSIZE/NOFILE/NPROC/CORE), wall-clock timeouts,
output caps and a per-flow working directory - not a VM or container
runtime. Lantern carries no exploit code or payload generator of its own:
anything intrusive is a host tool, allowlisted, gated behind `--offensive`,
matched against `--scope`, and recorded argv-for-argv.

It was built for, and is sized against, one reference machine class:

| | |
|---|---|
| CPU / RAM | 4 × Cortex-A76 @ 2.4 GHz aarch64, 7.87 GiB + 2 GiB zram swap |
| Disk | 30.79 GB ext4, 20% kept free as a floor `lantern setup` won't cross |
| OS | Debian 13 (trixie), kernel 6.18, glibc 2.41 |
| GPU | none (display-only) - inference is always external |

That table is a reference point, not a hardcoded assumption: `lantern
doctor` re-measures whatever device it's actually on, and concurrency /
child-memory rlimits scale with it (`DeviceProfile::detect` reads live
cores/RAM/swap) - down toward 1 task/256 MB on something smaller, up on a
bigger box, no rebuild required. An explicit `LANTERN_CONCURRENCY` or
`LANTERN_CHILD_MEM_MB` still wins over the derived value.

## Quick start

```sh
make && make test                 # release build; 360+ tests, no API spend
./target/release/lantern setup    # provider, model, key, then every host tool
lantern doctor                    # confirm what's configured

lantern run --dry-run --target example.com --scope example.com   # free, scripted
lantern run --target example.com --scope "example.com, 104.20.23.154/32"
lantern ask --target example.com --scope example.com \
  --prompt "Check TLS and headers, defensive only"                # words, not flags
lantern chat                      # the same flow, conversational
```

Requires Rust 1.85+ and OpenSSL development headers (`libssl-dev` on
Debian/Ubuntu); TLS uses the system OpenSSL (`native-tls`) to keep the build
free of `cmake`/`ring`/a bundled `libclang`.

### Every command

```sh
lantern setup                                   # provider, model, key, then every host tool
lantern doctor                                   # device, budget, integrations, tools
lantern run --target T --scope S                 # full pipeline, read-only
lantern run --target T --scope S --offensive     # ...gated tools may now run
lantern run --target T --scope S --dry-run       # same pipeline, zero model calls
lantern run --target T --scope S --roles researcher,pentester   # pick the roles
lantern run --target T --scope S --interactive   # a role may stop and ask you
lantern ask --target T --scope S --prompt "..."  # instruct in words, not flags
lantern ask --target T --scope S --file framework.md --dry-run  # a whole framework, free to preview
lantern chat                                     # the same flow, conversational: / commands, Esc aborts
lantern flows                                    # id, status, target, created, scope
lantern report <flow-id> [--out report.md]        # markdown, from the database, no model call
lantern delete <flow-id> --yes                     # permanently remove one flow, every row and file
lantern tools                                     # every tool and its gate
lantern gc                                        # retention: compress, prune, vacuum
lantern queue add --target T --scope S [--offensive] [--dry-run]  # schedule, don't run yet
lantern queue list [--status pending|running|done|failed]
lantern queue remove <id>                         # a running job must finish first
lantern daemon [--interval SECS]                  # poll the queue, run jobs unattended
```

## Architecture

```
lantern-cli     CLI: setup / doctor / run / ask / chat / flows / report / tools / gc
lantern-agent   roles, prompts, the tool-calling loop, intent parsing, reports
lantern-tools   native tools, sandboxed host exec, bounded network fetches, the tool registry
lantern-llm     chat clients (OpenAI-compatible, Anthropic), embeddings, context window
lantern-core    config, device profiling, SQLite storage, budget, scope, retention
```

Every crate is deterministic where it can be: findings are extracted and
validated rather than trusted verbatim, reports render straight from SQLite
with no model call, and `--dry-run` runs the whole pipeline against a
scripted provider so the loop is testable without spending anything.

## Roles and delegation: a fixed pipeline with one bounded escape hatch

Six roles run in a set order on every flow - `orchestrator → planner →
researcher → coder → pentester → reflector` - each a bounded tool-calling
loop against the configured model. The pipeline itself is fixed: no role
adds, removes, or reorders another role, and that is what makes a run's
cost and shape predictable before you start it (`--dry-run` prints the
exact token/tool-call estimate).

Within that fixed pipeline, researcher/coder/pentester can call
`delegate_task` to spin off one bounded sub-investigation and get back a
condensed answer - Lantern's answer to Claude Code's `Task` tool or
opencode's agent types, deliberately narrower than either:

- A delegated sub-task's tools can only be a subset of the **calling role's
  own** tool list - it can never reach a tool the parent didn't already have,
  so delegation cannot be used to smuggle in capability.
- It shares the parent's scope and `--offensive` grant exactly; it cannot
  exceed either (it is still just a role, running through the same
  `Registry::execute` choke point as every other tool call).
- **It cannot delegate again.** `delegate_task` is never in a delegated
  sub-task's own tool list - not a depth counter that could have an off-by-
  one, an absent capability - enforced twice over: the sub-task's model
  literally has no schema for the tool, and the one place a tool call named
  `delegate_task` could still be handled refuses it by name instead.
- Capped at 5 steps per call, 10 total across every `delegate_task` call one
  role makes in its own turn - a role cannot multiply its own step budget
  unboundedly by calling it repeatedly.
- Fully audited the same way everything else is: a delegation skips
  `Registry::execute` (the real work needs to call the model, which
  `lantern-tools` has no access to), which is also where every other tool
  call's database event gets written - so it logs its own start/finish
  event the same way, rather than existing only in the live progress
  stream. Its own nested tool calls still go through `Registry::execute`
  normally and are audited exactly like any other call. Token/cost counters
  already aggregate correctly since a delegated call is still just a call
  to `agent.chat()`.
- Visible in `chat` as its own nested block, not flattened into the
  parent's own tool-call list: `↳ researcher delegates: "..."`, its tool
  calls indented one level further than a direct call, `↳ ✓ sub-task done -
  N step(s)` closing the block - the same thing Claude Code's `Task` tool or
  opencode's sub-agent panels show, inline rather than collapsible (this
  viewport is six rows, not a scrollback pane).

What this is not: open-ended, recursive, or dynamic task decomposition. A
role decides to delegate one sub-question; it does not restructure the
pipeline, spawn an unbounded tree of agents, or hand a sub-task anything
it couldn't already reach itself. `Registry::defs_for` still scopes every
role (and every delegated sub-task) to a fixed, auditable tool list (below)
rather than "whatever the model decides to reach for."

| Role | Does | Tools |
|---|---|---|
| orchestrator | turns the objective into a short written plan | - |
| planner | reorders the plan by risk and effort | - |
| researcher | passive recon: DNS, TLS, headers, WHOIS, ports, subdomains, WAF/CDN, leaked secrets, API schemas, cloud/container exposure, web search | `dns_lookup`, `subdomain_enum`, `tls_inspect`, `http_probe`, `waf_fingerprint`, `secret_scan`, `api_schema_scan`, `graphql_introspect`, `cloud_bucket_check`, `container_expose_check`, `whois`, `port_scan`, `web_search`, `memory_search`, `memory_store`, `ask_operator`, `plan_patch`, `delegate_task` |
| coder | reproducible check steps and remediation advice | `memory_search`, `memory_store`, `ask_operator`, `plan_patch`, `code_run`, `secret_scan`, `delegate_task` |
| pentester | active verification inside scope | `port_scan`, `dir_bruteforce`, `host_nmap`, `host_nikto`, `host_tcpdump`, `host_testssl`, `host_gobuster`, `host_sqlmap`\*, `host_hydra`\*, `host_nuclei`\*, `host_msfconsole`\*, `host_john`\*, `host_amass`\*, `host_getuserspns`\*, `host_getnpusers`\*, `host_crackmapexec`\*, `host_bloodhound`\*, `host_kubehunter`\*, `cloud_bucket_check`, `container_expose_check`, `waf_fingerprint`, `secret_scan`, `memory_search`, `memory_store`, `ask_operator`, `plan_patch`, `delegate_task` |
| reflector | judges evidence quality and confidence of every finding | `memory_search`, `ask_operator`, `plan_patch` |

\* requires `--offensive`.

Every tool call passes through one choke point (`Registry::execute`), which
applies the scope check and the `--offensive` gate *before* the tool body
runs - and a role's own request to the model only ever carries the schemas
for the tools in its own column above, not the full registry, so `YOUR
TOOLS:` in the system prompt is an enforced fact, not just a hint.

`lantern ask`/`chat` layer natural language on top without touching that
structure: a detailed prompt can earn a role extra steps within its own
budget (`step_boosts`, capped) and shape *how* a role is told to think (an
`EngagementProfile` - web app, API, internal/AD, cloud, network -
contributes a short addendum naming the right taxonomy and what this
toolset honestly cannot check yet), but it never adds a role, removes one,
or grants a tool a role doesn't already have.

## Tools

**In-process** (no child process, so no host-tool sandboxing applies - these
are plain Rust): `port_scan`, `dns_lookup`, `subdomain_enum` (passive
certificate-transparency lookup via crt.sh - never touches target
infrastructure; candidates are labelled in/out of scope, never auto-added to
it), `http_probe`, `tls_inspect`, `waf_fingerprint` (CDN/WAF signature match
from one ordinary response - no payloads; run this before trusting a
zero-finding `sqlmap`/`nuclei` scan, since a silent WAF block looks
identical to a clean application), `secret_scan` (regex match for
credential-shaped strings in text another tool already captured - no network
access of its own, every match reported masked), `whois`, `dir_bruteforce`
(built-in 2,419-entry wordlist), `web_search` (DuckDuckGo by default, a
search API if configured; `mode: vulnerability` surfaces matching NVD CVEs
first), `memory_search`, `memory_store`, `ask_operator` (`--interactive`
only), `plan_patch`, `delegate_task` (one bounded sub-investigation for
researcher/coder/pentester - see
[Roles and delegation](#roles-and-delegation-a-fixed-pipeline-with-one-bounded-escape-hatch)).

**One sandboxed child, not a host binary**: `code_run` - a single Python
script (standard library only) behind `bwrap`, empty network namespace,
read-only filesystem except the flow's own directory. It computes; it can
never reach a target.

**Allowlisted host binaries**, provisioned by `lantern setup`:

| Binary | What it does | Gate |
|---|---|---|
| `nmap` | connect scan, ports and services | scope |
| `nikto` | web-server misconfiguration scan | scope |
| `tcpdump` | capture N packets to a pcap artifact | scope |
| `testssl.sh` | deep TLS/cipher inspection (downgrade, Heartbleed-class checks) | scope |
| `gobuster` | faster, multi-threaded directory/file discovery | scope |
| `sqlmap` | SQL-injection testing against a URL | `--offensive` + scope |
| `hydra` | password spraying against one service | `--offensive` + scope |
| `nuclei` | CVE template scan, JSONL findings | `--offensive` + scope |
| `amass` | active subdomain enumeration (active DNS, optional `-brute`) | `--offensive` + scope |
| `msfconsole` | one module (`use`/`set`/`run`\|`check`), one argv element | `--offensive` + scope |
| `john` | offline cracking: wordlist, optional rules, then `--show` | `--offensive` |

Each adapter builds its own argument array - the model never supplies raw
flags, so it cannot smuggle `-oN /etc/passwd` through. A few specifics worth
knowing: `msfconsole`'s session string is assembled from a validated module
path and character-filtered option values, so no option can chain a second
console command; `nuclei` runs with `-no-interactsh` so no callback leaves
for a third party; `gobuster` falls back to the same bundled wordlist
`dir_bruteforce` uses when no custom one is given; `tcpdump` alone holds
`cap_net_raw,cap_net_admin` and the `lantern` binary itself stays
unprivileged; `testssl.sh` ships no compiled binary - the kernel's shebang
handling runs it via `execve`, the same shape as `python3 script.py` in
`code_run`, with no shell interpolation anywhere in that path.

## Scope: hostnames, CIDR, and DNS drift

A target can be a host name, an IP, or a CIDR range, and the scope check
treats each correctly rather than as interchangeable strings:

- **A CIDR target is checked as the whole range it names**, not just its
  base address. A scope of `10.0.0.0/24` rejects a target of `10.0.0.0/8`
  even though `10.0.0.0` itself sits inside the declared range - the
  target's own prefix must be at least as narrow as the scope entry's.
- **A hostname is resolved immediately before the command runs**, and the
  resolved address is written to the audit row (`resolved_ips`, visible in
  `lantern report`) regardless of outcome. When `--scope` itself names IP
  ranges - the configuration this doc recommends - a hostname resolving
  outside every one of them is refused instead of silently scanned, catching
  DNS drift or rebinding between scope declaration and execution. A scope
  defined purely by hostname skips this extra check; there is nothing to
  compare the resolved address against.
- This narrows, but cannot fully close, the gap between Lantern's check and
  a host tool's own connection: `nmap`/`nikto`/`sqlmap` resolve DNS
  internally, and pinning a third-party binary to one address would break
  vhost-based tools that need the hostname intact for `Host`/SNI. Put the
  resolved IP in `--scope` alongside the hostname for the tightest guarantee.

## Concurrency and multiple sessions

Yes - more than one `lantern run`/`ask`/`chat` can point at the same data
root at once (SQLite runs in WAL, which is built for exactly this), and
that's an ordinary thing to happen, not an edge case: a scheduled job and an
operator both touching the same box, or two operators on a shared machine.
A few things worth knowing about what that does and doesn't guarantee:

- **Flow and task IDs are collision-safe across processes.** Each id mixes a
  millisecond timestamp, the OS pid, and a per-process counter
  (`lantern_core::ids`) specifically so two processes starting in the same
  millisecond - the normal case for "launch two assessments at once" - can
  never produce the same flow id. (An earlier version of this scheme mixed
  in only the timestamp and a counter that reset to zero on every process
  start, which could collide outright; fixed and covered by a direct test.)
- **The disk budget is best-effort across processes, not exact.** Each
  process tracks its own view of how much of `LANTERN_DATA_CAP_MB` is used,
  seeded from the on-disk size at its own startup; two long-running
  concurrent flows writing heavily will not see each other's writes in
  real time. This is a soft cap on space, not a security boundary - the
  actual hard limits (`RLIMIT_AS` per child, bounded HTTP reads, the disk
  floor `lantern setup` itself enforces) are per-process already and
  unaffected. `lantern gc`/the floor check resync against the real
  filesystem and will catch up.
- **No single-instance lock exists or is needed.** There is nothing to
  coordinate: each flow is independent, scope-checked and budgeted on its
  own, and the database is the only shared state.

For unattended/scheduled assessment, `lantern queue add` plus `lantern
daemon` is the same story at the level of whole flows instead of one
process: `lantern queue add` from any invocation and a long-running
`lantern daemon` elsewhere coordinate through nothing but that same shared
SQLite file (`Db::claim_next_queued` is a locked SELECT immediately
followed by an UPDATE, so two daemons against the same data root can never
claim the same job twice). The daemon is a polling loop, not a server: it
opens no listening socket, and SIGINT/SIGTERM both let the job in progress
finish before it exits.

### Session lifecycle: create, read, update, delete

A "session" in `lantern chat` is its live settings (`target`, `scope`,
`roles`, `offensive`, `dry-run`, `steps`) plus whatever flows you run under
them; each flow it starts is its own row in the database, independent of
the session that created it. Full lifecycle control, all from inside the
TUI - no need to quit and relaunch to start over, and no file-system
spelunking to clean up after yourself:

| | command | does |
|---|---|---|
| **Create** | `/new` | resets the session's settings to blank - a fresh target, scope, roles, offensive grant and step cap, ready for the next engagement. Nothing is deleted: every flow already run stays exactly as it was. |
| **Read** | `/flows` | lists recorded flows (id, status, target) - the same data `lantern flows` shows outside chat. |
| **Update** | `/target`, `/scope`, `/roles`, `/offensive`, `/dry-run`, `/steps` | change one setting of the live session; each takes effect on the next instruction. |
| **Delete** | `/delete <flow-id> yes` | **permanently** removes one flow: every database row across every table in one transaction (`Db::delete_flow`), its artifact files, its working directory, its rendered report. Typing just `/delete <flow-id>` shows what would be destroyed and refuses - the `yes` has to be deliberate, there is no retention window behind this the way there is behind `lantern gc`'s scheduled pruning. |

The same delete is available outside chat as `lantern delete <flow-id>
--yes` (same confirmation requirement, same transaction). Deleting one flow
never touches another - verified directly, not just assumed, in both the
database layer (`delete_flow`'s own tests) and live, under a real terminal,
with two flows from two separate `/new` sessions and only one deleted.

What Lantern does **not** currently do: run as a long-lived daemon or
systemd service, or expose a queue/scheduler of its own. It is a CLI
invoked per assessment. A systemd timer calling `lantern ask` on a schedule
works today with no code changes; a first-class `lantern daemon` with its
own queue is a reasonable next build if continuous/scheduled assessment
matters to how your firm runs it.

## Detectability and the agent's own attack surface

**Can the target detect it?** Partially, by design on the recon side:
`http_probe`, `waf_fingerprint`, `dir_bruteforce` and `web_search` send
`User-Agent: lantern/<version>` by default - honest, self-identifying
traffic, consistent with the audit-everything stance everywhere else, and
useful when an engagement wants a defender's SOC to be able to attribute the
traffic. Override it with `LANTERN_USER_AGENT` when blending in is itself
part of the test. What overriding it does **not** buy: `nikto` is loud and
signature-heavy by its own design, `nmap`'s scan timing is its own
fingerprint, `sqlmap` already runs with `--random-agent`. No header changes
any of that.

**Does it leave traces?** Yes, extensively, on the machine running it - the
entire audit value proposition, not a flaw. Every command (binary, full
argv, exit code, resolved IP) lands in `lantern.db` and a JSONL trace file;
artifacts and reports are plain files under the data root. Anyone with read
access to that box can reconstruct the whole engagement. Traces *on the
target* are a property of the allowlisted tools themselves - identical to
running `nmap`/`nikto`/`sqlmap` by hand.

**Is the agent itself secure, or just a vulnerable pentester?** The
adversarial direction worth checking is a hostile or compromised *target*
attacking the agent back through its own response parsing. Every in-process
network fetch (`http_probe`, `waf_fingerprint`, `dir_bruteforce`,
`subdomain_enum`, `web_search`) is bounded at the read itself
(`lantern_tools::fetch`) rather than truncated after the whole response was
already buffered - none of that code runs under the `RLIMIT_AS` that
protects a sandboxed host-tool child, so a target serving a multi-gigabyte
or endlessly chunked response cannot force unbounded memory growth in the
process itself. Verified against a real oversized response from a local TCP
listener in `fetch.rs`'s tests, not just reasoned about. The same bound
applies, at a more generous cap, to the model-provider responses
(`lantern_llm::fetch`) and the setup wizard's model-list fetch - a lower-risk
tier (operator-configured, not the target), bounded anyway rather than left
as the one unbounded read in the codebase.

## Setup

`lantern setup` is the whole installation story: on a fresh machine it asks
the three questions only you can answer and provisions what's missing; on an
already-configured machine it reports everything present and changes
nothing. Re-running it is free.

**The model half** comes first (it's one API call; the tools can take
minutes). It lists providers, fetches the endpoint's own live model list,
reads the key with input hidden, and spends one real completion verifying it
works before storing it - a key that cannot reach its endpoint is not worth
saving. With no terminal attached (a script, CI), it takes whatever the
environment already provides, checks it once, and stores it - or, if the
environment can't finish the job, writes nothing and names the one variable
that would.

| file | contents |
|---|---|
| `~/.config/lantern/credentials` | the key, mode `0600` - never in the database, logs, traces or reports |
| `~/.config/lantern/config.json` | provider, model, endpoint - no secret |

**The tools**, in order, each through the same audited executor (argv
arrays, no shell, rlimits, timeouts, one row per command) - and each step
degrades to a printed warning rather than blocking when it can't proceed
(no `sudo`, no `apt`, offline mode, wrong architecture):

1. **distribution packages** - `nmap`, `sqlmap`, `nikto`, `hydra`, `tcpdump`,
   `bubblewrap`, `gobuster`, `amass` via `apt-get`, only what's missing, only
   with passwordless `sudo`.
2. **john (jumbo)**, built from source - 328 formats instead of a
   distribution package's handful.
3. **nuclei** - the release binary for the host's architecture.
4. **the CVE template set** - a sparse clone (4,348 files, 33 MB), not the
   whole template repository.
5. **testssl.sh** - a shallow clone (it ships no compiled binary).
6. **the exploit framework** - signing key, signed repository, ~754 MB
   package.

Everything lands in your package manager's own directories or in
`~/.local/share/lantern-tools/` (deliberately **outside** the capped data
root, so provisioning never competes with logs/artifacts/findings for
space). The last step links the binary into `~/.local/bin` - a symlink, so a
rebuild never leaves a stale copy behind, and when that directory isn't on
`PATH` yet the export line is printed rather than written into your shell
startup files behind your back.

**Installing packages is something `lantern setup` does - never `run`,
`ask`, or `chat`.** Those three only check what's already resolvable on the
restricted `PATH`; nothing in the assessment path ever shells out to a
package manager.

## Environment variables

Every value has a default; nothing here is required. Precedence is
**environment > `~/.config/lantern` files (written by the wizard) >
preset**.

| Variable | Default | Purpose |
|---|---|---|
| `LANTERN_LLM_PROVIDER` | `deepseek` | preset id, see [Providers](#providers) |
| `LANTERN_LLM_API_KEY` | - | generation key (each preset also names its own var) |
| `LANTERN_LLM_BASE_URL` / `LANTERN_LLM_MODEL` | preset's | endpoint / model override |
| `LANTERN_CONFIG_DIR` | `~/.config/lantern` | where `config.json`/`credentials` live |
| `LANTERN_LLM_TIMEOUT_SECS` / `LANTERN_LLM_MAX_TOKENS` | `90` / `2000` | per-request timeout / reply cap |
| `OLLAMA_URL` / `OLLAMA_EMBED_MODEL` | `http://127.0.0.1:11434` / `nomic-embed-text` | local embeddings |
| `LANTERN_EMBED` | `1` | `0` = keyword-only memory search |
| `LANTERN_DATA_ROOT` | `~/.local/share/lantern` | single data root |
| `LANTERN_DATA_CAP_MB` / `LANTERN_LOG_CAP_MB` | `1280` / `200` | hard caps |
| `LANTERN_DISK_FLOOR_PERCENT` | `20` | free space `lantern setup` won't cross |
| `LANTERN_CONCURRENCY` | device-derived (`3` on the reference device) | parallel task budget |
| `LANTERN_TASK_TIMEOUT_SECS` | `120` | per-task wall clock |
| `LANTERN_MAX_OUTPUT_BYTES` | `2097152` | captured output cap per command |
| `LANTERN_CHILD_MEM_MB` / `LANTERN_CHILD_CPU_SECS` | device-derived (`512`) / `60` | child rlimits |
| `LANTERN_PATH` | `/usr/local/bin:/usr/bin:/bin` + tools dirs | restricted `PATH` for children |
| `LANTERN_ALLOWLIST` | `nmap,sqlmap,nikto,hydra,tcpdump,nuclei,msfconsole,john,bwrap,testssl.sh,gobuster,amass` | host binaries that may run |
| `LANTERN_TOOLS_DIR` | `~/.local/share/lantern-tools` | where `setup` provisions tools |
| `LANTERN_NUCLEI_TEMPLATES` | `<tools-dir>/share/nuclei-templates` | template set for `host_nuclei` |
| `LANTERN_OPERATOR_ANSWER` | - | reply for `ask_operator` with no terminal |
| `LANTERN_OFFENSIVE` | `0` | same as `--offensive` |
| `LANTERN_OFFLINE` | `0` | no external calls at all |
| `LANTERN_USER_AGENT` | `lantern/<version>` | target-facing `User-Agent`, see [Detectability](#detectability-and-the-agents-own-attack-surface) |
| `LANTERN_TOKEN_BUDGET` | `6000` | context budget per role |
| `LANTERN_PRICE_INPUT_PER_MTOK` / `_OUTPUT_PER_MTOK` | - | USD/M tokens, so a run can print cost |
| `LANTERN_ARTIFACT_DAYS` / `_TRACE_DAYS` / `_LOG_DAYS` | `7` / `14` / `30` | retention |
| `LANTERN_VACUUM_FREE_PERCENT` | `25` | full `VACUUM` threshold |

### Providers

Nine presets and one escape hatch. The wizard shows the endpoint's own model
list when it answers, else falls back to the shortlist below.

| id | endpoint | key variable | default model |
|---|---|---|---|
| `deepseek` | `https://api.deepseek.com` | `DEEPSEEK_API_KEY` | `deepseek-flash` |
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta/openai` | `GEMINI_API_KEY` | `gemini-2.5-flash` |
| `openrouter` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | `deepseek/deepseek-chat` |
| `groq` | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| `mistral` | `https://api.mistral.ai/v1` | `MISTRAL_API_KEY` | `mistral-small-latest` |
| `xai` | `https://api.x.ai/v1` | `XAI_API_KEY` | `grok-4` |
| `ollama` | `http://127.0.0.1:11434/v1` | none (local) | first model it lists |
| `custom` | your own URL | `LANTERN_LLM_API_KEY` (optional) | you name it |

One chat client drives all of them (the preset decides the wire shape -
`anthropic` takes the Messages API, the rest chat completions). A key saved
for one provider is never sent to another. Change provider or model by
re-running `lantern setup`, or override per-run with `LANTERN_LLM_MODEL=...`.

## Data root, memory, and retention

```
~/.local/share/lantern/
├── lantern.db          # flows, tasks, commands, findings, memory (FTS5), events
├── logs/                # rotating text log, size-capped
├── traces/              # JSONL audit trace, pruned by age
├── artifacts/           # raw tool output per flow, gzip-compressed after 7 days
├── flows/<flow-id>/     # per-flow working directory (code_run's one writable path)
└── reports/<flow-id>.md
```

The tools directory lives **outside** this root. Storage rules, in order:
writes refuse before `LANTERN_DATA_CAP_MB`; `lantern setup` alone refuses to
start below the 20% disk floor (it's the only step that downloads/builds
gigabytes - `run`/`ask`/`chat`/`gc` work at any free space); artifacts
gzip after 7 days and delete once compressed; traces prune after 14 days,
logs after 30; SQLite runs WAL with incremental auto-vacuum plus a
conditional full `VACUUM` under the free-space threshold; findings are kept
forever.

Each role's observations are stored with an embedding when Ollama is
available (768-dim `nomic-embed-text`) and searched with a hybrid of FTS5
keyword matching and cosine similarity - keyword-only, automatically, if
Ollama is unreachable. `memory_search` recalls on demand, `memory_store`
writes a note back; a note of kind `guide` lands in a shared namespace that
outlives the engagement, so a lesson learned on one target is read by every
flow after it.

## Roadmap

The five gaps this section used to describe are now built:

- **Internal/Active Directory tooling**: `host_getuserspns` (Kerberoasting),
  `host_getnpusers` (AS-REP Roasting), `host_crackmapexec` (SMB/WinRM/LDAP
  enumeration and credential validation - enumeration only, no execution
  method is ever accepted), and `host_bloodhound` (BloodHound relationship
  collection). All `--offensive`-gated, all provisioned by `lantern setup`.
- **API-aware testing**: `api_schema_scan` parses an OpenAPI/Swagger JSON
  document and reports which endpoints declare no authentication;
  `graphql_introspect` reports whether GraphQL introspection is enabled and,
  if so, the real type/query/mutation surface. Both passive.
- **Cloud posture**: `cloud_bucket_check`, a credential-free outside-in
  check of whether an S3 bucket, Azure Blob container, or GCS bucket allows
  anonymous listing.
- **Container/K8s**: `container_expose_check` (unauthenticated Docker daemon
  API or Kubelet anonymous auth, passive) and `host_kubehunter`
  (kube-hunter active probing, `--offensive`-gated).
- **A real daemon mode**: `lantern queue add/list/remove` plus
  `lantern daemon`, a polling loop against Lantern's own SQLite queue table
  (never a listening socket) that runs jobs through the exact same path
  `lantern run` already uses. See
  [Concurrency and multiple sessions](#concurrency-and-multiple-sessions).

What's still honestly missing: JWT-specific analysis, a structured
OAuth/SAML flow tester, an IAM policy evaluator, and container-escape
testing. `prompts::engagement_addendum` tells the model what it cannot check
for a detected profile, specifically so it says "no tool for that" instead
of narrating a check it never ran.

## License

Apache-2.0
