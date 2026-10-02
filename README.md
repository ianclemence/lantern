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
> before any socket opens (see [Scope](#scope-hostnames-cidr-and-dns-drift)).
>
> **There is no shell.** Tools take structured arguments and run via `execve`
> argument arrays only - never `sh -c`, never string-built commands.
>
> **Active testing is opt-in twice.** `sqlmap`, `hydra`, `nuclei`, `amass`,
> `msfconsole`, `john` and the AD/`kube-hunter` tools refuse to run unless the
> flow was started with `--offensive` *and* the target is in scope. A
> natural-language instruction (`lantern ask`/`chat`) can narrow that gate,
> never grant it.
>
> **Everything is audited.** Binary, full argv, cwd, exit code, duration,
> output size, resolved IP - every invocation lands in SQLite and a JSONL
> trace file before the next one runs.

---

## What this is, and isn't

A CLI, not a service: one process per invocation, one SQLite database as the
single source of truth, no listener, no web UI. The one optional background
process, `lantern daemon`, is a polling loop against that same SQLite file -
it opens no socket of its own (see [Concurrency, sessions, and the
daemon](#concurrency-sessions-and-the-daemon)).

Isolation on the host side comes from an executable allowlist, a cleared
environment, a restricted `PATH`, `setrlimit` (CPU/AS/FSIZE/NOFILE/NPROC/CORE),
wall-clock timeouts, output caps and a per-flow working directory - not a VM
or container runtime. Lantern carries no exploit code or payload generator of
its own: anything intrusive is a host tool, allowlisted, gated behind
`--offensive`, matched against `--scope`, and recorded argv-for-argv.

It was built for, and is sized against, one reference machine class - 4-core
aarch64, ~8 GiB RAM, 30 GB disk - but `lantern doctor` re-measures whatever
device it's actually on and scales concurrency/child-memory rlimits to match
(`DeviceProfile::detect`), down toward 1 task/256 MB on something smaller, up
on a bigger box, no rebuild required. An explicit `LANTERN_CONCURRENCY` or
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

## Setup

`lantern setup` is the whole installation story: on a fresh machine it asks
the three questions only you can answer and provisions what's missing; on an
already-configured machine it reports everything present and changes
nothing. Re-running it is free. **Installing packages is something `setup`
does - never `run`, `ask`, or `chat`**, which only check what's already
resolvable on the restricted `PATH`.

**The model half** comes first (it's one API call; the tools can take
minutes). It lists providers (see [Providers](#providers)), fetches the
endpoint's own live model list, reads the key with input hidden, and spends
one real completion verifying it works before storing it. With no terminal
attached (a script, CI), it takes whatever the environment already provides,
checks it once, and stores it - or, if the environment can't finish the job,
writes nothing and names the one variable that would.

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
3. **nuclei** - the release binary for the host's architecture, plus a
   sparse clone of the CVE template set (4,348 files, 33 MB).
4. **testssl.sh** - a shallow clone (it ships no compiled binary).
5. **the exploit framework** - signing key, signed repository, ~754 MB
   package.
6. **AD/Impacket tooling and kube-hunter** (`GetUserSPNs.py`, `GetNPUsers.py`,
   `crackmapexec`, `bloodhound-python`, `kube-hunter`) - via
   `pip3 install --user`, since none of these ship an exact-named
   distribution package.

Everything lands in your package manager's own directories, in
`~/.local/share/lantern-tools/` (deliberately **outside** the capped data
root), or in `~/.local/bin` (pip's `--user` scripts; the restricted `PATH`
reaches it). The last step also links the `lantern` binary itself into
`~/.local/bin` - a symlink, so a rebuild never leaves a stale copy behind,
and when that directory isn't on `PATH` yet the export line is printed
rather than written into your shell startup files behind your back.

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
lantern-cli     CLI: setup / doctor / run / ask / chat / flows / report / tools / gc / queue / daemon
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
adds, removes, or reorders another role, which is what makes a run's cost
and shape predictable before you start it (`--dry-run` prints the exact
token/tool-call estimate).

Within that fixed pipeline, researcher/coder/pentester can call
`delegate_task` to spin off one bounded sub-investigation and get back a
condensed answer - narrower, deliberately, than Claude Code's `Task` tool or
opencode's agent types:

- A delegated sub-task's tools can only be a subset of the **calling role's
  own** tool list - it can never reach a tool the parent didn't already have.
- It shares the parent's scope and `--offensive` grant exactly, through the
  same `Registry::execute` choke point every tool call goes through.
- **It cannot delegate again** - enforced twice over: the sub-task's model
  has no schema for `delegate_task`, and the one place a call named that
  could still be handled refuses it by name.
- Capped at 5 steps per call, 10 total across every `delegate_task` call one
  role makes in its own turn.
- Fully audited: its own start/finish event is logged the same way every
  other tool call's is, and its nested tool calls go through
  `Registry::execute` normally.
- Visible in `chat` as its own nested block: `↳ researcher delegates: "..."`,
  its tool calls indented one level further, `↳ ✓ sub-task done - N step(s)`
  closing the block.

What this is not: open-ended or recursive task decomposition. A role decides
to delegate one sub-question; it does not restructure the pipeline or hand a
sub-task anything it couldn't already reach itself. `Registry::defs_for`
scopes every role (and every delegated sub-task) to a fixed, auditable tool
list - the one below - rather than "whatever the model decides to reach for."

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
budget (capped), and shape *how* a role is told to think (an
`EngagementProfile` - web app, API, internal/AD, cloud, network -
contributes a short addendum naming the right taxonomy and what this
toolset honestly cannot check yet), but it never adds a role, removes one,
or grants a tool a role doesn't already have.

## Tools

**In-process** (no child process, so no host-tool sandboxing applies - these
are plain Rust): `port_scan`, `dns_lookup`, `subdomain_enum` (passive
certificate-transparency lookup via crt.sh), `http_probe`, `tls_inspect`,
`waf_fingerprint` (CDN/WAF signature match from one ordinary response - run
this before trusting a zero-finding `sqlmap`/`nuclei` scan, since a silent
WAF block looks identical to a clean application), `secret_scan` (regex
match for credential-shaped strings in text another tool already captured),
`api_schema_scan` (parses an OpenAPI/Swagger JSON document, flags endpoints
with no declared authentication), `graphql_introspect` (reports whether
GraphQL introspection is enabled and, if so, the real type/query/mutation
surface), `cloud_bucket_check` (credential-free check of whether an S3/Azure
Blob/GCS bucket allows anonymous listing), `container_expose_check`
(unauthenticated Docker daemon API or Kubelet anonymous auth), `whois`,
`dir_bruteforce` (built-in 2,419-entry wordlist), `web_search` (DuckDuckGo by
default; `mode: vulnerability` surfaces matching NVD CVEs first),
`memory_search`, `memory_store`, `ask_operator` (`--interactive` only),
`plan_patch`, `delegate_task` (see [Roles and
delegation](#roles-and-delegation-a-fixed-pipeline-with-one-bounded-escape-hatch)).

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
| `GetUserSPNs.py` | Kerberoasting - dumps crackable TGS hashes (Impacket) | `--offensive` + scope |
| `GetNPUsers.py` | AS-REP Roasting - dumps crackable hashes (Impacket) | `--offensive` + scope |
| `crackmapexec` | SMB/WinRM/LDAP enumeration and credential validation, read-only modules only | `--offensive` + scope |
| `bloodhound-python` | AD relationship collection for BloodHound | `--offensive` + scope |
| `kube-hunter` | active Kubernetes attack-vector probing | `--offensive` + scope |

Each adapter builds its own argument array - the model never supplies raw
flags, so it cannot smuggle `-oN /etc/passwd` through. A few specifics worth
knowing: `msfconsole`'s session string is assembled from a validated module
path and character-filtered option values, so no option can chain a second
console command; `nuclei` runs with `-no-interactsh` so no callback leaves
for a third party; `crackmapexec`'s `enum_flag` is a closed allowlist of
read-only modules - no execution method (`-x`/`-X`/`--exec-method`) is ever
accepted; `tcpdump` alone holds `cap_net_raw,cap_net_admin` and the `lantern`
binary itself stays unprivileged; `testssl.sh` ships no compiled binary - the
kernel's shebang handling runs it via `execve`, the same shape as
`python3 script.py` in `code_run`, with no shell interpolation anywhere in
that path.

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
  ranges, a hostname resolving outside every one of them is refused instead
  of silently scanned, catching DNS drift or rebinding between scope
  declaration and execution. A scope defined purely by hostname skips this
  extra check; there is nothing to compare the resolved address against.
- This narrows, but cannot fully close, the gap between Lantern's check and
  a host tool's own connection: `nmap`/`nikto`/`sqlmap` resolve DNS
  internally, and pinning a third-party binary to one address would break
  vhost-based tools that need the hostname intact for `Host`/SNI. Put the
  resolved IP in `--scope` alongside the hostname for the tightest guarantee.

## Concurrency, sessions, and the daemon

More than one `lantern run`/`ask`/`chat` can point at the same data root at
once (SQLite runs in WAL, built for exactly this) - a scheduled job and an
operator both touching the same box, or two operators on a shared machine,
is an ordinary thing to happen, not an edge case:

- **Flow and task IDs are collision-safe across processes.** Each id mixes a
  millisecond timestamp, the OS pid, and a per-process counter, so two
  processes starting in the same millisecond can never produce the same
  flow id.
- **The disk budget is best-effort across processes, not exact.** Each
  process tracks its own view of how much of `LANTERN_DATA_CAP_MB` is used,
  seeded at its own startup. This is a soft cap on space, not a security
  boundary - the actual hard limits (`RLIMIT_AS` per child, bounded HTTP
  reads, the disk floor `lantern setup` enforces) are per-process already.
  `lantern gc` resyncs against the real filesystem.
- **No single-instance lock exists or is needed.** Each flow is independent,
  scope-checked and budgeted on its own; the database is the only shared
  state.

**Unattended/scheduled assessment** is the same story at the level of whole
flows: `lantern queue add` (from any invocation) and a long-running
`lantern daemon` (elsewhere) coordinate through nothing but that shared
SQLite file. `Db::claim_next_queued` is a locked `SELECT` immediately
followed by an `UPDATE`, so two daemons against the same data root can never
claim the same job twice; jobs run one at a time, through the exact same
`run::run` path `lantern run` itself uses. The daemon is a polling loop, not
a server - it opens no listening socket - and SIGINT/SIGTERM both let the
job in progress finish before it exits.

### Session lifecycle: create, read, update, delete

A "session" in `lantern chat` is its live settings (`target`, `scope`,
`roles`, `offensive`, `dry-run`, `steps`) plus whatever flows you run under
them; each flow it starts is its own row in the database, independent of
the session that created it.

| | command | does |
|---|---|---|
| **Create** | `/new` | resets the session's settings to blank - nothing already run is deleted. |
| **Read** | `/flows` | lists recorded flows (id, status, target) - same as `lantern flows` outside chat. |
| **Update** | `/target`, `/scope`, `/roles`, `/offensive`, `/dry-run`, `/steps` | change one setting of the live session, effective on the next instruction. |
| **Delete** | `/delete <flow-id> yes` | **permanently** removes one flow: every database row across every table in one transaction, its artifact files, its working directory, its rendered report. Typing just `/delete <flow-id>` shows what would be destroyed and refuses. |

The same delete is available outside chat as `lantern delete <flow-id>
--yes`. Deleting one flow never touches another - verified both in the
database layer and live, under a real terminal, with two flows from two
separate `/new` sessions and only one deleted.

## Detectability and the agent's own attack surface

**Target-side detection** is partial, by design, on the recon side:
`http_probe`, `waf_fingerprint`, `dir_bruteforce` and `web_search` send
`User-Agent: lantern/<version>` by default - honest, self-identifying
traffic, useful when an engagement wants a defender's SOC to attribute it.
Override with `LANTERN_USER_AGENT` when blending in is itself part of the
test - though that buys nothing against `nikto`'s own loud signature, `nmap`'s
own scan timing, or `sqlmap`'s own `--random-agent`.

**Traces on the Lantern host** are extensive - the entire audit value
proposition, not a flaw. Every command (binary, full argv, exit code,
resolved IP) lands in `lantern.db` and a JSONL trace file; anyone with read
access to that box can reconstruct the whole engagement. Traces *on the
target* are a property of the allowlisted tools themselves, identical to
running `nmap`/`nikto`/`sqlmap` by hand.

**Against a hostile or compromised target attacking the agent back**: every
in-process network fetch (`http_probe`, `waf_fingerprint`, `dir_bruteforce`,
`subdomain_enum`, `web_search`, `api_schema_scan`, `graphql_introspect`,
`cloud_bucket_check`, `container_expose_check`) is bounded at the read
itself (`lantern_tools::fetch`) rather than truncated after the whole
response was already buffered - none of that code runs under the
`RLIMIT_AS` that protects a sandboxed host-tool child, so a target serving a
multi-gigabyte or endlessly chunked response cannot force unbounded memory
growth in the process itself. The same bound applies, at a more generous
cap, to model-provider responses (`lantern_llm::fetch`).

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
| `LANTERN_ALLOWLIST` | `nmap,sqlmap,nikto,hydra,tcpdump,nuclei,msfconsole,john,bwrap,testssl.sh,gobuster,amass,GetUserSPNs.py,GetNPUsers.py,crackmapexec,bloodhound-python,kube-hunter` | host binaries that may run |
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
├── lantern.db          # flows, tasks, commands, findings, memory (FTS5), events, queue
├── logs/                # rotating text log, size-capped
├── traces/              # JSONL audit trace, pruned by age
├── artifacts/           # raw tool output per flow, gzip-compressed after 7 days
├── flows/<flow-id>/     # per-flow working directory (code_run's one writable path)
└── reports/<flow-id>.md
```

The tools directory lives **outside** this root. Storage rules, in order:
writes refuse before `LANTERN_DATA_CAP_MB`; `lantern setup` alone refuses to
start below the 20% disk floor (it's the only step that downloads/builds
gigabytes); artifacts gzip after 7 days and delete once compressed; traces
prune after 14 days, logs after 30; SQLite runs WAL with incremental
auto-vacuum plus a conditional full `VACUUM` under the free-space threshold;
findings are kept forever.

Each role's observations are stored with an embedding when Ollama is
available (768-dim `nomic-embed-text`) and searched with a hybrid of FTS5
keyword matching and cosine similarity - keyword-only, automatically, if
Ollama is unreachable. `memory_search` recalls on demand, `memory_store`
writes a note back; a note of kind `guide` lands in a shared namespace that
outlives the engagement, so a lesson learned on one target is read by every
flow after it.

## Status

Every gap this section used to list - internal/AD tooling, API-schema-aware
testing, cloud posture, container/K8s exposure, a real daemon mode - is now
built; see [Tools](#tools) and [Roles and
delegation](#roles-and-delegation-a-fixed-pipeline-with-one-bounded-escape-hatch)
for what each one does.

What's still honestly missing: JWT-specific analysis, a structured
OAuth/SAML flow tester, an IAM policy evaluator, and container-escape
testing. `prompts::engagement_addendum` tells the model what it cannot check
for a detected profile, specifically so it says "no tool for that" instead
of narrating a check it never ran.

## License

Apache-2.0
