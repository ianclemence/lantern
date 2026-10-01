# Lantern

A native security assessment agent for small Linux hosts.
Lantern runs a scoped, fully audited assessment from the command line: a
multi-role agent (planner, researcher, coder, pentester, reflector) drives
in-process tools and a short allowlist of host binaries, keeps everything it
learns in SQLite, and writes a deterministic markdown report.

> **New here?** [GETTING_STARTED.md](GETTING_STARTED.md) walks from a fresh
> clone to a written report - build, setup, the first run, and what the numbers
> at the end of a run mean.

It is built for one machine class and sized for it: a 4-core aarch64 host with
8 GiB of RAM and a 30 GB root filesystem.

> ### ⚠️ Safety
>
> **Only assess systems you are authorised to test.** Everything Lantern does
> is bounded by the `--scope` you declare; targets outside it are refused
> before any socket is opened.
>
> **There is no shell.** Tools take structured arguments and are executed with
> `execve` style argument arrays only - never through a shell. There is no
> `sh -c`, no `eval`, no string concatenation into a command line.
>
> **Active testing is opt-in twice.** `sqlmap`, `hydra`, `nuclei`,
> `msfconsole` and `john` refuse to run unless the flow was started with
> `--offensive` *and* the target is in scope. Every invocation - binary, argv,
> cwd, exit code, duration, output size - is written to SQLite and to a JSONL
> trace file.
>
> **Nothing offensive runs by default.** A plain `lantern run` observes,
> verifies and reports. Exploitation, credential attacks and hash cracking
> exist, but only as explicitly gated, fully audited host-tool calls against
> targets you declared in scope.

---

## What it is not

To be explicit about the boundaries, because they are deliberate:

- **No implicit exploitation.** Lantern carries no exploit code of its own and
  no payload generator. Anything intrusive is a host tool that must be
  allowlisted, run one module at a time, gated behind `--offensive`, matched
  against `--scope`, and recorded argv-for-argv before and after it runs.
- **Runs directly on the host.** No sandbox runtime, no VM, no background
  service. Isolation comes from an executable allowlist, a cleared environment,
  a restricted `PATH`, a fresh session per child,
  `setrlimit` (CPU/AS/FSIZE/NOFILE/NPROC/CORE), wall-clock timeouts, output
  caps and a per-flow working directory.
- **No web UI, no HTTP server.** A 7.87 GiB host cannot spend 1-2 GiB on a
  browser stack. The CLI is the interface.
- **No monitoring stack, no graph database, no object store.** Logs are
  `tracing` output into a size-capped rotating file; everything else is one
  SQLite database.
- **No multi-tenancy, no remote workers, no GPU assumptions.**

## Device profile

| | |
|---|---|
| CPU | 4 × Cortex-A76 @ 2.4 GHz, aarch64 |
| RAM | 7.87 GiB + 2 GiB zram swap (6+ GiB typically available) |
| Disk | 30.79 GB ext4, **6.16 GB (20%) is a floor `lantern setup` will not cross** |
| GPU | none (display-only silicon) - no compute, so inference is external |
| OS | Debian 13 (trixie), kernel 6.18, glibc 2.41 |
| Budgets | data root 1.28 GB, logs 200 MB, concurrency 3, token budget 6000 |

`lantern doctor` re-measures all of this at runtime and prints the numbers it
actually sees. The figures above are what this profile measures on the
reference 4-core/8 GiB device; they are not hardcoded. `concurrency` and the
per-child memory rlimit (`LANTERN_CHILD_MEM_MB`) are derived from whatever
host `lantern` actually runs on - `DeviceProfile::detect` reads the live core
count, RAM and swap and sizes both from that, so the same binary lands on
`concurrency=3`/`512 MB` on this reference device, scales down toward 1
task/256 MB on something smaller, and scales up on a bigger box, all without
a rebuild. An explicit `LANTERN_CONCURRENCY` or `LANTERN_CHILD_MEM_MB` still
overrides the derived value, same as every other setting in this table.

## Build

```sh
make            # release build + on-disk and runtime footprint
make test       # 234 tests, no API spend (scripted provider)

# then any shell can type `lantern`: setup links it into ~/.local/bin
./target/release/lantern setup
```

Requires a Rust toolchain (1.85+) and OpenSSL development headers. TLS uses
the system OpenSSL (`native-tls`), which is what keeps the build free of
`cmake`, `ring` and a bundled `libclang`.

The release profile is tuned for this device: `lto = "thin"`,
`codegen-units = 1`, `panic = "abort"`, `strip = true`, `debug = false`.

## Commands

```sh
lantern setup                                  # provider, model, key - then every host tool (once per machine)
lantern doctor                                  # device, budget, integrations, tools
lantern run --target example.com \
            --scope "example.com, 104.20.23.154/32, 172.66.147.243/32"   # full pipeline (read-only), scope covers what it resolves to
lantern run --target 10.10.5.4 --scope 10.10.5.0/24 \
            --offensive                         # ...and now the gated tools may run
lantern run --dry-run --target example.com \
            --scope "example.com"               # free: same pipeline, zero model calls
lantern run ... --roles researcher,pentester    # pick the roles
lantern run ... --interactive                   # ...and let a role ask you a question
lantern ask --target example.com --scope "example.com" \
            --prompt "Check TLS and headers, defensive only"   # instruct in words, not flags
lantern chat                                  # ...or talk it through: / commands, approvals, Esc aborts
lantern flows                                   # what has been run
lantern report flw_abc123                       # markdown report to stdout
lantern report flw_abc123 --out report.md
lantern tools                                   # every tool and its gate
lantern gc                                      # retention: compress, prune, vacuum
```

## Setup

`lantern setup` is the whole installation story: on a machine that has never
seen Lantern it asks the three questions only you can answer and provisions
what is missing; on a machine that is already set up it reports everything
present and changes nothing.

```sh
lantern setup      # provider, model, key - then everything the pipeline drives
```

The model half comes first. It lists the providers, fetches that endpoint's own
model list so the menu shows what the account can actually call, reads the key
with the input hidden and spends one real completion checking that it works -
a key that cannot talk to the endpoint is not worth storing. The key lands in
`~/.config/lantern/credentials` at mode `0600`; provider, model and endpoint go
to `config.json` beside it, which holds no secret. With no terminal attached
there is nobody to question, so setup keeps whatever the environment already
says and stores it after one real check - and when the environment cannot
finish the job it writes nothing and names the one variable that would, so a
script never blocks on a prompt.

The tools, then, in order:

1. **distribution packages** - `nmap`, `sqlmap`, `nikto`, `hydra`, `tcpdump`
   and `bubblewrap` (the sandbox the coder's scripts run in) through
   `apt-get`, but only the ones that are missing, and only if
   passwordless `sudo` is available. Without `sudo` it prints exactly what is
   missing instead of failing halfway.
2. **john (jumbo)** - cloned and built from source into the tools directory,
   giving 328 formats instead of the handful a distribution package provides.
   The build residue is deleted afterwards.
3. **nuclei** - the release binary for the host's architecture, fetched and
   unpacked into the tools directory.
4. **template set** - a sparse clone of the CVE templates (4,348 files, 33 MB)
   rather than the whole repository.
5. **exploit framework** - the ~754 MB signing key, signed repository and
   package install, downloaded on a first setup like everything else. Without
   `sudo`, without `apt`, or on an architecture it publishes no packages for,
   it says so and moves on - it never stops to ask.

Everything runs through the same executor the agent uses - argv arrays, no
shell, rlimits, timeouts, one audit row per command - and lands either in your
package manager's own directories or in the tools directory:

```
~/.local/share/lantern-tools/
├── bin/nuclei           # fetched binaries
├── john/                # standalone jumbo build (john, charsets, rules, wordlists)
└── share/nuclei-templates/
```

The last step is the operator's own: the binary is linked into `~/.local/bin`,
so a fresh terminal just types `lantern`. It is a symlink rather than a copy,
which means a rebuild cannot leave a stale binary behind, and when that
directory is not searched yet the line to add is printed instead of being
written into a shell startup file behind your back.

The tools directory is deliberately **outside** the data root: provisioning
never competes with logs, artifacts and findings for space.

### Roles

| Role | What it does | Tools |
|---|---|---|
| orchestrator | turns the objective into a written plan | - |
| planner | reorders the plan by risk and effort | - |
| researcher | passive recon: DNS, TLS, HTTP headers, WHOIS, open ports, subdomains, WAF/CDN, leaked secrets, web search | `dns_lookup`, `subdomain_enum`, `tls_inspect`, `http_probe`, `waf_fingerprint`, `secret_scan`, `whois`, `port_scan`, `web_search`, `memory_search`, `memory_store`, `ask_operator`, `plan_patch` |
| coder | reproducible check steps and remediation advice | `memory_search`, `memory_store`, `ask_operator`, `plan_patch`, `code_run`, `secret_scan` |
| pentester | active verification inside scope | `port_scan`, `dir_bruteforce`, `host_nmap`, `host_nikto`, `host_tcpdump`, `host_testssl`, `host_gobuster`, `host_sqlmap`\*, `host_hydra`\*, `host_nuclei`\*, `host_msfconsole`\*, `host_john`\*, `host_amass`\*, `waf_fingerprint`, `secret_scan`, `memory_search`, `memory_store`, `ask_operator`, `plan_patch` |
| reflector | reviews the evidence quality and confidence of every finding | `memory_search`, `ask_operator`, `plan_patch` |

\* requires `--offensive`.

Every tool call passes through one choke point
(`Registry::execute`), which applies the scope check and the `--offensive`
gate *before* the tool body runs. Each role's own tool-calling loop only ever
*sees* (and pays context budget for) the schemas of the tools in its own
`Tools` column above (`Registry::defs_for`) - not the whole registry - so
`YOUR TOOLS:` in the system prompt is an enforced fact about what the model
can even call, not just a steering hint, and the registry can keep growing
without inflating every role's fixed per-request overhead.

### Tools

In-process (no child process): `port_scan`, `dns_lookup`, `subdomain_enum`
(certificate-transparency lookup via crt.sh - passive, touches no target
infrastructure; candidates are labelled in/out of scope, never auto-added to
it), `http_probe`, `tls_inspect`, `waf_fingerprint` (CDN/WAF signature match
from one ordinary response - headers, cookies, a block page's own
self-identification; no payloads, same risk tier as `http_probe` - run this
before trusting a zero-finding `sqlmap`/`nuclei` scan, since a silent WAF
block looks identical to a clean application in that tool's own output),
`secret_scan` (regex match for credential-shaped strings - AWS/GCP/Stripe/
Slack/GitHub/Twilio/SendGrid keys, JWTs, private key blocks - in text another
tool already captured; no network or file access of its own, and every match
is reported masked, never the live value), `whois`, `dir_bruteforce`
(built-in 2,419-entry wordlist), `web_search` (DuckDuckGo HTML by default, a
search API if you configure one; `mode: vulnerability` puts matching NVD
CVEs and their CVSS scores first), `memory_search`, `memory_store`,
`ask_operator` (only under `--interactive`, and silent unless you set
`LANTERN_OPERATOR_ANSWER`), `plan_patch` (roles correct the plan once facts
disagree with it, and later roles read the corrected version).

One child process, and it is not a host binary: `code_run` - a single
Python script (standard library only, nothing else the model can name)
behind `bwrap`, with an empty network namespace and a read-only
filesystem where only the flow's own directory is writable. It computes;
it can never reach a target.

Allowlisted host binaries, all provisioned by `lantern setup`:

| Binary | What the adapter does | Gate |
|---|---|---|
| `nmap` | connect scan, ports and services | scope |
| `nikto` | web-server misconfiguration scan | scope |
| `tcpdump` | capture N packets to a pcap artifact | scope |
| `testssl.sh` | deep TLS/cipher inspection (protocol downgrade, Heartbleed-class checks) | scope |
| `gobuster` | faster, multi-threaded directory/file discovery than `dir_bruteforce` | scope |
| `sqlmap` | SQL-injection testing against a URL | `--offensive` + scope |
| `hydra` | password spraying against one service | `--offensive` + scope |
| `nuclei` | CVE template scan of a URL, JSONL findings | `--offensive` + scope |
| `msfconsole` | one module (`use`/`set`/`run` or `check`), built as a single argv element | `--offensive` + scope |
| `john` | offline cracking: wordlist, optional rules, then `--show` | `--offensive` |
| `amass` | active subdomain enumeration (active DNS resolution, optional `-brute`) | `--offensive` + scope |

Each adapter builds its own argument array - the model never supplies raw
flags, so it cannot smuggle `-oN /etc/passwd` through. The `msfconsole`
session string is assembled from a validated module path and character-filtered
option values, so no option can chain a second console command; `john` writes
its hashes into the flow's own artifact directory and keeps its pot file in the
flow working directory; `nuclei` runs with `-no-interactsh` so no callback ever
leaves for a third party; `gobuster` falls back to the same bundled wordlist
`dir_bruteforce` uses, materialised into the flow's own artifact directory,
when no custom one is given. `tcpdump` alone holds `cap_net_raw,cap_net_admin`;
the `lantern` binary stays unprivileged. `testssl.sh` is a shell script with
no compiled binary of its own - the kernel's shebang handling runs it via
`execve`, exactly like `python3 script.py` in `code_run`; there is no shell
string interpolation of operator input anywhere in that path, same as every
other adapter.

### Scope: CIDR and DNS

A target can be a host name, an IP, or a CIDR range, and the scope check
treats each correctly rather than as interchangeable strings:

- **A CIDR target (e.g. `msfconsole`'s `RHOSTS`) is checked as the whole
  range it names**, not just its base address. A scope of `10.0.0.0/24`
  rejects a target of `10.0.0.0/8` even though `10.0.0.0` itself sits inside
  the declared range - the target's own prefix must be at least as narrow as
  the scope entry's, so nothing can request a broader sweep than was
  authorised by naming a wider mask over the same network address.
- **A host-name target is resolved immediately before the command runs**,
  and the resolved address is written to the audit row (`resolved_ips`,
  visible in `lantern report` and the trace file) regardless of outcome. When
  `--scope` itself names one or more IP ranges - the configuration this
  README recommends - a hostname that now resolves outside every one of them
  is refused instead of silently scanned, catching DNS drift or rebinding
  between the moment the scope was declared and the moment a tool actually
  runs. A scope defined purely by host name (no IP/CIDR entries at all) skips
  this extra check, since there is nothing to compare the resolved address
  against.
- This narrows, but cannot fully close, the gap between Lantern's check and
  the host tool's own connection: `nmap`/`nikto`/`sqlmap` do their own DNS
  resolution internally, and nothing in user space can pin a third-party
  binary to one resolved address without breaking vhost-based tools that
  need the host name intact for the `Host`/SNI value. Put the resolved IP in
  `--scope` alongside the host name for the tightest guarantee.

## Environment variables

Every value has a default, so nothing here is required. Underneath the
environment sit the two files the wizard writes - `config.json` (provider,
model, endpoint; no secrets) and `credentials` (the key, mode `0600`) - and the
order is environment, then file, then preset.

| Variable | Default | Purpose |
|---|---|---|
| `LANTERN_LLM_PROVIDER` | `deepseek` | preset id from [Providers](#providers) |
| `LANTERN_LLM_API_KEY` | - | generation key for any provider (each preset also names its own) |
| `LANTERN_LLM_BASE_URL` | preset's | endpoint override |
| `LANTERN_LLM_MODEL` | preset's | model override |
| `LANTERN_CONFIG_DIR` | `~/.config/lantern` | where `config.json` and `credentials` live |
| `LANTERN_LLM_TIMEOUT_SECS` | `90` | per-request timeout |
| `LANTERN_LLM_MAX_TOKENS` | `2000` | reply cap |
| `OLLAMA_URL` / `OLLAMA_EMBED_MODEL` | `http://127.0.0.1:11434` / `nomic-embed-text` | local embeddings |
| `LANTERN_EMBED` | `1` | `0` disables embeddings (keyword search only) |
| `LANTERN_DATA_ROOT` | `~/.local/share/lantern` | single data root |
| `LANTERN_DATA_CAP_MB` | `1280` | hard cap on the data root |
| `LANTERN_LOG_CAP_MB` | `200` | cap on the log directory |
| `LANTERN_DISK_FLOOR_PERCENT` | `20` | free space `lantern setup` will not cross |
| `LANTERN_CONCURRENCY` | device-derived (`3` on the reference device) | parallel task budget |
| `LANTERN_TASK_TIMEOUT_SECS` | `120` | per-task wall clock |
| `LANTERN_MAX_OUTPUT_BYTES` | `2097152` | max captured output per command |
| `LANTERN_CHILD_MEM_MB` / `LANTERN_CHILD_CPU_SECS` | device-derived (`512`) / `60` | child rlimits |
| `LANTERN_PATH` | `/usr/local/bin:/usr/bin:/bin` + tools dirs | restricted `PATH` for children |
| `LANTERN_ALLOWLIST` | `nmap,sqlmap,nikto,hydra,tcpdump,nuclei,msfconsole,john,bwrap,testssl.sh,gobuster,amass` | host binaries that may run |
| `LANTERN_TOOLS_DIR` | `~/.local/share/lantern-tools` | where `lantern setup` provisions tools |
| `LANTERN_NUCLEI_TEMPLATES` | `<tools-dir>/share/nuclei-templates` | template set for `host_nuclei` |
| `LANTERN_OPERATOR_ANSWER` | - | reply for `ask_operator` when no terminal is attached |
| `LANTERN_OFFENSIVE` | `0` | same as `--offensive` |
| `LANTERN_OFFLINE` | `0` | no external calls at all |
| `LANTERN_USER_AGENT` | `lantern/<version>` | `User-Agent` for in-process target fetches - see [Detectability](#detectability-traces-and-the-agents-own-attack-surface) |
| `LANTERN_TOKEN_BUDGET` | `6000` | context window budget per role |
| `LANTERN_PRICE_INPUT_PER_MTOK` / `LANTERN_PRICE_OUTPUT_PER_MTOK` | - | USD per million tokens, so a run can print what it cost |
| `LANTERN_ARTIFACT_DAYS` / `LANTERN_TRACE_DAYS` / `LANTERN_LOG_DAYS` | `7` / `14` / `30` | retention |
| `LANTERN_VACUUM_FREE_PERCENT` | `25` | full `VACUUM` threshold |

### Providers

Nine presets and one escape hatch. The wizard shows the endpoint's own model
list when it will answer, and falls back to each preset's shortlist - whose
first entry is the last column below.

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

One chat client drives all of them; the preset decides which wire shape to
speak, since `anthropic` takes the Messages API rather than chat completions.
A key saved for one provider is never sent to another.

## Data root

```
~/.local/share/lantern/
├── lantern.db          # flows, tasks, commands, findings, memory (FTS5), events
├── logs/               # rotating text log, size-capped
├── traces/             # JSONL audit trace, pruned by age
├── artifacts/          # raw tool output per flow, gzip-compressed after 7 days
├── flows/<flow-id>/    # per-flow working directory for child processes
└── reports/<flow-id>.md
```

The tools directory is deliberately **outside** the data root.

Storage rules, in order of preference:

1. writes are refused before the data root reaches `LANTERN_DATA_CAP_MB`;
2. provisioning (`lantern setup`) refuses to start below the 20% floor, because
   that is the only step that downloads and builds gigabytes; assessments,
   `chat` and `gc` run at any free space (`lantern doctor` reports where the
   disk stands);
3. artifacts are gzip-compressed after 7 days and deleted once compressed;
4. traces are pruned after 14 days, logs after 30;
5. SQLite runs in WAL with `auto_vacuum=INCREMENTAL`, plus a conditional full
   `VACUUM` when free space drops under the threshold;
6. findings are kept forever - they are the point of the exercise.

## Detectability, traces, and the agent's own attack surface

Questions worth asking of any pentest tool before it runs against something
real, answered plainly rather than assumed:

**Can the target detect it?** Partially, and by design rather than oversight
on the recon side. `http_probe`, `waf_fingerprint`, `dir_bruteforce` and
`web_search` send `User-Agent: lantern/<version>` by default - honest,
self-identifying traffic, the same audit-first stance as everything else
here (every command logged argv-for-argv; a target's own logs seeing what
actually touched them is that same idea, not a gap). Override it with
`LANTERN_USER_AGENT` for an engagement where blending into ordinary browser
traffic is itself part of the test. What overriding it does **not** buy:
`nikto` is a loud, signature-heavy scanner by its own design, `nmap`'s SYN/
connect-scan timing is its own fingerprint, `sqlmap` already carries
`--random-agent` as a separate setting, and none of that changes with a
header. Nothing here claims stealth it cannot deliver.

**Does it leave traces?** Yes, extensively, on the machine running it - this
is the whole audit value proposition, not a flaw to route around. Every
command (binary, full argv, exit code, duration, resolved IPs) lands in
`lantern.db` and a JSONL trace file; artifacts and reports sit in plain
files under the data root; the credential file is mode `0600` but its
*path* is not hidden. Anyone with read access to the box - the operator,
whoever administers it, a forensic review after the fact - can reconstruct
exactly what ran, against what, and when. If "does it leave traces"
means *on the target*, that is a question about the allowlisted tools
themselves (`nmap`/`nikto`/`sqlmap` logs, WAF/IDS logs, access logs) - the
same traces any of those tools would leave run by hand, not something this
wrapper adds or removes.

**Is the agent itself secure, or just a vulnerable pentester?** The things
that would make it the latter: no shell anywhere (checked, see `exec.rs`);
every child process gets `RLIMIT_AS`/`RLIMIT_CPU`/output caps independent of
what the tool itself does; argument builders are hand-written per tool so
the model can never smuggle a flag. The gap a thorough review has to ask
about is the other direction - a hostile or compromised *target* attacking
the agent back through its own response parsing. That gap existed until
this session: `http_probe`, `waf_fingerprint`, `dir_bruteforce` and the
search/CT-log lookups all buffered an HTTP response fully into memory
(`reqwest`'s `.bytes()`/`.text()`) before any truncation applied, and none of
that in-process code runs under the `RLIMIT_AS` that protects a sandboxed
child - a target serving a multi-gigabyte or endlessly chunked response
could force unbounded memory growth in the agent process itself. Every
in-process network fetch is now bounded at the read itself
(`fetch::read_capped_body`/`read_capped_text`, stops reading the instant the
cap is hit rather than truncating after the fact), verified against a real
oversized response in `fetch.rs`'s tests, not just reasoned about. The
model's own text output is still bounded the way it always was (JSON parse
with graceful fallback, `text_clip` everywhere a blob reaches a report or a
prompt) - the fix was specifically the "read before truncate" class of bug,
not a general audit of every parser.

## Memory

Observations from each role are stored in SQLite with an embedding when Ollama
is available (`nomic-embed-text`, 768 dimensions) and searched with a hybrid of
FTS5 keyword matching and cosine similarity computed in Rust. If Ollama is
unreachable, Lantern says so and falls back to keyword search - it never fails
the flow over a missing embedder.

Two tools put it in the model's hands: `memory_search` recalls on demand and
`memory_store` writes a note back. A note of kind `guide` lands in a shared
namespace that outlives the engagement, so a lesson learned on one target is
read by every flow after it.

## Architecture

```
lantern-cli     CLI: setup / doctor / run / flows / report / tools / gc
lantern-agent   roles, prompts, tool loop, review, reports
lantern-tools   native tools, cross-role memory, sandboxed host exec, tool registry (one choke point)
lantern-llm     chat clients (OpenAI-compatible, Anthropic), embeddings, context window
lantern-core    config, device profiling, storage (SQLite), budget, scope, logging, retention
```

Every crate is deterministic where it can be: findings are extracted and
validated, reports are rendered straight from SQLite with no model call, and
`--dry-run` runs the whole pipeline against a scripted provider so the loop is
testable without spending anything.

## License

Apache-2.0
