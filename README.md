# Lantern

A native security assessment agent for small Linux hosts.
Lantern runs a scoped, fully audited assessment from the command line: a
multi-role agent (planner, researcher, coder, pentester, reflector) drives
in-process tools and a short allowlist of host binaries, keeps everything it
learns in SQLite, and writes a deterministic markdown report.

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
| Disk | 30.79 GB ext4, **6.16 GB (20%) is a floor Lantern will not touch** |
| GPU | none (display-only silicon) - no compute, so inference is external |
| OS | Debian 13 (trixie), kernel 6.18, glibc 2.41 |
| Budgets | data root 1.28 GB, logs 200 MB, concurrency 3, token budget 6000 |

`lantern doctor` re-measures all of this at runtime and prints the numbers it
actually sees.

## Build

```sh
make            # release build + on-disk and runtime footprint
make test       # 141 tests, no API spend (scripted provider)
```

Requires a Rust toolchain (1.85+) and OpenSSL development headers. TLS uses
the system OpenSSL (`native-tls`), which is what keeps the build free of
`cmake`, `ring` and a bundled `libclang`.

The release profile is tuned for this device: `lto = "thin"`,
`codegen-units = 1`, `panic = "abort"`, `strip = true`, `debug = false`.

## Commands

```sh
lantern setup                                  # provision every host tool (once per machine)
lantern setup --with-metasploit                # ...plus the exploit framework (~754 MB)
lantern doctor                                  # device, budget, integrations, tools
lantern run --target example.com \
            --scope "example.com, 93.184.216.0/24"   # full pipeline (read-only)
lantern run --target 10.10.5.4 --scope 10.10.5.0/24 \
            --offensive                         # ...and now the gated tools may run
lantern run --target 127.0.0.1 --scope 127.0.0.1 --dry-run   # scripted, free
lantern run ... --roles researcher,pentester    # pick the roles
lantern run ... --interactive                   # ...and let a role ask you a question
lantern flows                                   # what has been run
lantern report flw_abc123                       # markdown report to stdout
lantern report flw_abc123 --out report.md
lantern tools                                   # every tool and its gate
lantern gc                                      # retention: compress, prune, vacuum
```

## Setup

`lantern setup` is the whole installation story: on a machine that has never
seen Lantern it detects what is missing and provisions it, and on a machine
that is already provisioned it reports everything present and changes nothing.

```sh
lantern setup                  # apt tools + john + nuclei + template set
lantern setup --with-metasploit # ...also add the exploit framework
lantern setup --yes             # never prompt (for scripts)
```

What it does, in order:

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
5. **exploit framework** - opt-in, ~754 MB: signing key, signed repository,
   package install. It asks before it starts unless `--with-metasploit` or
   `--yes` was given.

Everything runs through the same executor the agent uses - argv arrays, no
shell, rlimits, timeouts, one audit row per command - and lands either in your
package manager's own directories or in the tools directory:

```
~/.local/share/lantern-tools/
├── bin/nuclei           # fetched binaries
├── john/                # standalone jumbo build (john, charsets, rules, wordlists)
└── share/nuclei-templates/
```

The tools directory is deliberately **outside** the data root: provisioning
never competes with logs, artifacts and findings for space.

### Roles

| Role | What it does | Tools |
|---|---|---|
| orchestrator | turns the objective into a written plan | - |
| planner | reorders the plan by risk and effort | - |
| researcher | passive recon: DNS, TLS, HTTP headers, WHOIS, open ports, web search | `dns_lookup`, `tls_inspect`, `http_probe`, `whois`, `port_scan`, `web_search`, `memory_search`, `memory_store`, `ask_operator`, `plan_patch` |
| coder | reproducible check steps and remediation advice | `memory_search`, `memory_store`, `ask_operator`, `plan_patch`, `code_run` |
| pentester | active verification inside scope | `port_scan`, `dir_bruteforce`, `host_nmap`, `host_nikto`, `host_tcpdump`, `host_sqlmap`\*, `host_hydra`\*, `host_nuclei`\*, `host_msfconsole`\*, `host_john`\*, `memory_search`, `memory_store`, `ask_operator`, `plan_patch` |
| reflector | judges evidence quality and confidence of every finding | `memory_search`, `ask_operator`, `plan_patch` |

\* requires `--offensive`.

Every tool call passes through one choke point
(`Registry::execute`), which applies the scope check and the `--offensive`
gate *before* the tool body runs.

### Tools

In-process (no child process): `port_scan`, `dns_lookup`, `http_probe`,
`tls_inspect`, `whois`, `dir_bruteforce` (built-in 2,419-entry wordlist),
`web_search` (DuckDuckGo HTML by default, a search API if you configure one;
`mode: vulnerability` puts matching NVD CVEs and their CVSS scores first),
`memory_search`, `memory_store`, `ask_operator` (only under `--interactive`,
and silent unless you set `LANTERN_OPERATOR_ANSWER`), `plan_patch` (roles
correct the plan once facts disagree with it, and later roles read the
corrected version).

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
| `sqlmap` | SQL-injection testing against a URL | `--offensive` + scope |
| `hydra` | password spraying against one service | `--offensive` + scope |
| `nuclei` | CVE template scan of a URL, JSONL findings | `--offensive` + scope |
| `msfconsole` | one module (`use`/`set`/`run` or `check`), built as a single argv element | `--offensive` + scope |
| `john` | offline cracking: wordlist, optional rules, then `--show` | `--offensive` |

Each adapter builds its own argument array - the model never supplies raw
flags, so it cannot smuggle `-oN /etc/passwd` through. The `msfconsole`
session string is assembled from a validated module path and character-filtered
option values, so no option can chain a second console command; `john` writes
its hashes into the flow's own artifact directory and keeps its pot file in the
flow working directory; `nuclei` runs with `-no-interactsh` so no callback ever
leaves for a third party. `tcpdump` alone holds `cap_net_raw,cap_net_admin`;
the `lantern` binary stays unprivileged.

## Environment variables

Keys are read from the environment and **never written to disk**.

| Variable | Default | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | - | generation key (required unless `--dry-run`) |
| `LANTERN_LLM_BASE_URL` | `https://api.deepseek.com` | OpenAI-compatible endpoint |
| `LANTERN_LLM_MODEL` | `deepseek-flash` | chat model |
| `LANTERN_LLM_TIMEOUT_SECS` | `90` | per-request timeout |
| `LANTERN_LLM_MAX_TOKENS` | `2000` | reply cap |
| `TYPESAFE_API_KEY` | - | structured judgement client (optional) |
| `LANTERN_JEV_URL` / `LANTERN_JEV_MODEL` | `https://api.typesafe.ai/v1/systemone` / `jev-latest` | judgement endpoint |
| `OLLAMA_URL` / `OLLAMA_EMBED_MODEL` | `http://127.0.0.1:11434` / `nomic-embed-text` | local embeddings |
| `LANTERN_EMBED` | `1` | `0` disables embeddings (keyword search only) |
| `LANTERN_DATA_ROOT` | `~/.local/share/lantern` | single data root |
| `LANTERN_DATA_CAP_MB` | `1280` | hard cap on the data root |
| `LANTERN_LOG_CAP_MB` | `200` | cap on the log directory |
| `LANTERN_DISK_FLOOR_PERCENT` | `20` | filesystem free-space floor |
| `LANTERN_CONCURRENCY` | `3` | parallel task budget |
| `LANTERN_TASK_TIMEOUT_SECS` | `120` | per-task wall clock |
| `LANTERN_MAX_OUTPUT_BYTES` | `2097152` | max captured output per command |
| `LANTERN_CHILD_MEM_MB` / `LANTERN_CHILD_CPU_SECS` | `512` / `60` | child rlimits |
| `LANTERN_PATH` | `/usr/local/bin:/usr/bin:/bin` + tools dirs | restricted `PATH` for children |
| `LANTERN_ALLOWLIST` | `nmap,sqlmap,nikto,hydra,tcpdump,nuclei,msfconsole,john,bwrap` | host binaries that may run |
| `LANTERN_TOOLS_DIR` | `~/.local/share/lantern-tools` | where `lantern setup` provisions tools |
| `LANTERN_NUCLEI_TEMPLATES` | `<tools-dir>/share/nuclei-templates` | template set for `host_nuclei` |
| `LANTERN_OPERATOR_ANSWER` | - | reply for `ask_operator` when no terminal is attached |
| `LANTERN_OFFENSIVE` | `0` | same as `--offensive` |
| `LANTERN_OFFLINE` | `0` | no external calls at all |
| `LANTERN_TOKEN_BUDGET` | `6000` | context window budget per role |
| `LANTERN_ARTIFACT_DAYS` / `LANTERN_TRACE_DAYS` / `LANTERN_LOG_DAYS` | `7` / `14` / `30` | retention |
| `LANTERN_VACUUM_FREE_PERCENT` | `25` | full `VACUUM` threshold |

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
2. the filesystem is never taken below the 20% floor - `lantern run` refuses
   to start (`lantern gc` still works);
3. artifacts are gzip-compressed after 7 days and deleted once compressed;
4. traces are pruned after 14 days, logs after 30;
5. SQLite runs in WAL with `auto_vacuum=INCREMENTAL`, plus a conditional full
   `VACUUM` when free space drops under the threshold;
6. findings are kept forever - they are the point of the exercise.

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
lantern-agent   roles, prompts, tool loop, judgement, reports
lantern-tools   native tools, cross-role memory, sandboxed host exec, tool registry (one choke point)
lantern-llm     OpenAI-compatible client, judgement client, embeddings, context window
lantern-core    config, device profiling, storage (SQLite), budget, scope, logging, retention
```

Every crate is deterministic where it can be: findings are extracted and
validated, reports are rendered straight from SQLite with no model call, and
`--dry-run` runs the whole pipeline against a scripted provider so the loop is
testable without spending anything.

## License

Apache-2.0
