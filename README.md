# Lantern

A native, container-free security assessment agent for small Linux hosts.
Lantern runs a scoped, fully audited assessment from the command line: a
multi-role agent (planner, researcher, coder, pentester, reflector) drives
in-process tools and a short allowlist of host binaries, keeps everything it
learns in SQLite, and writes a deterministic markdown report.

It is built for one machine class and sized for it: a Raspberry Pi 5 with
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
> **Active testing is opt-in twice.** `sqlmap` and `hydra` refuse to run unless
> the flow was started with `--offensive` *and* the target is in scope. Every
> invocation - binary, argv, cwd, exit code, duration, output size - is written
> to SQLite and to a JSONL trace file.
>
> **Lantern does not exploit.** It observes, verifies and reports. It cannot
> execute code on a target, deploy a payload, or crack hashes.

---

## What it is not

To be explicit about the boundaries, because they are deliberate:

- **No exploitation framework.** Lantern ships no exploit modules, no payload
  generation, and no post-exploitation. **Metasploit and hashcat are not
  integrated and will not be** (they also do not fit this device's storage,
  RAM and lack of GPU).
- **No containers.** No Docker, Podman, or sandbox VM - the host has neither
  the RAM nor the images for it. Isolation comes from an executable allowlist,
  a cleared environment, a restricted `PATH`, a fresh session per child,
  `setrlimit` (CPU/AS/FSIZE/NOFILE/NPROC/CORE), wall-clock timeouts, output
  caps and a per-flow working directory.
- **No web UI, no HTTP server.** A 7.87 GiB host cannot spend 1-2 GiB on a
  browser stack. The CLI is the interface.
- **No monitoring stack.** No Prometheus, Grafana, Loki, Jaeger, ClickHouse,
  Redis, MinIO, Neo4j or Graphiti. Logs are `tracing` output into a size-capped
  rotating file; storage is one SQLite database.
- **No multi-tenancy, no remote workers, no GPU assumptions.**

## Device profile

| | |
|---|---|
| Board | Raspberry Pi 5 (BCM2712), 4 × Cortex-A76 @ 2.4 GHz, aarch64 |
| RAM | 7.87 GiB + 2 GiB zram swap (6+ GiB typically available) |
| Disk | 30.79 GB ext4, **6.16 GB (20%) is a floor Lantern will not touch** |
| GPU | VideoCore display-only - no compute, so inference is external |
| OS | Debian 13 (trixie), kernel 6.18, glibc 2.41 |
| Budgets | data root 1.28 GB, logs 200 MB, concurrency 3, token budget 6000 |

`lantern doctor` re-measures all of this at runtime and prints the numbers it
actually sees, including free space against the floor.

## Build

```sh
make            # release build + on-disk and runtime footprint
make test       # 128 tests, no API spend (scripted provider)
```

Requires a Rust toolchain (1.85+) and OpenSSL development headers. TLS uses
the system OpenSSL (`native-tls`), which is what keeps the build free of
`cmake`, `ring` and a bundled `libclang`.

The release profile is tuned for this board: `lto = "thin"`,
`codegen-units = 1`, `panic = "abort"`, `strip = true`, `debug = false`.

## Commands

```sh
lantern doctor                                  # device, budget, integrations, tools
lantern run --target example.com \
            --scope "example.com, 93.184.216.0/24"   # full pipeline (read-only)
lantern run --target 10.10.5.4 --scope 10.10.5.0/24 \
            --offensive                         # ...and now sqlmap/hydra may run
lantern run --target 127.0.0.1 --scope 127.0.0.1 --dry-run   # scripted, free
lantern run ... --roles researcher,pentester    # pick the roles
lantern flows                                   # what has been run
lantern report flw_abc123                       # markdown report to stdout
lantern report flw_abc123 --out report.md
lantern tools                                   # every tool and its gate
lantern gc                                      # retention: compress, prune, vacuum
```

### Roles

| Role | What it does | Tools |
|---|---|---|
| orchestrator | turns the objective into a written plan | - |
| planner | reorders the plan by risk and effort | - |
| researcher | passive recon: DNS, TLS, HTTP headers, WHOIS, open ports, web search | `dns_lookup`, `tls_inspect`, `http_probe`, `whois`, `port_scan`, `web_search` |
| coder | reproducible check steps and remediation advice | - |
| pentester | active verification inside scope | `port_scan`, `dir_bruteforce`, `host_nmap`, `host_nikto`, `host_tcpdump`, `host_sqlmap`\*, `host_hydra`\* |
| reflector | judges evidence quality and confidence of every finding | - |

\* requires `--offensive`.

Every tool call passes through one choke point
(`Registry::execute`), which applies the scope check and the `--offensive`
gate *before* the tool body runs.

### Tools

In-process (no child process): `port_scan`, `dns_lookup`, `http_probe`,
`tls_inspect`, `whois`, `dir_bruteforce` (built-in 2,419-entry wordlist),
`web_search` (DuckDuckGo HTML by default, a search API if you configure one).

Allowlisted host binaries: `nmap`, `sqlmap`, `nikto`, `hydra`, `tcpdump`
(`tcpdump` alone holds `cap_net_raw,cap_net_admin`; the `lantern` binary stays
unprivileged). Each adapter builds its own argument array - the model never
supplies raw flags, so it cannot smuggle `-oN /etc/passwd` through.

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
| `LANTERN_PATH` | `/usr/local/bin:/usr/bin:/bin` | restricted `PATH` for children |
| `LANTERN_ALLOWLIST` | `nmap,sqlmap,nikto,hydra,tcpdump` | host binaries that may run |
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

Storage rules, in order of preference:

1. writes are refused before the data root reaches `LANTERN_DATA_CAP_MB`;
2. the filesystem is never taken below the 20% floor - `lantern run` refuses
   to start (`lantern gc` still works);
3. artifacts are gzip-compressed after 7 days and deleted once compressed;
4. traces are pruned after 14 days, logs after 30;
5. SQLite runs in WAL with `auto_vacuum=INCREMENTAL`, plus a conditional full
   `VACUUM` when free space drops under the threshold;
6. findings are kept forever - they are the point of the exercise.

`lantern doctor` and `lantern gc` both print current usage against the budget.

## Memory

Observations from each role are stored in SQLite with an embedding when Ollama
is available (`nomic-embed-text`, 768 dimensions) and searched with a hybrid of
FTS5 keyword matching and cosine similarity computed in Rust. If Ollama is
unreachable, Lantern says so and falls back to keyword search - it never fails
the flow over a missing embedder.

## Architecture

```
lantern-cli     CLI: doctor / run / flows / report / tools / gc
lantern-agent   roles, prompts, cross-role memory, tool loop, judgement, reports
lantern-tools   native tools, sandboxed host exec, tool registry (one choke point)
lantern-llm     OpenAI-compatible client, judgement client, embeddings, context window
lantern-core    config, device profiling, storage (SQLite), budget, scope, logging, retention
```

Every crate is deterministic where it can be: findings are extracted and
validated, reports are rendered straight from SQLite with no model call, and
`--dry-run` runs the whole pipeline against a scripted provider so the loop is
testable without spending anything.

## License

Apache-2.0
