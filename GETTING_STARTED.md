# Getting started

From a fresh clone to a written report, in the order you will actually run
things. Every number below was measured on this machine (4 cores, aarch64,
8 GiB, Debian 13); every output block is copy-pasted from a real run.

> Only assess systems you are authorised to test. A run is bounded by
> `--scope` before any socket opens, and `--offensive` is a second, separate
> gate. The full safety section is in the [README](README.md#-safety).

## 0. What you need

| | |
|---|---|
| Host | Linux on aarch64 or x86_64 |
| Toolchain | Rust 1.85+ (`cargo`), OpenSSL headers, `git`, `gcc`/`make` |
| Network | for the model endpoint and for provisioning on first setup |
| `sudo` | optional: without it, setup prints what it would install and moves on |
| A model key | any of the ten presets, added during setup |
| Authorisation | for whatever you point it at |

Debian/Ubuntu toolchain in one line:

```sh
sudo apt install build-essential libssl-dev pkg-config
```

## 1. Clone and build

```sh
git clone https://github.com/ianclemence/lantern.git
cd lantern
make          # release build, then on-disk and runtime footprint
make test     # 234 tests, no API spend (scripted provider)
```

If `cargo` is not on `PATH` yet, prefix with `export PATH="$HOME/.cargo/bin:$PATH"`
(or call `~/.cargo/bin/cargo` directly).

That produces `target/release/lantern` - 8,546,696 bytes (8.15 MB), reporting
`lantern 0.1.5`.

## 2. One command: setup

```sh
./target/release/lantern setup
```

It does three things, in this order: the model half, the tools, then the
binary itself.

### The model half (a terminal asks three questions)

```
  AI provider
     1) DeepSeek         https://api.deepseek.com
     2) OpenAI           https://api.openai.com/v1
     ...
    10) Custom endpoint  your own URL
    choose 1-10:
```

Then the model - the endpoint's own list is fetched live, the preset shortlist
is the fallback, `m` types any name - and then the key, read with the input
hidden and checked with one real 16-token completion before it is stored:

```
  testing DeepSeek / deepseek-flash
  [warn]    llm http 401 Unauthorized: ...your api key: ****0001 is invalid...
    save it anyway? [y/N]
```

(That is a deliberately bad key being refused. A key that cannot reach its
endpoint is not worth saving, and the message is redacted so the key never
reaches your terminal or a log.)

What it writes:

| file | contents |
|---|---|
| `~/.config/lantern/credentials` | the key, mode `0600` - never in the database, logs, traces or reports |
| `~/.config/lantern/config.json` | provider, model, endpoint - no secret |

### With no terminal attached

There is nobody to question, so setup takes the answer the environment already
gives - `LANTERN_LLM_PROVIDER`, `LANTERN_LLM_MODEL`, `LANTERN_LLM_BASE_URL` and
the key - checks it with one call, and stores it. When the environment cannot
finish the job, nothing is written and the message names the single variable
that would:

```
  [skip]    AI provider: no terminal here - export DEEPSEEK_API_KEY; run `lantern setup` in a terminal to be walked through provider, model and key
```

So `KEY=... lantern setup < /dev/null` in a script leaves the machine
configured, and a bare one leaves it untouched.

### The tools, then the binary

1. distribution packages - `nmap`, `sqlmap`, `nikto`, `hydra`, `tcpdump` and
   `bubblewrap`, only the ones missing, only with passwordless `sudo`;
2. john (jumbo) built from source - 328 formats;
3. nuclei plus a sparse clone of the CVE templates (4,348 files, 33 MB);
4. the exploit framework's signed repository and package;
5. the binary linked into `~/.local/bin`, so the next terminal just types
   `lantern` (if that directory is not searched yet, the `export` line is
   printed rather than written into your shell startup files).

Every step is an argv array through the audited executor: one audit row per
command. Re-running `lantern setup` is free - things that are present report
`ok` and nothing is re-downloaded.

## 3. Verify

```sh
lantern doctor
```

```
  device    : 4 cores, aarch64
  memory    : 8.5 GiB total, 5.9 GiB available, swap 2.1 GiB
  disk      : 6.55 GB free of 30.79 GB (floor keeps 6.16 GB free)
  generation: deepseek / deepseek-flash @ https://api.deepseek.com [NO KEY - run `lantern setup`]
  embeddings: ollama nomic-embed-text @ http://127.0.0.1:11434 - 768-dim
  tools     : 12 native, allowlist: nmap sqlmap nikto hydra tcpdump nuclei msfconsole john bwrap
  runtime   : concurrency 3 | task timeout 120s | child 512 MB / 60 CPU-s | token budget 6000
  warnings  :
    - no generation key: runs are limited to --dry-run
```

36-37 ms. The `warnings` line is the only one you must act on; it reads
`none` once the key is stored.

## 4. Your first run

**Free first.** Same pipeline, scripted provider, no model calls:

```sh
lantern run --dry-run --target example.com --scope "example.com"
```

0.3-0.5 s for the full pipeline (one cold first run measured 1.6 s), a report
written, nothing charged.

**Then the real read-only assessment.** `--scope` is the hard boundary, and it
should cover whatever the target *resolves to*:

```sh
lantern run --target example.com \
            --scope "example.com, 104.20.23.154/32, 172.66.147.243/32"
```

Measured end to end: **152.4 s, 16 model steps, 38 tool calls, 3 findings,
cost at or under $0.01.** The time goes to the tools as much as the model -
three connect scans at ~5.5 s each, nikto at 0.3-0.4 s, 60 path probes in
0.5 s.

**Then, only where you are allowed to poke:**

```sh
lantern run --target 10.10.5.4 --scope 10.10.5.0/24 --offensive
```

`--offensive` unlocks `sqlmap`, `hydra`, `nuclei`, `msfconsole` and `john`;
each call is still scope-gated and logged argv-for-argv.

Everyday variations:

```sh
lantern run ... --roles researcher,pentester   # subset of the pipeline
lantern run ... --steps 4                      # cap model steps per role
lantern run ... --interactive                  # roles may stop and ask you
LANTERN_OPERATOR_ANSWER="yes" lantern run ...  # ...answered unattended instead
lantern ask --target example.com --scope "example.com" \
            --prompt "Check TLS and headers, defensive only"   # words, not flags
lantern ask --target shop.example.com --scope "shop.example.com" \
            --file framework.md --dry-run                      # a whole framework, free to preview
```

`ask` takes the same `--target`, `--scope`, `--roles`, `--steps` and
`--offensive` as `run`, plus one instruction: `--prompt`, `--file`, or piped
stdin. The full text is stored with the flow and each role sees its head, so a
35-section framework fits the 6,000-token working set. Before anything runs, an
intent card says what was understood - and the safety rule is that the prompt
can only restrain `--offensive`, never grant it: ask for exploitation without
the flag and you get reconnaissance plus the flag named; pass the flag with a
defensive-only prompt and the prompt wins, loudly in both cases.

`chat` is the same flow behind a conversational screen: the transcript stays
in the terminal's scrollback while a small viewport shows status, live role
and tool activity, and the input line. `/target`, `/scope`, `/roles`,
`/offensive`, `/dry-run` and `/steps` set the session; anything else you type
runs as an instruction. Active testing requested without the session allowing
it raises an inline card (`1` allows this flow once, `2` or Esc stays
reconnaissance); a line typed mid-flow is noted for the roles still to run;
Esc stops the flow at the next step boundary and the flow reports `aborted`
with what it finished. Roles cannot stop for questions here, so flows run
non-interactively by design.

## 5. Reading the results

```sh
lantern flows                       # id, status, target, created, scope
lantern report flw_1a0eb8865620000  # markdown to stdout
lantern report flw_1a0eb8865620000 --out report.md
```

The report is assembled from the database, so it quotes what the run actually
did - status, model steps, tool invocations, token spend, context peak - with
no model call in the rendering:

```
- Status: completed

## Summary

0 finding(s), 0 tool invocation(s), 2 model step(s), 2,468 in / 112 out tokens.

Context peaked at 91 of 6,000 tokens: 0 summarization(s), 0 budget stop(s).
```

## 6. The two lines at the end of a run

```
model   : 2,468 in / 112 out tokens - $0.0008
context : peak 91 / 6,000 tokens, 0 summarization(s), 0 budget stop(s)
```

Tokens come from the endpoint's own usage block, so they are always printed.
Money is printed only when you say what a token costs where you buy it:

```sh
export LANTERN_PRICE_INPUT_PER_MTOK=0.27   # USD per million input tokens
export LANTERN_PRICE_OUTPUT_PER_MTOK=1.10  # ...and per million output tokens
```

Without them you get the token line on its own. A `--dry-run` prints the same
line labelled as an estimate - it counts the messages and the tool schemas, so
it is a free pre-flight size check before you spend anything.

What to change, and when:

| you see | do this |
|---|---|
| `budget stop(s)` above 0 | a role hit `LANTERN_TOKEN_BUDGET` before it finished - raise it |
| frequent `summarization(s)` | the working set is being compressed often; raise the budget if your model's context is cheap |
| cost higher than you want | fewer roles (`--roles`), a lower `--steps`, or a cheaper model |
| `usage not reported` | that endpoint does not bill usage per call; the token count is unavailable |

The defaults these lines are there to check:

| knob | default | where the number came from |
|---|---|---|
| steps per role | orchestrator 1, planner 1, researcher 6, coder 2, pentester 6, reflector 1 (17 max) | the real read-only run above used 16 of 17 |
| context budget | 6,000 tokens (compress at 4,500, keep 1,500) | a call starts with 3,034-3,290 tokens before the conversation: 2,770 for the 20 tool schemas sent on every request, 264-520 for the system prompt |
| `LANTERN_TASK_TIMEOUT_SECS` | 120 s, for the sandboxed analysis script | longest script actually recorded: 33 ms, zero timeouts - a safety cap, not a target |

The first run with a real key gives you the cost number; the lines above are
how the next change gets made from evidence rather than from a guess.

## 7. Living with it

```sh
lantern gc      # compress artifacts, prune traces and logs, vacuum when low on space
```

**Precedence: environment > `~/.config/lantern` files > preset defaults.**

| you want to... | do this |
|---|---|
| switch provider for good | re-run `lantern setup`, or set `LANTERN_LLM_PROVIDER=groq` |
| override just the model | `LANTERN_LLM_MODEL=llama-3.3-70b-versatile lantern run ...` |
| keep several machines in step | point `LANTERN_CONFIG_DIR` at a shared directory |
| run keyless | provider `ollama` or `custom` - no key at all |
| go offline | `LANTERN_OFFLINE=1` (network steps skip, `--dry-run` still works) |

Everything a run produces sits under one root, `~/.local/share/lantern`:
the SQLite database, `reports/<flow>.md`, audit traces, logs, artifacts and
per-flow working directories. `LANTERN_DATA_ROOT` moves it; `lantern doctor`
prints where it is and how full it is.
