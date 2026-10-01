//! The runtime loop: plan -> roles (tool calling) -> judgement -> report.
//!
//! Design notes:
//! * one `ToolCtx` per flow, so every tool call is checked against that flow's
//!   scope, budget and workdir;
//! * every model turn is bounded (`max_steps`, token budget, wall clock);
//! * a role failure is recorded and does not abort the flow - the report has to
//!   explain what happened, including partial runs.

use crate::ctx::{AgentCtx, Footprint};
use crate::findings;
use crate::prompts;
use crate::report;
use crate::roles::{role, RoleId};
use anyhow::Context as _;
use lantern_llm::provider::{ChatRequest, Message};
use lantern_llm::ContextWindow;
use lantern_tools::ctx::ToolCtx;
use lantern_tools::memory::Memory;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// One live progress event from a running flow. The terminal renders these as
/// they arrive; the plain CLI prints nothing for them.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    PlanStarted,
    RoleStarted(RoleId),
    ToolCalled(String),
    RoleFinished { role: RoleId, steps: usize, error: bool },
}

/// Where progress events go. `None` means nobody is watching.
pub type ProgressSink = std::sync::Arc<dyn Fn(ProgressEvent) + Send + Sync>;

/// What the operator asked for.
#[derive(Clone)]
pub struct FlowOptions {
    pub target: String,
    pub scope: String,
    pub offensive: bool,
    /// Empty means "run the default pipeline".
    pub roles: Vec<RoleId>,
    /// Override the per-role step cap (clamped down, never up, per role).
    pub max_steps: Option<usize>,
    /// Additional steps earned by a role from how much of the operator's own
    /// instruction (`lantern ask`) pointed at it - see
    /// `intent::Intent::step_boosts`. Raises a role's budget above its
    /// static default, unlike `max_steps`, which only ever lowers it; an
    /// explicit `max_steps` still wins as the hard ceiling over both.
    pub extra_steps: Vec<(RoleId, usize)>,
    /// What kind of engagement the operator's own instruction sounds like -
    /// see `intent::Intent::engagement_profile` and
    /// `prompts::engagement_addendum`. `General` (the default) changes
    /// nothing about the system prompt a plain `lantern run` gets.
    pub engagement_profile: crate::intent::EngagementProfile,
    /// Roles may stop and ask the operator a question (`ask_operator`).
    pub interactive: bool,
    /// The operator's own instruction, verbatim (`lantern ask`). Stored with
    /// the flow as an artifact; each role sees the condensed head of it.
    pub directive: Option<String>,
    /// Live progress feed for the terminal. Nothing else reads it.
    pub progress: Option<ProgressSink>,
    /// Set to stop the flow at the next step boundary. Checked per model step
    /// and per tool call; the flow then reports `aborted` with whatever it
    /// finished, instead of silently running on.
    pub abort: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Lines the operator typed while the flow runs. Drained at each step
    /// boundary into the working set and cross-role memory, so later roles
    /// act on them.
    pub steering: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
}

// `progress` and `abort` carry no printable state, so they debug as presence.
impl std::fmt::Debug for FlowOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowOptions")
            .field("target", &self.target)
            .field("scope", &self.scope)
            .field("offensive", &self.offensive)
            .field("roles", &self.roles)
            .field("max_steps", &self.max_steps)
            .field("extra_steps", &self.extra_steps)
            .field("engagement_profile", &self.engagement_profile)
            .field("interactive", &self.interactive)
            .field(
                "directive",
                &self.directive.as_ref().map(|d| d.chars().count()),
            )
            .field("progress", &self.progress.is_some())
            .field("abort", &self.abort.is_some())
            .field("steering", &self.steering.is_some())
            .finish()
    }
}

fn emit(opts: &FlowOptions, ev: ProgressEvent) {
    if let Some(sink) = &opts.progress {
        sink(ev);
    }
}

fn aborted(opts: &FlowOptions) -> bool {
    opts.abort
        .as_ref()
        .map(|a| a.load(Ordering::Relaxed))
        .unwrap_or(false)
}

impl FlowOptions {
    pub fn new(target: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            scope: scope.into(),
            offensive: false,
            roles: Vec::new(),
            max_steps: None,
            extra_steps: Vec::new(),
            engagement_profile: crate::intent::EngagementProfile::default(),
            interactive: false,
            directive: None,
            progress: None,
            abort: None,
            steering: None,
        }
    }

    pub fn offensive(mut self, yes: bool) -> Self {
        self.offensive = yes;
        self
    }

    pub fn interactive(mut self, yes: bool) -> Self {
        self.interactive = yes;
        self
    }

    pub fn roles(mut self, roles: Vec<RoleId>) -> Self {
        self.roles = roles;
        self
    }
}

/// Result of one role.
#[derive(Debug, Clone)]
pub struct RoleOutcome {
    pub role: RoleId,
    pub summary: String,
    pub steps: usize,
    pub findings: usize,
    pub error: Option<String>,
}

/// Result of a whole flow.
#[derive(Debug, Clone)]
pub struct FlowOutcome {
    pub flow_id: String,
    pub plan: String,
    pub roles: Vec<RoleOutcome>,
    pub findings: usize,
    pub steps: usize,
    /// Tool invocations across every role, failures included.
    pub tool_calls: usize,
    pub report: Option<PathBuf>,
    pub warnings: Vec<String>,
    pub elapsed_ms: u64,
    /// Measured spend: what the endpoint billed and how hard the context
    /// budget was pushed. Read back so the operator can tune the defaults from
    /// a run instead of from a guess.
    pub footprint: Footprint,
}

fn default_plan(target: &str) -> String {
    format!(
        "1. Resolve DNS for {target} and record the addresses.\n\
         2. Fingerprint TLS certificates and HTTP response headers.\n\
         3. Discover open TCP ports on the target.\n\
         4. Enumerate exposed paths and known web-server issues.\n\
         5. Correlate everything into findings with evidence."
    )
}

/// Run a complete assessment flow.
pub async fn run_flow(agent: &AgentCtx, opts: FlowOptions) -> anyhow::Result<FlowOutcome> {
    let started = std::time::Instant::now();
    let target = opts.target.trim().to_string();
    if target.is_empty() {
        anyhow::bail!("empty target");
    }
    let scope = agent.scope.render();
    agent.scope.require(&target).with_context(|| {
        format!("target `{target}` is outside the declared scope `{scope}`")
    })?;

    let flow_id = lantern_core::ids::new_flow();
    let order: Vec<RoleId> = if opts.roles.is_empty() {
        crate::roles::pipeline().to_vec()
    } else {
        opts.roles.clone()
    };
    agent.db.create_flow(
        &flow_id,
        &target,
        &scope,
        &json!({
            "offensive": opts.offensive,
            "roles": order.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "dry_run": agent.dry_run,
            "directive_chars": opts.directive.as_ref().map(|d| d.chars().count()).unwrap_or(0),
        }),
    )?;
    agent.db.set_flow_status(&flow_id, "running")?;
    agent.db.add_event(
        Some(&flow_id),
        None,
        "info",
        "flow",
        &format!("flow started for {target}"),
        Some(&json!({"scope": scope, "offensive": opts.offensive})),
    )?;

    let outcome = run_inner(agent, &flow_id, &target, &scope, &opts, &order).await;
    match &outcome {
        Ok(o) => {
            // Status, counters and spend were already on the row before the
            // report was rendered; only the completion event is left. An
            // aborted flow keeps its own status rather than being
            // re-labelled completed here.
            let status = agent
                .db
                .get_flow(&flow_id)?
                .map(|f| f.status)
                .unwrap_or_default();
            if status != "aborted" {
                agent.db.set_flow_status(&flow_id, "completed")?;
            }
            agent.db.add_event(
                Some(&flow_id),
                None,
                "info",
                "flow",
                &format!(
                    "flow {status}: {} finding(s) in {} ms",
                    o.findings,
                    started.elapsed().as_millis()
                ),
                None,
            )?;
        }
        Err(e) => {
            agent.db.set_flow_status(&flow_id, "failed")?;
            agent.db.add_event(
                Some(&flow_id),
                None,
                "error",
                "flow",
                &format!("flow failed: {e:#}"),
                None,
            )?;
        }
    }
    outcome
}

async fn run_inner(
    agent: &AgentCtx,
    flow_id: &str,
    target: &str,
    scope: &str,
    opts: &FlowOptions,
    order: &[RoleId],
) -> anyhow::Result<FlowOutcome> {
    let mut tool_ctx = agent
        .tool_ctx(Some(flow_id), opts.offensive)
        .context("creating the flow execution context")?;
    tool_ctx.interactive = opts.interactive;
    let memory = agent.memory(scope);
    let mut warnings: Vec<String> = Vec::new();
    let mut outcomes: Vec<RoleOutcome> = Vec::new();
    let mut steps = 0usize;
    let started = std::time::Instant::now();

    if opts.offensive && !agent.config.offensive {
        warnings.push(
            "flow requested active testing but the process was not started with --offensive"
                .to_string(),
        );
    }

    // --- plan -------------------------------------------------------------
    // The operator's words are stored verbatim as an artifact and travel
    // condensed into every objective: the model acts on the instruction, but
    // the 6,000-token working set cannot carry a whole framework per call.
    let directive_brief = opts
        .directive
        .as_deref()
        .map(|d| crate::intent::condense_directive(d, crate::intent::DIRECTIVE_CHARS));
    if let Some(full) = &opts.directive {
        if let Err(e) = tool_ctx.write_artifact("directive.md", full.as_bytes()) {
            warnings.push(format!("directive not stored: {e:#}"));
        }
    }
    emit(opts, ProgressEvent::PlanStarted);
    let plan = match plan_phase(agent, target, scope, opts.directive.as_deref()).await {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("planning failed, using the default plan: {e:#}"));
            default_plan(target)
        }
    };
    tool_ctx.set_plan(lantern_tools::tools::plan::steps_from_plan_text(&plan));
    if !agent.dry_run {
        outcomes.push(RoleOutcome {
            role: RoleId::Orchestrator,
            summary: plan.clone(),
            steps: 1,
            findings: 0,
            error: None,
        });
        steps += 1;
    }

    // --- roles ------------------------------------------------------------
    for id in order {
        if *id == RoleId::Orchestrator {
            continue; // already covered by the plan phase
        }
        emit(opts, ProgressEvent::RoleStarted(*id));
        let res = match id {
            RoleId::Planner => {
                let ordered = planner_phase(agent, flow_id, target, &tool_ctx.plan_text()).await;
                if let Ok(o) = &ordered {
                    // The planner's ordering becomes the live plan, so every
                    // later role - and every amendment - builds on it.
                    let steps = lantern_tools::tools::plan::steps_from_plan_text(&o.summary);
                    if steps.len() >= 2 {
                        tool_ctx.set_plan(steps);
                    }
                }
                ordered
            }
            RoleId::Reflector => reflect_phase(agent, flow_id, &mut warnings).await,
            _ => {
                let recalled = memory.recall(target, 5);
                let plan_now = tool_ctx.plan_text();
                let mut objective =
                    prompts::role_objective(*id, target, &plan_now, &Memory::render(&recalled));
                if let Some(brief) = &directive_brief {
                    objective = format!("OPERATOR DIRECTIVE:\n{brief}\n\n{objective}");
                }
                run_role(
                    agent,
                    flow_id,
                    target,
                    scope,
                    opts,
                    &tool_ctx,
                    &memory,
                    *id,
                    objective,
                )
                .await
            }
        };
        match res {
            Ok(o) => {
                steps += o.steps;
                if let Some(err) = &o.error {
                    warnings.push(format!("{}: {err}", o.role));
                }
                emit(
                    opts,
                    ProgressEvent::RoleFinished {
                        role: o.role,
                        steps: o.steps,
                        error: o.error.is_some(),
                    },
                );
                outcomes.push(o);
            }
            Err(e) => {
                // An abort is reported once, at the break below - not once per
                // role on the way out.
                if !aborted(opts) {
                    warnings.push(format!("{} failed: {e:#}", id));
                }
                agent.db.add_event(
                    Some(flow_id),
                    None,
                    "error",
                    "role",
                    &format!("{id}: {e:#}"),
                    None,
                )?;
                emit(
                    opts,
                    ProgressEvent::RoleFinished {
                        role: *id,
                        steps: 0,
                        error: true,
                    },
                );
                outcomes.push(RoleOutcome {
                    role: *id,
                    summary: format!("failed: {e:#}"),
                    steps: 0,
                    findings: 0,
                    error: Some(format!("{e:#}")),
                });
            }
        }
        if aborted(opts) {
            warnings.push("aborted by operator".to_string());
            break;
        }
    }

    // --- report -----------------------------------------------------------
    // Rendered last, but describing a flow that is finished: status, counters
    // and spend go on the row *before* the report reads them. Otherwise every
    // report claims the flow is still running and quotes whatever fallback the
    // rows can offer instead of what the run measured.
    let footprint = agent.counters.snapshot();
    // An aborted flow is reported as aborted, not completed: the report must
    // say what actually happened.
    agent.db.set_flow_status(
        flow_id,
        if aborted(opts) { "aborted" } else { "completed" },
    )?;
    agent.db.set_flow_stats(flow_id, steps, tool_ctx.tool_call_count())?;
    agent.db.set_flow_footprint(
        flow_id,
        &json!({
            "input_tokens": footprint.input_tokens,
            "output_tokens": footprint.output_tokens,
            "peak_context": footprint.peak_context,
            "summarizations": footprint.summarizations,
            "budget_stops": footprint.budget_stops,
            "budget": agent.config.token_budget,
        }),
    )?;
    let findings_count = agent.db.findings_for_flow(flow_id)?.len();
    let path = report::write(&agent.config, &agent.db, flow_id)
        .context("writing the report")
        .map_err(|e| {
            warnings.push(format!("report not written: {e:#}"));
            e
        })
        .ok();

    Ok(FlowOutcome {
        flow_id: flow_id.to_string(),
        plan: tool_ctx.plan_text(),
        roles: outcomes,
        findings: findings_count,
        steps,
        tool_calls: tool_ctx.tool_call_count(),
        report: path,
        warnings,
        elapsed_ms: started.elapsed().as_millis() as u64,
        footprint,
    })
}

async fn plan_phase(
    agent: &AgentCtx,
    target: &str,
    scope: &str,
    directive: Option<&str>,
) -> anyhow::Result<String> {
    if agent.dry_run {
        return Ok(default_plan(target));
    }
    let mut prompt = prompts::plan_objective(target, scope);
    if let Some(d) = directive {
        prompt.push_str("\n\nOPERATOR DIRECTIVE:\n");
        prompt.push_str(&crate::intent::condense_directive(
            d,
            crate::intent::DIRECTIVE_CHARS,
        ));
    }
    let text = agent
        .complete(&prompt, 500)
        .await
        .context("orchestrator call")?;
    let text = text.trim().to_string();
    if text.is_empty() {
        anyhow::bail!("empty plan");
    }
    Ok(text)
}

async fn planner_phase(
    agent: &AgentCtx,
    flow_id: &str,
    target: &str,
    plan: &str,
) -> anyhow::Result<RoleOutcome> {
    let text = if agent.dry_run {
        format!("(scripted ordering of the plan for {target})")
    } else {
        let prompt = format!(
            "Reorder this assessment plan by risk and effort, one numbered step per line, \
             naming the tool each step needs. Answer with the list only.\n\n{plan}"
        );
        agent.complete(&prompt, 500).await?
    };
    agent.db.insert_task(
        flow_id,
        RoleId::Planner.as_str(),
        "plan",
        &json!({"steps": lantern_core::text_clip(&text, 400)}),
    )?;
    Ok(RoleOutcome {
        role: RoleId::Planner,
        summary: text,
        steps: 1,
        findings: 0,
        error: None,
    })
}

/// The tool-calling loop for one role.
async fn run_role(
    agent: &AgentCtx,
    flow_id: &str,
    target: &str,
    scope: &str,
    opts: &FlowOptions,
    tool_ctx: &ToolCtx,
    memory: &Memory,
    id: RoleId,
    objective: String,
) -> anyhow::Result<RoleOutcome> {
    let meta = role(id);
    let task = agent.db.insert_task(
        flow_id,
        id.as_str(),
        "role",
        &json!({"objective": lantern_core::text_clip(&objective, 300)}),
    )?;
    agent.db.task_started(task)?;

    let boost = opts
        .extra_steps
        .iter()
        .find(|(r, _)| *r == id)
        .map(|(_, n)| *n)
        .unwrap_or(0);
    let boosted_default = meta.max_steps + boost;
    let max_steps = match opts.max_steps {
        // An explicit --steps is the operator's own hard ceiling and still
        // wins over a vocabulary-earned boost, the same way --offensive is
        // always the final word over what a prompt asks for.
        Some(n) => boosted_default.min(n.max(1)),
        None => boosted_default,
    };
    let budget = Duration::from_secs(
        max_steps as u64 * (agent.config.llm.timeout_secs.saturating_add(60)),
    );

    let looped = tokio::time::timeout(
        budget,
        role_loop(
            agent, id, target, scope, &objective, tool_ctx, memory, max_steps, opts,
        ),
    )
    .await;

    match looped {
        Err(_) => {
            let msg = format!("role exceeded its {}s time budget", budget.as_secs());
            agent
                .db
                .task_finished(task, "error", None, Some(&msg))
                .ok();
            anyhow::bail!(msg);
        }
        Ok(Err(e)) => {
            agent
                .db
                .task_finished(task, "error", None, Some(&format!("{e:#}")))
                .ok();
            return Err(e);
        }
        Ok(Ok((text, steps))) => {
            let mut count = 0usize;
            if meta.emits_findings {
                for f in findings::extract(&text) {
                    agent.db.add_finding(flow_id, &f)?;
                    count += 1;
                }
            }
            if !text.trim().is_empty() {
                memory.remember(id.as_str(), &text).await;
            }
            agent.db.task_finished(
                task,
                "done",
                Some(&json!({
                    "summary": lantern_core::text_clip(&text, 400),
                    "findings": count,
                    "steps": steps,
                })),
                None,
            )?;
            Ok(RoleOutcome {
                role: id,
                summary: lantern_core::text_clip(&text, 600),
                steps,
                findings: count,
                error: None,
            })
        }
    }
}

/// Returns (final text, model steps used).
async fn role_loop(
    agent: &AgentCtx,
    id: RoleId,
    target: &str,
    scope: &str,
    objective: &str,
    tool_ctx: &ToolCtx,
    memory: &Memory,
    max_steps: usize,
    opts: &FlowOptions,
) -> anyhow::Result<(String, usize)> {
    let meta = role(id);
    let system = prompts::system(
        meta,
        target,
        scope,
        tool_ctx.offensive,
        opts.engagement_profile,
    );
    let mut window = ContextWindow::new(
        agent.config.token_budget,
        agent.config.summarize_at,
        agent.config.keep_recent_tokens,
    );
    window.push(Message::user(objective));

    // Scoped to this role's own focus: every role already pays this cost on
    // every request, and `meta.focus` is exactly what the system prompt's
    // `YOUR TOOLS:` line already told the model it may use - sending schemas
    // for everything else is pure overhead that only grows as the registry
    // does. A role with no declared focus (there are none on the tool-calling
    // path today) falls back to the full registry rather than silently
    // seeing nothing.
    let defs = agent.registry.defs_for(meta.focus);
    let mut text = String::new();
    let mut steps = 0usize;
    // Shared across every `delegate_task` call this role makes this
    // invocation - see `run_delegate_task`. Decremented by whatever a
    // sub-task actually spent, so a role that calls it several times still
    // cannot multiply its own step budget unboundedly.
    let mut delegate_budget = lantern_tools::tools::delegate::TOTAL_STEP_BUDGET;

    while steps < max_steps {
        if aborted(opts) {
            anyhow::bail!("aborted by operator");
        }
        // Steering typed mid-flow joins the working set at the next boundary,
        // so the roles still to run act on it.
        if let Some(queue) = &opts.steering {
            // Drain into a local Vec and drop the lock before the first
            // `.await`: holding a std::sync::Mutex guard across an await
            // point blocks whoever next tries to lock it (chat's UI thread
            // pushing a newly typed steering line) for the duration of a
            // model/network call rather than a pointer swap.
            let lines: Vec<String> = {
                let mut queued = queue.lock().unwrap_or_else(|e| e.into_inner());
                queued.drain(..).collect()
            };
            for line in lines {
                memory.remember("operator", &line).await;
                window.push(Message::user(format!("OPERATOR (live steering): {line}")));
            }
        }
        let request = ChatRequest::new(window.render(&system))
            .with_tools(defs.clone())
            .max_tokens(agent.config.llm.max_output_tokens)
            .temperature(agent.config.llm.temperature);
        agent.counters.context(window.tokens());
        let reply = agent
            .chat(request)
            .await
            .with_context(|| format!("model call for {id}"))?;
        steps += 1;

        if !reply.message.content.trim().is_empty() {
            text.push_str(&reply.message.content);
            text.push('\n');
        }

        if reply.message.tool_calls.is_empty() {
            window.push(Message::assistant(reply.message.content.clone()));
            break;
        }

        window.push(Message::assistant_with_calls(
            reply.message.content.clone(),
            reply.message.tool_calls.clone(),
        ));

        for call in &reply.message.tool_calls {
            if aborted(opts) {
                anyhow::bail!("aborted by operator");
            }
            emit(opts, ProgressEvent::ToolCalled(call.name.clone()));
            // `delegate_task` is intercepted here, before the registry: the
            // real work needs to call the model, which lantern-tools has no
            // access to. This is the only place a delegated sub-task can be
            // started - see delegate.rs for why its own registry body fails
            // closed - and the only place `delegate_budget` is spent.
            let body = if call.name == "delegate_task" {
                run_delegate_task(
                    agent,
                    id,
                    target,
                    scope,
                    meta.focus,
                    tool_ctx,
                    memory,
                    opts,
                    call.args(),
                    &mut delegate_budget,
                )
                .await
            } else {
                match agent
                    .registry
                    .execute(&call.name, call.args(), tool_ctx)
                    .await
                {
                    Ok(out) => {
                        let data = lantern_core::text_clip(&out.data.to_string(), 500);
                        let combined = format!("{}\n\nDATA: {}", out.summary, data);
                        if out.summary.len() > 40 {
                            memory.remember("tool", &out.summary).await;
                        }
                        combined
                    }
                    Err(e) => format!("TOOL ERROR: {e:#}"),
                }
            };
            window.push(Message::tool(&call.id, ContextWindow::clip(&body, 700)));
        }

        if window.needs_summary() {
            let transcript = window.material_for_summary();
            let prompt = lantern_llm::context::summarization_prompt(&transcript);
            match agent.chat(ChatRequest::new(prompt).max_tokens(500)).await {
                Ok(reply) => {
                    window.apply_summary(reply.text().to_string());
                    agent.counters.summarization();
                }
                Err(e) => tracing::warn!(error = %e, "summarization failed; keeping the transcript"),
            }
        }
        agent.counters.context(window.tokens());
        if window.tokens() >= agent.config.token_budget {
            // The cap ends the role here, whatever it still had left to say.
            // Counted so a budget set too low shows up as stops instead of as
            // quietly shorter answers.
            agent.counters.budget_stop();
            break;
        }
    }

    Ok((text, steps))
}

/// Validate a `delegate_task` call and, if it passes, run the bounded
/// sub-task. Always returns a tool-response body (an error string on
/// refusal, never a hard failure of the parent role) - the same contract
/// every other tool call in this loop has.
#[allow(clippy::too_many_arguments)]
async fn run_delegate_task(
    agent: &AgentCtx,
    parent: RoleId,
    target: &str,
    scope: &str,
    parent_focus: &[&str],
    tool_ctx: &ToolCtx,
    memory: &Memory,
    opts: &FlowOptions,
    args: serde_json::Value,
    delegate_budget: &mut usize,
) -> String {
    let objective = match args.get("objective").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return "TOOL ERROR: delegate_task needs a non-empty `objective`".into(),
    };
    let requested: Vec<String> = match args.get("tools").and_then(|v| v.as_array()) {
        Some(a) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        None => return "TOOL ERROR: delegate_task needs a `tools` array".into(),
    };
    if requested.is_empty() {
        return "TOOL ERROR: delegate_task's `tools` array is empty - name at least one".into();
    }
    // The sub-task's tool set can only ever be a subset of what the parent
    // already has - and can never include delegate_task itself, however the
    // parent's own focus is defined, so a delegated sub-task can never
    // delegate again. This check is what makes that true; it does not rely
    // on the sub-loop's own tool defs happening to exclude it (though they
    // do too - see delegated_loop).
    let mut tools: Vec<&str> = Vec::new();
    for want in &requested {
        if want == "delegate_task" {
            return "TOOL ERROR: delegate_task cannot be delegated to a sub-task".into();
        }
        match parent_focus.iter().find(|f| *f == want) {
            Some(f) => tools.push(f),
            None => {
                return format!(
                    "TOOL ERROR: `{want}` is not one of your own tools, so a sub-task cannot \
                     have it either"
                )
            }
        }
    }
    let max_steps = args
        .get("max_steps")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(3)
        .clamp(1, lantern_tools::tools::delegate::MAX_STEPS_PER_CALL)
        .min(*delegate_budget);
    if max_steps == 0 {
        return format!(
            "TOOL ERROR: delegated-task budget exhausted for this turn \
             ({} steps already spent across earlier delegate_task calls)",
            lantern_tools::tools::delegate::TOTAL_STEP_BUDGET
        );
    }

    let result = delegated_loop(
        agent, parent, target, scope, &objective, &tools, max_steps, tool_ctx, memory, opts,
    )
    .await;

    match result {
        Ok((text, spent)) => {
            *delegate_budget = delegate_budget.saturating_sub(spent);
            format!("DELEGATED SUB-TASK RESULT ({spent} step(s) spent):\n{text}")
        }
        Err(e) => format!("TOOL ERROR: delegated sub-task failed: {e:#}"),
    }
}

/// The bounded sub-loop itself. Structurally a smaller copy of `role_loop`,
/// not a call to it: a delegated sub-task is not a `Role` (no findings
/// contract, no static focus list, no mission beyond the objective it was
/// given), and keeping the two loops textually separate means the one
/// property that matters most - this loop's own tool defs never include
/// `delegate_task`, so a sub-task cannot delegate again - is visible by
/// reading this function alone, not by tracing a shared one with branches.
/// Returns (condensed answer, steps actually spent).
#[allow(clippy::too_many_arguments)]
async fn delegated_loop(
    agent: &AgentCtx,
    parent: RoleId,
    target: &str,
    scope: &str,
    objective: &str,
    tools: &[&str],
    max_steps: usize,
    tool_ctx: &ToolCtx,
    memory: &Memory,
    opts: &FlowOptions,
) -> anyhow::Result<(String, usize)> {
    let system = prompts::delegated_system(parent, target, scope, tool_ctx.offensive, tools);
    let mut window = ContextWindow::new(
        agent.config.token_budget,
        agent.config.summarize_at,
        agent.config.keep_recent_tokens,
    );
    window.push(Message::user(objective.to_string()));
    let defs = agent.registry.defs_for(tools);
    let mut text = String::new();
    let mut steps = 0usize;

    while steps < max_steps {
        if aborted(opts) {
            anyhow::bail!("aborted by operator");
        }
        let request = ChatRequest::new(window.render(&system))
            .with_tools(defs.clone())
            .max_tokens(agent.config.llm.max_output_tokens)
            .temperature(agent.config.llm.temperature);
        agent.counters.context(window.tokens());
        let reply = agent
            .chat(request)
            .await
            .with_context(|| format!("delegated sub-task call for {parent}"))?;
        steps += 1;

        if !reply.message.content.trim().is_empty() {
            text.push_str(&reply.message.content);
            text.push('\n');
        }
        if reply.message.tool_calls.is_empty() {
            window.push(Message::assistant(reply.message.content.clone()));
            break;
        }
        window.push(Message::assistant_with_calls(
            reply.message.content.clone(),
            reply.message.tool_calls.clone(),
        ));

        for call in &reply.message.tool_calls {
            if aborted(opts) {
                anyhow::bail!("aborted by operator");
            }
            // Defense in depth: `defs` above never includes delegate_task,
            // so the model has no schema for it here - but refuse by name
            // too rather than trust that alone.
            if call.name == "delegate_task" {
                window.push(Message::tool(
                    &call.id,
                    "TOOL ERROR: delegation is not available inside a delegated sub-task",
                ));
                continue;
            }
            emit(opts, ProgressEvent::ToolCalled(call.name.clone()));
            let body = match agent
                .registry
                .execute(&call.name, call.args(), tool_ctx)
                .await
            {
                Ok(out) => {
                    let data = lantern_core::text_clip(&out.data.to_string(), 500);
                    let combined = format!("{}\n\nDATA: {}", out.summary, data);
                    if out.summary.len() > 40 {
                        memory.remember("delegated-tool", &out.summary).await;
                    }
                    combined
                }
                Err(e) => format!("TOOL ERROR: {e:#}"),
            };
            window.push(Message::tool(&call.id, ContextWindow::clip(&body, 700)));
        }
    }

    Ok((lantern_core::text_clip(&text, 1_500), steps))
}

/// Review every finding for evidence quality and severity accuracy. Never
/// fatal: the report ships either way.
async fn reflect_phase(
    agent: &AgentCtx,
    flow_id: &str,
    warnings: &mut Vec<String>,
) -> anyhow::Result<RoleOutcome> {
    let found = agent.db.findings_for_flow(flow_id)?;
    if found.is_empty() {
        return Ok(RoleOutcome {
            role: RoleId::Reflector,
            summary: "no findings to review".into(),
            steps: 0,
            findings: 0,
            error: None,
        });
    }

    let mut reviewed = 0usize;
    // A scripted run makes no model calls, the same as every other phase here.
    if !agent.dry_run {
        let prompt = format!(
            "Review these findings for evidence quality and severity accuracy. \
             One line each, prefix `NAME:` with a confidence from 0 to 1.\n\n{}",
            findings_json(&found)
        );
        match agent.complete(&prompt, 500).await {
            Ok(text) => {
                agent.db.insert_task(
                    flow_id,
                    RoleId::Reflector.as_str(),
                    "review",
                    &json!({"review": lantern_core::text_clip(&text, 500)}),
                )?;
                reviewed = found.len();
            }
            Err(e) => warnings.push(format!("review skipped: {e:#}")),
        }
    }

    let summary = if reviewed == found.len() {
        format!("reviewed {reviewed} finding(s)")
    } else {
        format!("reviewed {reviewed} of {} finding(s)", found.len())
    };
    Ok(RoleOutcome {
        role: RoleId::Reflector,
        summary,
        steps: 1,
        findings: found.len(),
        error: None,
    })
}

fn findings_json(found: &[lantern_core::storage::models::Finding]) -> String {
    let arr: Vec<serde_json::Value> = found
        .iter()
        .map(|f| {
            json!({
                "title": f.title,
                "severity": f.severity,
                "asset": f.asset,
                "port": f.port,
                "description": f.description,
                "evidence": f.evidence,
                "confidence": f.confidence,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Array(arr))
        .unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::AgentCtx;
    use lantern_core::config::{Config, Paths};
    use lantern_llm::mock::{MockProvider, Scripted};

    fn config() -> Config {
        let root = std::env::temp_dir().join(format!(
            "lantern-run-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut c = Config::load().unwrap();
        c.paths = Paths::new(root);
        c.allowlist = vec!["nmap".into()];
        c
    }

    fn scripted(script: Vec<Scripted>) -> AgentCtx {
        AgentCtx::new(config(), "127.0.0.1, localhost", true)
            .unwrap()
            .with_provider(std::sync::Arc::new(MockProvider::with_script(script)))
    }

    fn findings_reply() -> Scripted {
        Scripted::Text(
            r#"Done. Findings:
```json
{"findings":[{"title":"Closed port 1","severity":"info","asset":"127.0.0.1",
"description":"Nothing is listening on the probed port.",
"evidence":"port_scan -> 0 open of 1 probed","confidence":0.9}]}
```"#
                .into(),
        )
    }

    #[tokio::test]
    async fn runs_the_pipeline_with_a_scripted_model() {
        let agent = scripted(vec![
            Scripted::ToolCall {
                name: "port_scan".into(),
                arguments: r#"{"host":"127.0.0.1","ports":"1"}"#.into(),
            },
            findings_reply(),
            findings_reply(),
            findings_reply(),
        ]);
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher, RoleId::Coder, RoleId::Pentester]);
        let out = run_flow(&agent, opts).await.expect("flow runs");

        assert!(out.findings >= 1, "at least one finding: {out:?}");
        assert!(out.steps > 0);
        assert!(out.report.is_some(), "report path: {:?}", out.warnings);
        let body = std::fs::read_to_string(out.report.unwrap()).unwrap();
        assert!(body.contains("Closed port 1"));
        // The report describes a finished flow: final status, the counters the
        // run measured and what it spent - not what the rows held before the
        // last role returned.
        assert!(body.contains("Status: completed"), "not still running: {body}");
        assert!(
            body.contains(&format!("{} model step(s)", out.steps)),
            "quoted step counter: {body}"
        );
        assert!(body.contains("Context peaked at"), "spend is recorded: {body}");
        assert!(body.contains("tokens"), "token line: {body}");

        let flow = agent.db.get_flow(&out.flow_id).unwrap().unwrap();
        assert_eq!(flow.status, "completed");
        assert_eq!(flow.target, "127.0.0.1");
    }

    #[tokio::test]
    async fn a_role_can_amend_the_plan_and_the_outcome_shows_it() {
        let agent = scripted(vec![
            Scripted::ToolCall {
                name: "plan_patch".into(),
                arguments: r#"{"add":"crack the captured hash with host_john"}"#.into(),
            },
            findings_reply(),
        ]);
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher]);
        let out = run_flow(&agent, opts).await.expect("flow runs");

        assert!(
            out.plan.contains("crack the captured hash with host_john"),
            "plan: {}",
            out.plan
        );
        // The default plan has five steps: the amendment lands as the sixth,
        // and the whole list is renumbered rather than appended to blindly.
        assert!(
            out.plan.ends_with("6. crack the captured hash with host_john"),
            "{}",
            out.plan
        );
        assert!(out.plan.starts_with("1. "), "{}", out.plan);
    }

    #[tokio::test]
    async fn refuses_targets_outside_scope_before_anything_happens() {
        let agent = scripted(vec![]);
        let err = run_flow(&agent, FlowOptions::new("10.99.99.99", "127.0.0.1"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
        assert!(agent.db.list_flows(10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_target_is_rejected() {
        let agent = scripted(vec![]);
        let err = run_flow(&agent, FlowOptions::new("  ", "127.0.0.1"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty target"), "got: {err}");
    }

    #[tokio::test]
    async fn default_plan_is_used_in_dry_run() {
        let agent = scripted(vec![]);
        let p = plan_phase(&agent, "127.0.0.1", "127.0.0.1", None)
            .await
            .unwrap();
        assert!(p.contains("Resolve DNS"));
    }
    #[tokio::test]
    async fn a_directive_is_stored_and_names_the_flow_options() {
        let agent = scripted(vec![findings_reply()]);
        let mut opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher]);
        opts.directive = Some("MISSION: check TLS\nTARGETS: 127.0.0.1".into());
        let out = run_flow(&agent, opts).await.expect("flow runs");

        let artifact = agent
            .config
            .paths
            .artifacts()
            .join(&out.flow_id)
            .join("directive.md");
        let stored = std::fs::read_to_string(&artifact).expect("directive artifact");
        assert!(stored.contains("MISSION: check TLS"), "{stored}");

        let flow = agent.db.get_flow(&out.flow_id).unwrap().unwrap();
        assert_eq!(flow.options["directive_chars"].as_u64().unwrap(), 37);
    }

    #[tokio::test]
    async fn an_aborted_flow_reports_aborted_with_what_it_finished() {
        let agent = scripted(vec![findings_reply(), findings_reply()]);
        let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher, RoleId::Coder]);
        opts.abort = Some(abort);
        let out = run_flow(&agent, opts).await.expect("abort is not an error");

        let flow = agent.db.get_flow(&out.flow_id).unwrap().unwrap();
        assert_eq!(flow.status, "aborted");
        assert!(
            out.warnings.iter().any(|w| w.contains("aborted")),
            "warnings: {:?}",
            out.warnings
        );
        // The second role never ran: the abort stopped the pipeline.
        assert!(
            !out.roles.iter().any(|r| r.role == RoleId::Coder),
            "roles: {:?}",
            out.roles.iter().map(|r| r.role).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn progress_events_cover_a_role_from_start_to_finish() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_sink = seen.clone();
        let agent = scripted(vec![
            Scripted::ToolCall {
                name: "port_scan".into(),
                arguments: r#"{"host":"127.0.0.1","ports":"1"}"#.into(),
            },
            findings_reply(),
        ]);
        let mut opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher]);
        opts.progress = Some(std::sync::Arc::new(move |ev| {
            sink_sink.lock().unwrap().push(format!("{ev:?}"));
        }));
        run_flow(&agent, opts).await.expect("flow runs");

        let log = seen.lock().unwrap().join("\n");
        assert!(log.contains("RoleStarted(Researcher)"), "{log}");
        assert!(log.contains("ToolCalled(\"port_scan\")"), "{log}");
        assert!(log.contains("RoleFinished"), "{log}");
    }

    // --- delegate_task -----------------------------------------------------

    #[tokio::test]
    async fn a_role_can_delegate_a_bounded_sub_task_end_to_end() {
        // researcher's own call -> delegate_task; the delegated sub-loop's
        // one call -> plain text, no further tool calls, ending the
        // sub-task at 1 step; back in the role's own loop -> findings.
        let agent = scripted(vec![
            Scripted::ToolCall {
                name: "delegate_task".into(),
                arguments: r#"{"objective":"resolve example.com","tools":["dns_lookup"],"max_steps":2}"#.into(),
            },
            Scripted::Text("sub-task done: A record found".into()),
            findings_reply(),
        ]);
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1, localhost")
            .roles(vec![RoleId::Researcher]);
        let out = run_flow(&agent, opts).await.expect("flow runs");
        assert!(out.findings >= 1, "the role still reaches its own findings: {out:?}");
    }

    #[tokio::test]
    async fn delegation_cannot_grant_a_tool_the_parent_does_not_have() {
        let agent = scripted(vec![]);
        let tool_ctx = agent.tool_ctx(None, false).unwrap();
        let memory = agent.memory("test");
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1");
        let mut budget = lantern_tools::tools::delegate::TOTAL_STEP_BUDGET;

        let body = run_delegate_task(
            &agent,
            RoleId::Researcher,
            "127.0.0.1",
            "127.0.0.1",
            role(RoleId::Researcher).focus,
            &tool_ctx,
            &memory,
            &opts,
            serde_json::json!({"objective": "x", "tools": ["host_msfconsole"]}),
            &mut budget,
        )
        .await;
        assert!(body.contains("TOOL ERROR"), "{body}");
        assert!(body.contains("host_msfconsole"), "{body}");
        assert_eq!(budget, lantern_tools::tools::delegate::TOTAL_STEP_BUDGET, "a refused call spends nothing");
    }

    #[tokio::test]
    async fn delegation_cannot_delegate_itself() {
        let agent = scripted(vec![]);
        let tool_ctx = agent.tool_ctx(None, false).unwrap();
        let memory = agent.memory("test");
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1");
        let mut budget = lantern_tools::tools::delegate::TOTAL_STEP_BUDGET;

        let body = run_delegate_task(
            &agent,
            RoleId::Pentester,
            "127.0.0.1",
            "127.0.0.1",
            role(RoleId::Pentester).focus,
            &tool_ctx,
            &memory,
            &opts,
            serde_json::json!({"objective": "x", "tools": ["delegate_task"]}),
            &mut budget,
        )
        .await;
        assert!(body.contains("TOOL ERROR"), "{body}");
        assert!(body.to_lowercase().contains("cannot be delegated"), "{body}");
    }

    #[tokio::test]
    async fn empty_objective_and_empty_tools_are_both_refused() {
        let agent = scripted(vec![]);
        let tool_ctx = agent.tool_ctx(None, false).unwrap();
        let memory = agent.memory("test");
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1");

        let mut budget = lantern_tools::tools::delegate::TOTAL_STEP_BUDGET;
        let body = run_delegate_task(
            &agent, RoleId::Researcher, "127.0.0.1", "127.0.0.1",
            role(RoleId::Researcher).focus, &tool_ctx, &memory, &opts,
            serde_json::json!({"objective": "  ", "tools": ["dns_lookup"]}),
            &mut budget,
        ).await;
        assert!(body.contains("objective"), "{body}");

        let mut budget = lantern_tools::tools::delegate::TOTAL_STEP_BUDGET;
        let body = run_delegate_task(
            &agent, RoleId::Researcher, "127.0.0.1", "127.0.0.1",
            role(RoleId::Researcher).focus, &tool_ctx, &memory, &opts,
            serde_json::json!({"objective": "find things", "tools": []}),
            &mut budget,
        ).await;
        assert!(body.contains("TOOL ERROR"), "{body}");
    }

    #[tokio::test]
    async fn total_delegate_budget_is_enforced_across_calls() {
        let agent = scripted(vec![]);
        let tool_ctx = agent.tool_ctx(None, false).unwrap();
        let memory = agent.memory("test");
        let opts = FlowOptions::new("127.0.0.1", "127.0.0.1");
        let mut budget = 0usize; // already exhausted by earlier (hypothetical) calls

        let body = run_delegate_task(
            &agent, RoleId::Researcher, "127.0.0.1", "127.0.0.1",
            role(RoleId::Researcher).focus, &tool_ctx, &memory, &opts,
            serde_json::json!({"objective": "find things", "tools": ["dns_lookup"]}),
            &mut budget,
        ).await;
        assert!(body.contains("budget exhausted"), "{body}");
    }
}
