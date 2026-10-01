//! `lantern chat` - a conversational terminal over the assessment flow.
//!
//! One screen, no alternate buffer: the transcript lives in the terminal's own
//! scrollback and the UI owns a small viewport at the bottom (status, activity,
//! composer). A `/` palette switches session settings, an approval card
//! answers the one question the gate asks, and Esc stops a running flow at the
//! next step boundary.
//!
//! What this is not: roles cannot stop for questions here. `ask_operator`
//! reads stdin, which the terminal owns while the UI runs, so flows started
//! from chat always run non-interactively - steer them with a typed line
//! while they work instead.

use lantern_agent::{intent, run_flow, AgentCtx, FlowOptions, ProgressEvent};
use lantern_core::budget::{dir_size, Budget};
use lantern_core::config::Config;
use lantern_core::retention;
use lantern_core::storage::Db;
use std::io::IsTerminal as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Widget as _, Wrap};
use ratatui::{DefaultTerminal, Frame, TerminalOptions, Viewport};
use tokio::sync::mpsc::UnboundedReceiver;
use unicode_width::UnicodeWidthStr;

pub struct Args {
    pub target: Option<String>,
    pub scope: Option<String>,
    pub roles: Option<String>,
    pub offensive: bool,
    pub dry_run: bool,
    pub steps: Option<usize>,
}

/// Viewport rows: status (1) + body (7) + composer (2).
const VIEWPORT_H: u16 = 10;
/// Progress lines kept in the activity trail.
const TRAIL_CAP: usize = 6;
/// Instruction size cap, same as `ask`: a framework is ~15 KB.
const MAX_PROMPT_BYTES: usize = 128 * 1024;

// --- session ---------------------------------------------------------------

#[derive(Debug, Default)]
struct Session {
    target: Option<String>,
    scope: Option<String>,
    roles: Option<String>,
    offensive: bool,
    dry_run: bool,
    steps: Option<usize>,
}

// --- composer ----------------------------------------------------------------
// Single-line editor with history. Pure state, no terminal: tested below.

#[derive(Debug, Default)]
struct Composer {
    text: String,
    /// Byte index, always a char boundary.
    cursor: usize,
    history: Vec<String>,
    /// Position in history being shown, if any.
    hist_pos: Option<usize>,
    /// Text stashed while browsing history.
    saved: String,
}

/// Largest byte index `<= i` that lands on a `char` boundary of `s`.
/// Equivalent to the standard library's `str::floor_char_boundary`, which
/// stabilized in Rust 1.91 - after this project's declared MSRV of 1.85
/// (`Cargo.toml`, README). Reimplemented here rather than relying on a
/// toolchain newer than the one the project claims to support; `0` is
/// always a boundary, so the loop terminates.
fn floor_char_boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut j = i;
    while j > 0 && !s.is_char_boundary(j) {
        j -= 1;
    }
    j
}

impl Composer {
    fn floor(&mut self) {
        self.cursor = floor_char_boundary(&self.text, self.cursor).min(self.text.len());
    }

    fn insert(&mut self, s: &str) {
        self.floor();
        // One line only: pasted newlines become spaces, Enter stays submit.
        let clean: String = s
            .chars()
            .map(|c| if c == '\n' { ' ' } else { c })
            .collect();
        self.text.insert_str(self.cursor, &clean);
        self.cursor += clean.len();
        self.hist_pos = None;
    }

    fn move_left(&mut self) {
        self.floor();
        if self.cursor == 0 {
            return;
        }
        let mut prev = 0;
        for (i, _) in self.text.char_indices() {
            if i >= self.cursor {
                break;
            }
            prev = i;
        }
        self.cursor = prev;
    }

    fn move_right(&mut self) {
        self.floor();
        if self.cursor >= self.text.len() {
            return;
        }
        let mut next = self.text.len();
        for (i, _) in self.text.char_indices() {
            if i > self.cursor {
                next = i;
                break;
            }
        }
        self.cursor = next;
    }

    fn backspace(&mut self) {
        self.floor();
        if self.cursor == 0 {
            return;
        }
        let mut prev = 0;
        for (i, _) in self.text.char_indices() {
            if i >= self.cursor {
                break;
            }
            prev = i;
        }
        self.text.drain(prev..self.cursor);
        self.cursor = prev;
        self.hist_pos = None;
    }

    fn kill_line(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.hist_pos = None;
    }

    /// Take the line for submission. Empty lines submit nothing.
    fn submit(&mut self) -> Option<String> {
        let line = self.text.trim().to_string();
        self.text.clear();
        self.cursor = 0;
        self.hist_pos = None;
        self.saved.clear();
        if line.is_empty() {
            return None;
        }
        if self.history.last().map(|h| h != &line).unwrap_or(true) {
            self.history.push(line.clone());
        }
        Some(line)
    }

    fn recall(&mut self, older: bool) {
        if self.history.is_empty() {
            return;
        }
        match self.hist_pos {
            None if older => {
                self.saved = std::mem::take(&mut self.text);
                self.hist_pos = Some(self.history.len() - 1);
            }
            Some(i) => {
                let next = if older {
                    i.saturating_sub(1)
                } else {
                    i + 1
                };
                if next >= self.history.len() {
                    self.text = std::mem::take(&mut self.saved);
                    self.hist_pos = None;
                } else {
                    self.hist_pos = Some(next);
                }
            }
            None => return,
        }
        if let Some(i) = self.hist_pos {
            self.text = self.history[i].clone();
        }
        self.cursor = self.text.len();
    }

    /// Display width of the text before the cursor (for cursor placement).
    fn cursor_width(&self) -> usize {
        let end = floor_char_boundary(&self.text, self.cursor).min(self.text.len());
        UnicodeWidthStr::width(&self.text[..end])
    }
}

// --- palette -----------------------------------------------------------------

struct PaletteCmd {
    name: &'static str,
    desc: &'static str,
    needs_args: bool,
}

const COMMANDS: &[PaletteCmd] = &[
    PaletteCmd { name: "help", desc: "list commands and keys", needs_args: false },
    PaletteCmd { name: "target", desc: "set target (/target example.com)", needs_args: true },
    PaletteCmd { name: "scope", desc: "set scope (/scope a.com, 1.2.3.0/24)", needs_args: true },
    PaletteCmd { name: "roles", desc: "set roles (/roles researcher,pentester)", needs_args: true },
    PaletteCmd { name: "offensive", desc: "gated tools on|off", needs_args: true },
    PaletteCmd { name: "dry-run", desc: "scripted runs on|off", needs_args: true },
    PaletteCmd { name: "steps", desc: "cap steps per role (/steps 4)", needs_args: true },
    PaletteCmd { name: "new", desc: "start a fresh session (clears target/scope/roles)", needs_args: false },
    PaletteCmd { name: "flows", desc: "list recorded flows", needs_args: false },
    PaletteCmd { name: "delete", desc: "permanently remove a flow (/delete flw_... yes)", needs_args: true },
    PaletteCmd { name: "clear", desc: "clear the screen", needs_args: false },
    PaletteCmd { name: "quit", desc: "exit", needs_args: false },
];

/// Indices into COMMANDS matching the query (prefix match on the name).
fn palette_matches(query: &str) -> Vec<usize> {
    let q = query.trim().to_ascii_lowercase();
    COMMANDS
        .iter()
        .enumerate()
        .filter(|(_, c)| c.name.starts_with(&q))
        .map(|(i, _)| i)
        .collect()
}

/// An exactly typed name wins over the highlight, so a fully typed command
/// never runs its alphabetically-earlier neighbour sitting on row zero.
fn palette_pick(items: &[usize], typed: &str, sel: usize) -> usize {
    if let Some(first) = typed.split_whitespace().next() {
        let want = first.trim_start_matches('/').to_ascii_lowercase();
        if let Some(i) = items.iter().find(|i| COMMANDS[**i].name == want).copied() {
            return i;
        }
    }
    items.get(sel).or(items.first()).copied().unwrap_or(0)
}

/// First whitespace-separated word, if any.
fn first_word(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

/// The word being completed after `/` ("" when the box holds just "/").
fn palette_query(ui: &Ui) -> &str {
    first_word(ui.composer.text.trim_start_matches('/'))
}

// --- approval ----------------------------------------------------------------
// The gate's one question: a prompt asked for active testing without the
// session allowing it. Allow-once grants this flow only; deny (or Esc, which
// is deny-by-inaction) keeps reconnaissance.

/// Resolve an approval keystroke. Returns the decision, if made.
fn approval_key(code: &KeyCode, sel: &mut usize) -> Option<bool> {
    match code {
        KeyCode::Char('1') => Some(true),
        KeyCode::Char('2') => Some(false),
        KeyCode::Left => {
            *sel = 0;
            None
        }
        KeyCode::Right => {
            *sel = 1;
            None
        }
        KeyCode::Enter => Some(*sel == 0),
        KeyCode::Esc => Some(false),
        _ => None,
    }
}

// --- transcript --------------------------------------------------------------

/// Wrap one logical line to terminal width (greedy, word-aware).
fn wrap_line(line: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if UnicodeWidthStr::width(line) <= width {
        return vec![line.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in line.split(' ') {
        let w = UnicodeWidthStr::width(word);
        let add = if cur.is_empty() { w } else { w + 1 };
        if cur_w + add > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        if !cur.is_empty() {
            cur.push(' ');
            cur_w += 1;
        }
        out_word(&mut cur, &mut cur_w, word, w, width);
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// Append one word; a word wider than the screen is hard-clipped rather than
/// wrapped mid-word forever.
fn out_word(cur: &mut String, cur_w: &mut usize, word: &str, w: usize, width: usize) {
    if w <= width {
        cur.push_str(word);
        *cur_w += w;
        return;
    }
    for c in word.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
        if *cur_w + cw > width {
            break;
        }
        cur.push(c);
        *cur_w += cw;
    }
}

// --- ui state ------------------------------------------------------------------

struct Running {
    handle: std::thread::JoinHandle<FlowDone>,
    progress_rx: UnboundedReceiver<ProgressEvent>,
    abort: Arc<AtomicBool>,
    steering: Arc<std::sync::Mutex<Vec<String>>>,
    started: Instant,
    role: String,
    steps: usize,
    tools: usize,
}

/// What the flow thread hands back: the agent (for the outcome block) and the
/// flow result.
struct FlowDone {
    agent: AgentCtx,
    result: anyhow::Result<lantern_agent::FlowOutcome>,
}

struct PendingFlow {
    instruction: String,
}

struct Ui {
    session: Session,
    composer: Composer,
    /// Palette selection index within the current matches.
    palette_sel: usize,
    /// Activity trail (body area when no palette/approval is up).
    trail: Vec<String>,
    run: Option<Running>,
    /// Approval card selection (0 allow, 1 deny) with its pending flow.
    approval: Option<(usize, PendingFlow)>,
    model: String,
    flows: usize,
}

impl Ui {
    fn palette_open(&self) -> bool {
        self.approval.is_none() && self.run.is_none() && self.composer.text.starts_with('/')
    }

    fn status_spans(&self) -> Vec<Span<'static>> {
        let tgt = self.session.target.clone().unwrap_or_else(|| "-".into());
        let scope = self.session.scope.clone().unwrap_or_else(|| "-".into());
        let mut spans = vec![
            Span::styled(format!(" {tgt} "), Style::default().fg(Color::Cyan)),
            Span::raw(format!("| {scope} ")),
        ];
        if self.session.offensive {
            spans.push(Span::styled(" OFFENSIVE", Style::default().fg(Color::Red)));
        } else {
            spans.push(Span::styled(" recon", Style::default().fg(Color::Green)));
        }
        spans.push(Span::raw(format!(" | {} ", self.model)));
        if self.session.dry_run {
            spans.push(Span::styled("dry-run", Style::default().fg(Color::Yellow)));
            spans.push(Span::raw(" | "));
        }
        if let Some(r) = &self.run {
            let el = r.started.elapsed().as_secs();
            spans.push(Span::styled(
                format!("◌ {} · {} steps · {:02}:{:02}", r.role, r.steps, el / 60, el % 60),
                Style::default().fg(Color::Yellow),
            ));
        } else {
            spans.push(Span::styled("idle", Style::default().fg(Color::DarkGray)));
        }
        spans
    }
}

// --- terminal guard --------------------------------------------------------------

/// Restores the terminal no matter how the UI exits.
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

fn say(terminal: &mut DefaultTerminal, lines: &[String]) -> anyhow::Result<()> {
    let width = terminal.size().map(|s| s.width as usize).unwrap_or(100);
    for line in lines {
        for physical in wrap_line(line, width) {
            terminal.insert_before(1, |buf| {
                Paragraph::new(physical.clone()).render(buf.area, buf);
            })?;
        }
    }
    Ok(())
}

fn push_trail(ui: &mut Ui, line: String) {
    ui.trail.push(line);
    while ui.trail.len() > TRAIL_CAP {
        ui.trail.remove(0);
    }
}

fn on_progress(ui: &mut Ui, ev: ProgressEvent) {
    let Some(run) = &mut ui.run else { return };
    match ev {
        ProgressEvent::PlanStarted => push_trail(ui, "◇ plan".into()),
        ProgressEvent::RoleStarted(id) => {
            run.role = id.as_str().to_string();
            push_trail(ui, format!("◆ {}", id.as_str()));
        }
        ProgressEvent::ToolCalled(name) => {
            run.tools += 1;
            push_trail(ui, format!("  → {name}"));
        }
        ProgressEvent::RoleFinished { role, steps, error } => {
            run.steps += steps;
            let mark = if error { "!" } else { "✓" };
            push_trail(ui, format!("{mark} {} · {steps} steps", role.as_str()));
        }
    }
}

// --- drawing ---------------------------------------------------------------------

fn draw(ui: &mut Ui, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(2),
        ])
        .split(area);

    // Status bar.
    frame.render_widget(Paragraph::new(Line::from(ui.status_spans())), chunks[0]);

    // Body: approval card, palette, or activity trail.
    if let Some((sel, _)) = &ui.approval {
        let rows = vec![
            ListItem::new(if *sel == 0 {
                "▶ [1] allow once — this flow only"
            } else {
                "    [1] allow once — this flow only"
            }),
            ListItem::new(if *sel == 1 {
                "▶ [2] deny — stay reconnaissance"
            } else {
                "    [2] deny — stay reconnaissance"
            }),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" active testing was requested — allow it? (Esc denies) ");
        frame.render_widget(List::new(rows).block(block), chunks[1]);
    } else if ui.palette_open() {
        let items = palette_matches(palette_query(ui));
        let sel = ui.palette_sel.min(items.len().saturating_sub(1));
        let rows: Vec<ListItem> = items
            .iter()
            .enumerate()
            .map(|(row, i)| {
                let c = &COMMANDS[*i];
                let prefix = if row == sel { "→ " } else { "  " };
                ListItem::new(format!("{prefix}/{:<10} {}", c.name, c.desc))
            })
            .collect();
        let list = if rows.is_empty() {
            List::new(vec![ListItem::new("  no matching command")])
        } else {
            List::new(rows)
        };
        frame.render_widget(list, chunks[1]);
    } else if !ui.trail.is_empty() {
        let items: Vec<ListItem> = ui.trail.iter().map(|t| ListItem::new(t.as_str())).collect();
        frame.render_widget(List::new(items), chunks[1]);
    }

    // Composer: one line with horizontal scroll, hints below.
    let prompt_w = 2usize;
    let avail = chunks[2].width.saturating_sub(prompt_w as u16) as usize;
    let full_w = ui.composer.cursor_width();
    let inner = avail.saturating_sub(1).max(1);
    let skip_w = full_w.saturating_sub(inner);
    // Visible slice: drop leading chars until their width passes skip_w.
    let mut acc = 0usize;
    let mut start = ui.composer.text.len();
    for (i, c) in ui.composer.text.char_indices() {
        let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
        if acc + cw > skip_w {
            start = i;
            break;
        }
        acc += cw;
    }
    // When everything fits, start stays past the end: show it all.
    let visible = if skip_w == 0 {
        ui.composer.text.as_str()
    } else {
        &ui.composer.text[start..]
    };
    let cursor_x = (prompt_w + full_w - acc.min(full_w)) as u16;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(Color::Cyan)),
            Span::raw(visible.to_string()),
        ])),
        chunks[2],
    );
    let hints = if ui.run.is_some() {
        "Enter steer · Esc abort · ^C abort"
    } else {
        "Enter send · Esc abort · / commands · ^C quit"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            hints,
            Style::default().fg(Color::DarkGray),
        )]))
        .wrap(Wrap { trim: true }),
        ratatui::layout::Rect::new(chunks[2].x, chunks[2].y + 1, chunks[2].width, 1),
    );
    frame.set_cursor_position((
        chunks[2].x + cursor_x.min(chunks[2].width.saturating_sub(1)),
        chunks[2].y,
    ));
}

// --- flow control ------------------------------------------------------------------

fn degraded_note(config: &Config, dry_run: bool) -> Option<String> {
    if config.degraded() && !dry_run {
        let key_env = lantern_core::providers::by_id(&config.llm.provider)
            .and_then(|p| p.key_env)
            .unwrap_or("LANTERN_LLM_API_KEY");
        return Some(format!(
            "no generation key: export {key_env} (or `lantern setup`), or /dry-run on"
        ));
    }
    None
}

/// Validate and start a flow on its own thread (it owns its agent, so the
/// UI thread never blocks on model or tool calls). Notices go to the
/// scrollback; the running state lands in `ui.run`.
fn start_flow(
    ui: &mut Ui,
    terminal: &mut DefaultTerminal,
    config: &Config,
    instruction: &str,
    offensive: bool,
    handle: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    let Some(target) = ui.session.target.clone() else {
        say(terminal, &["set a target first (/target example.com)".into()])?;
        return Ok(());
    };
    let Some(scope_spec) = ui.session.scope.clone() else {
        say(terminal, &["set a scope first (/scope example.com)".into()])?;
        return Ok(());
    };
    if let Some(note) = degraded_note(config, ui.session.dry_run) {
        say(terminal, &[note])?;
        return Ok(());
    }
    let roles = match crate::run::parse_roles(ui.session.roles.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            say(terminal, &[format!("roles rejected: {e:#} (/roles to fix)")])?;
            return Ok(());
        }
    };

    let parsed = intent::parse_intent(instruction);
    if let Some(w) = crate::ask::target_warning(&target, &parsed.contract.target_list()) {
        say(terminal, &[format!("note: {w}")])?;
    }

    // The session's grant is an operator grant like the CLI flag: record it on
    // the per-flow config so the runtime's process-level check reads true.
    let mut flow_config = config.clone();
    flow_config.offensive = flow_config.offensive || offensive;
    let agent = match AgentCtx::new(flow_config, &scope_spec, ui.session.dry_run) {
        Ok(a) => a,
        Err(e) => {
            say(terminal, &[format!("could not start: {e:#}")])?;
            return Ok(());
        }
    };    let scope_render = agent.scope.render();
    let mut opts = FlowOptions::new(&target, &scope_render)
        .offensive(offensive)
        .roles(roles);
    opts.max_steps = ui.session.steps;
    opts.extra_steps = parsed.step_boosts();
    opts.engagement_profile = parsed.engagement_profile;
    opts.directive = Some(instruction.to_string());

    let (progress_tx, progress_rx) = tokio::sync::mpsc::unbounded_channel();
    opts.progress = Some(Arc::new(move |ev| {
        let _ = progress_tx.send(ev);
    }));
    let abort = Arc::new(AtomicBool::new(false));
    opts.abort = Some(abort.clone());
    let steering = Arc::new(std::sync::Mutex::new(Vec::new()));
    opts.steering = Some(steering.clone());

    say(
        terminal,
        &[format!("◆ assessing {target} ({})", if offensive { "active" } else { "recon" })],
    )?;
    ui.trail.clear();
    let thread = std::thread::spawn(move || {
        let result = handle.block_on(run_flow(&agent, opts));
        FlowDone { agent, result }
    });
    ui.run = Some(Running {
        handle: thread,
        progress_rx,
        abort,
        steering,
        started: Instant::now(),
        role: "plan".into(),
        steps: 0,
        tools: 0,
    });
    Ok(())
}

const HELP_LINES: &[&str] = &[
    "commands: /target /scope /roles /offensive /dry-run /steps /new /flows /delete /clear /quit",
    "keys: Enter send · Esc abort/close · Tab complete · ↑↓ history · ^C quit",
    "while a flow runs, a typed line is noted for its later roles; Esc stops it.",
];

fn help_lines() -> Vec<String> {
    HELP_LINES.iter().map(|s| s.to_string()).collect()
}

// --- commands ----------------------------------------------------------------------

/// Run one `/` command. Returns true when the session should quit.
fn run_command(
    ui: &mut Ui,
    terminal: &mut DefaultTerminal,
    config: &Config,
    line: &str,
) -> anyhow::Result<bool> {
    let mut parts = line.trim_start_matches('/').split_whitespace();
    let name = parts.next().unwrap_or("").to_ascii_lowercase();
    let args: Vec<&str> = parts.collect();
    match name.as_str() {
        "help" => {
            say(terminal, &help_lines())?;
        }
        "target" => {
            let v = args.join(" ").trim().to_string();
            if v.is_empty() {
                say(terminal, &["usage: /target example.com".into()])?;
            } else {
                ui.session.target = Some(v.clone());
                say(terminal, &[format!("target → {v}")])?;
            }
        }
        "scope" => {
            let v = args.join(" ").trim().to_string();
            if v.is_empty() {
                say(terminal, &["usage: /scope example.com, 1.2.3.0/24".into()])?;
            } else {
                ui.session.scope = Some(v.clone());
                say(terminal, &[format!("scope → {v}")])?;
            }
        }
        "roles" => {
            let v = args.join(" ").trim().to_string();
            if v.is_empty() || v.eq_ignore_ascii_case("clear") || v.eq_ignore_ascii_case("all") {
                ui.session.roles = None;
                say(terminal, &["roles → full pipeline".into()])?;
            } else {
                match crate::run::parse_roles(Some(&v)) {
                    Ok(_) => {
                        ui.session.roles = Some(v.clone());
                        say(terminal, &[format!("roles → {v}")])?;
                    }
                    Err(e) => say(terminal, &[format!("roles rejected: {e:#}")])?,
                }
            }
        }
        "offensive" => match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("on") => {
                ui.session.offensive = true;
                say(terminal, &["gated tools allowed (prompts may still restrain)".into()])?;
            }
            Some("off") => {
                ui.session.offensive = false;
                say(terminal, &["reconnaissance only".into()])?;
            }
            _ => say(terminal, &["usage: /offensive on|off".into()])?,
        },
        "dry-run" => match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("on") => {
                ui.session.dry_run = true;
                say(terminal, &["dry-run on: scripted provider, nothing spent".into()])?;
            }
            Some("off") => {
                ui.session.dry_run = false;
                say(terminal, &["dry-run off".into()])?;
            }
            _ => say(terminal, &["usage: /dry-run on|off".into()])?,
        },
        "steps" => {
            let v = args.join(" ").trim().to_string();
            if v.is_empty() || v.eq_ignore_ascii_case("clear") {
                ui.session.steps = None;
                say(terminal, &["steps → role defaults".into()])?;
            } else {
                match v.parse::<usize>() {
                    Ok(n) if n >= 1 => {
                        ui.session.steps = Some(n);
                        say(terminal, &[format!("steps → at most {n} per role")])?;
                    }
                    _ => say(terminal, &["usage: /steps 4".into()])?,
                }
            }
        }
        "new" => {
            // Fresh session: settings reset to blank, nothing destroyed.
            // Every flow already run stays in the database exactly as it
            // was - /new starts the next one, it does not undo the last.
            let was = (ui.session.target.clone(), ui.flows);
            ui.session = Session::default();
            ui.trail.clear();
            say(
                terminal,
                &[format!(
                    "new session - target/scope/roles/offensive/dry-run/steps reset{}",
                    match was.0 {
                        Some(t) => format!(" (previous target was {t}; {} flow(s) run so far stay recorded)", was.1),
                        None => String::new(),
                    }
                )],
            )?;
        }
        "flows" => {
            let db = Db::open(&config.paths.db())?;
            let flows = db.list_flows(10)?;
            if flows.is_empty() {
                say(terminal, &["no flows recorded yet".into()])?;
            } else {
                let mut lines = vec!["flow                       status     target".into()];
                for f in flows {
                    lines.push(format!("{:<26} {:<10} {}", f.id, f.status, f.target));
                }
                say(terminal, &lines)?;
            }
        }
        "delete" => {
            let flow_id = args.first().copied().unwrap_or("");
            if flow_id.is_empty() {
                say(terminal, &["usage: /delete flw_abc123 yes".into()])?;
            } else {
                let yes = args.get(1).map(|a| a.eq_ignore_ascii_case("yes")).unwrap_or(false);
                match crate::misc::delete_flow(config, flow_id, yes) {
                    Ok(msg) => say(terminal, &[msg])?,
                    Err(e) => say(terminal, &[format!("{e:#}")])?,
                }
            }
        }
        "clear" => {
            terminal.clear()?;
        }
        "quit" => return Ok(true),
        _ => {
            say(terminal, &[format!("unknown command: /{name} (try /help)")])?;
        }
    }
    Ok(false)
}

// --- main loop -----------------------------------------------------------------------

pub async fn run(config: Config, args: Args) -> anyhow::Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "no terminal here: `lantern chat` needs one - use `lantern ask --prompt \"...\"` \
             (or pipe the instruction on stdin) for the same flow without it"
        );
    }
    let budget = Budget::new(config.data_cap_bytes, dir_size(&config.paths.root));
    println!("{}", retention::startup_line(&config, &budget));

    let session = Session {
        target: args.target,
        scope: args.scope,
        roles: args.roles,
        offensive: args.offensive,
        dry_run: args.dry_run,
        steps: args.steps,
    };
    let model = if config.llm.model.is_empty() {
        "no model".to_string()
    } else {
        config.llm.model.clone()
    };

    // The UI loop is synchronous (ratatui draws sync, crossterm polls sync);
    // it runs on a blocking thread while flows execute on scoped threads that
    // borrow nothing and own their agent.
    let config2 = config.clone();
    tokio::task::spawn_blocking(move || ui_loop(config2, session, model)).await?
}

fn ui_loop(config: Config, session: Session, model: String) -> anyhow::Result<()> {
    let mut terminal = ratatui::try_init_with_options(TerminalOptions {
        viewport: Viewport::Inline(VIEWPORT_H),
    })?;
    let _guard = Guard;

    let mut ui = Ui {
        session,
        composer: Composer::default(),
        palette_sel: 0,
        trail: Vec::new(),
        run: None,
        approval: None,
        model,
        flows: 0,
    };

    say(
        &mut terminal,
        &[
            "lantern chat — instruct in words, watch it work.".into(),
            "type an instruction and press Enter; /help lists commands.".into(),
        ],
    )?;

    let handle = tokio::runtime::Handle::try_current()?;
    let mut quit = false;

    while !quit {
        terminal.draw(|f| draw(&mut ui, f))?;

        // Flow finished? Collect the outcome into the scrollback.
        if ui.run.is_some() {
            let mut events = Vec::new();
            if let Some(running) = &mut ui.run {
                while let Ok(ev) = running.progress_rx.try_recv() {
                    events.push(ev);
                }
            }
            for ev in events {
                on_progress(&mut ui, ev);
            }
            let finished = ui
                .run
                .as_ref()
                .map(|r| r.handle.is_finished())
                .unwrap_or(false);
            if finished {
                let running = ui.run.take().unwrap();
                let FlowDone { agent, result } = running.handle.join().expect("flow thread");
                ui.flows += 1;
                match result {
                    Ok(out) => {
                        let text = crate::run::format_outcome(&agent, &out)?;
                        let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
                        say(&mut terminal, &lines)?;
                    }
                    Err(e) => {
                        say(&mut terminal, &[format!("flow failed: {e:#}")])?;
                    }
                }
                ui.trail.clear();
            }
        }

        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };

        // Approval card owns the keyboard while it is up.
        if let Some((sel, pending)) = ui.approval.take() {
            let mut sel = sel;
            match approval_key(&key.code, &mut sel) {
                Some(allow) => {
                    let verb = if allow { "allowed once" } else { "denied" };
                    say(&mut terminal, &[format!("active testing {verb} for this flow")])?;
                    start_flow(
                        &mut ui,
                        &mut terminal,
                        &config,
                        &pending.instruction,
                        allow,
                        handle.clone(),
                    )?;
                }
                None => {
                    ui.approval = Some((sel, pending));
                }
            }
            continue;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match (&key.code, ctrl) {
            (KeyCode::Char('c'), true) | (KeyCode::Char('d'), true) => {
                if let Some(running) = &ui.run {
                    running.abort.store(true, Ordering::Relaxed);
                    push_trail(&mut ui, "■ aborting…".into());
                } else {
                    quit = true;
                }
            }
            (KeyCode::Esc, _) => {
                if ui.palette_open() {
                    ui.composer.kill_line();
                } else if let Some(running) = &ui.run {
                    running.abort.store(true, Ordering::Relaxed);
                    push_trail(&mut ui, "■ aborting…".into());
                } else if ui.composer.text.is_empty() {
                    quit = true;
                } else {
                    ui.composer.kill_line();
                }
            }
            (KeyCode::Enter, _) => {
                if ui.palette_open() {
                    let query = ui.composer.text.clone();
                    let q = first_word(query.trim_start_matches('/'));
                    let items = palette_matches(q);
                    if items.is_empty() {
                        ui.composer.kill_line();
                        say(&mut terminal, &["no matching command (try /help)".into()])?;
                        continue;
                    }
                    let picked = palette_pick(&items, &query, ui.palette_sel);
                    let cmd = &COMMANDS[picked];
                    // Compose-first when arguments are missing: running a
                    // command that needs them would only print usage.
                    let typed_args = query.split_whitespace().nth(1).is_some()
                        || ui.composer.text.contains(' ');
                    if cmd.needs_args && !typed_args {
                        ui.composer.text = format!("/{name} ", name = cmd.name);
                        ui.composer.cursor = ui.composer.text.len();
                        ui.palette_sel = 0;
                        continue;
                    }
                    let line = ui.composer.submit().unwrap_or_default();
                    ui.palette_sel = 0;
                    if run_command(&mut ui, &mut terminal, &config, &line)? {
                        quit = true;
                    }
                    continue;
                }
                let Some(line) = ui.composer.submit() else {
                    continue;
                };
                if let Some(running) = &ui.run {
                    // Steering: noted for the running flow's later roles.
                    if running.steering.lock().map(|mut q| q.push(line.clone())).is_ok() {
                        push_trail(&mut ui, "↳ queued for the running flow".into());
                    }
                    say(&mut terminal, &[format!("› {line}")])?;
                    continue;
                }
                submit_instruction(&mut ui, &mut terminal, &config, line, handle.clone())?;
            }
            (KeyCode::Tab, _) => {
                if ui.palette_open() {
                    let query = ui.composer.text.clone();
                    let q = first_word(query.trim_start_matches('/'));
                    let items = palette_matches(q);
                    if !items.is_empty() {
                        let picked = palette_pick(&items, &query, ui.palette_sel);
                        let rest = query.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
                        ui.composer.text = if rest.is_empty() {
                            format!("/{} ", COMMANDS[picked].name)
                        } else {
                            format!("/{} {rest}", COMMANDS[picked].name)
                        };
                        ui.composer.cursor = ui.composer.text.len();
                        ui.palette_sel = 0;
                    }
                }
            }
            (KeyCode::Up, _) => {
                if ui.palette_open() {
                    let n = palette_matches(palette_query(&ui)).len();
                    if n > 0 {
                        ui.palette_sel = (ui.palette_sel + n - 1) % n;
                    }
                } else {
                    ui.composer.recall(true);
                }
            }
            (KeyCode::Down, _) => {
                if ui.palette_open() {
                    let n = palette_matches(palette_query(&ui)).len();
                    if n > 0 {
                        ui.palette_sel = (ui.palette_sel + 1) % n;
                    }
                } else {
                    ui.composer.recall(false);
                }
            }
            (KeyCode::Left, _) => ui.composer.move_left(),
            (KeyCode::Right, _) => ui.composer.move_right(),
            (KeyCode::Home, _) => ui.composer.cursor = 0,
            (KeyCode::End, _) => ui.composer.cursor = ui.composer.text.len(),
            (KeyCode::Backspace, _) => ui.composer.backspace(),
            (KeyCode::Delete, _) => {
                // Forward delete: move right then backspace.
                ui.composer.move_right();
                ui.composer.backspace();
            }
            (KeyCode::Char('u'), true) => ui.composer.kill_line(),
            (KeyCode::Char(c), false) => ui.composer.insert(&c.to_string()),
            _ => {}
        }
    }

    println!("\nlantern chat ended · {} flow(s)", ui.flows);
    Ok(())
}

/// What Enter does with a plain instruction: intent card, gate, approval when
/// needed, otherwise straight to a flow.
fn submit_instruction(
    ui: &mut Ui,
    terminal: &mut DefaultTerminal,
    config: &Config,
    line: String,
    handle: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    if line.len() > MAX_PROMPT_BYTES {
        say(
            terminal,
            &[format!(
                "instruction is {} bytes (cap {MAX_PROMPT_BYTES}): \
                 shorten it or use `lantern ask --file`",
                line.len()
            )],
        )?;
        return Ok(());
    }
    let parsed = intent::parse_intent(&line);
    let (effective, gate_warning) = intent::resolve_offensive(ui.session.offensive, &parsed);

    say(terminal, &[format!("› {line}")])?;
    let intent_line = if parsed.defensive_only {
        "reconnaissance only (the prompt restrains it)"
    } else if parsed.wants_offensive {
        "active testing requested"
    } else {
        "as instructed"
    };
    say(terminal, &[format!("intent: {intent_line}")])?;
    if parsed.engagement_profile != intent::EngagementProfile::General {
        say(terminal, &[format!("profile: {:?}", parsed.engagement_profile)])?;
    }
    if let Some(w) = crate::ask::target_warning(
        ui.session.target.as_deref().unwrap_or(""),
        &parsed.contract.target_list(),
    ) {
        say(terminal, &[format!("note: {w}")])?;
    }

    // The gate's one question, asked inline: active testing requested but the
    // session does not allow it. Everything else proceeds or downgrades with
    // a note, exactly like `ask`.
    let asks_active = parsed.wants_offensive && !parsed.defensive_only;
    if gate_warning.is_some() && asks_active && !ui.session.offensive {
        // Default the highlight to [2] deny, not [1] allow: the module doc
        // already calls Esc "deny-by-inaction", and a card that pre-selects
        // the active-testing option means a reflexive Enter - the same key
        // that submits every other line in this UI - grants it. Reaching
        // "allow" now takes a deliberate Left/Right or typing `1`.
        ui.approval = Some((1, PendingFlow { instruction: line }));
        return Ok(());
    }
    if let Some(w) = gate_warning {
        say(terminal, &[format!("note: {w}")])?;
    }
    say(
        terminal,
        &[format!(
            "offensive: {}",
            if effective { "allowed for this flow" } else { "disabled — reconnaissance only" }
        )],
    )?;
    start_flow(ui, terminal, config, &line, effective, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_moves_a_char_boundary_cursor() {
        let mut c = Composer::default();
        c.insert("héllo");
        assert_eq!(c.cursor, 6);
        c.move_left();
        c.move_left();
        assert_eq!(c.cursor, 4, "byte index before the second l");
        c.backspace();
        assert_eq!(c.text, "hélo");
        c.move_right();
        c.move_right();
        c.insert("!");
        assert_eq!(c.text, "hélo!");
    }

    #[test]
    fn submit_pushes_history_once_and_clears() {
        let mut c = Composer::default();
        c.insert("check TLS");
        assert_eq!(c.submit().as_deref(), Some("check TLS"));
        assert_eq!(c.submit(), None, "empty line submits nothing");
        c.insert("check TLS");
        c.submit();
        assert_eq!(c.history, vec!["check TLS"], "no duplicate history rows");
        c.insert("draft");
        c.recall(true);
        assert_eq!(c.text, "check TLS");
        c.recall(false);
        assert_eq!(c.text, "draft", "newer recall restores the stashed line");
    }

    #[test]
    fn palette_filters_and_exact_names_win() {
        let all = palette_matches("");
        assert_eq!(all.len(), COMMANDS.len());
        let t = palette_matches("t");
        assert!(t.iter().any(|i| COMMANDS[*i].name == "target"));
        assert!(palette_matches("zzz").is_empty());
        // Fully typed "/quit" runs quit even with the highlight elsewhere.
        assert_eq!(COMMANDS[palette_pick(&all, "/quit", 7)].name, "quit");
    }

    #[test]
    fn floor_char_boundary_matches_the_std_semantics_it_replaces() {
        let s = "héllo"; // 'é' is 2 bytes, so byte 2 sits mid-character
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1); // boundary after 'h'
        assert_eq!(floor_char_boundary(s, 2), 1); // mid-'é': floors to before it
        assert_eq!(floor_char_boundary(s, 3), 3); // boundary after 'é'
        assert_eq!(floor_char_boundary(s, 100), s.len(), "past the end clamps to len");
        assert_eq!(floor_char_boundary("", 0), 0);
    }

    #[test]
    fn approval_card_defaults_to_deny_not_allow() {
        // A reflexive Enter on a freshly raised approval card - the same key
        // that submits every other line in this UI - must never grant active
        // testing. Explicit Left (or typing 1) is what reaches "allow".
        let mut sel = 1usize; // the default this card is raised with
        assert_eq!(approval_key(&KeyCode::Enter, &mut sel), Some(false));
        assert_eq!(approval_key(&KeyCode::Left, &mut sel), None);
        assert_eq!(sel, 0);
        assert_eq!(approval_key(&KeyCode::Enter, &mut sel), Some(true));
    }

    #[test]
    fn approval_keys_decide_or_move() {
        let mut sel = 1usize;
        assert_eq!(approval_key(&KeyCode::Char('1'), &mut sel), Some(true));
        assert_eq!(approval_key(&KeyCode::Char('2'), &mut sel), Some(false));
        assert_eq!(approval_key(&KeyCode::Esc, &mut sel), Some(false));
        assert_eq!(approval_key(&KeyCode::Left, &mut sel), None);
        assert_eq!(sel, 0);
        assert_eq!(approval_key(&KeyCode::Enter, &mut sel), Some(true));
    }

    #[test]
    fn wrapping_keeps_words_whole() {
        let lines = wrap_line("aaa bb ccccc", 6);
        assert_eq!(lines, vec!["aaa bb", "ccccc"]);
        assert_eq!(wrap_line("short", 100), vec!["short"]);
    }
}
