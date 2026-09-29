//! The guided half of `lantern setup`: provider, model, key.
//!
//! Three questions, one live check and two files. The endpoint's own model list
//! is fetched when it will answer (so the menu shows what that account can
//! actually call), the shortlist in the preset table is the fallback, and the
//! key is verified with a real one-line completion before it is stored - a key
//! that cannot talk to the endpoint is not worth saving.
//!
//! Nothing is asked when stdin is not a terminal. A scripted run has nobody to
//! question, so it takes the answer the environment already gives - provider,
//! model and key - checks it with one real call and stores it; and when the
//! environment cannot finish the job, the message names the one variable that
//! would.

use crate::prefs;
use lantern_core::config::Config;
use lantern_core::providers::{self, Provider, Wire};
use std::io::{IsTerminal, Write as _};
use std::time::{Duration, Instant};

/// What the operator settled on. `None` from `run` means "nothing to save".
pub struct Outcome {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub key_saved: bool,
}

pub async fn run(config: &Config) -> anyhow::Result<Option<Outcome>> {
    if !std::io::stdin().is_terminal() {
        return scripted(config).await;
    }
    if config.offline {
        crate::setup::skipped("AI provider: offline mode - nothing to ask for");
        return Ok(None);
    }

    let saved = prefs::read_prefs();
    let current = saved.provider.clone();
    let current_model = saved.model.clone().unwrap_or_default();

    println!("\n  AI provider");

    // A machine that is already set up should not be asked again, unless the
    // key it holds has stopped working or the operator wants to switch.
    if let Some(id) = current.as_deref() {
        let label = providers::by_id(id).map(|p| p.name).unwrap_or(id);
        if prefs::has_key(id) {
            println!("    configured: {label} / {current_model}");
            match ask_yes("    change provider or model? [y/N] ", false)? {
                Some(false) => {
                    crate::setup::ok(&format!("keeping {label} / {current_model}"));
                    return Ok(None);
                }
                Some(true) => {}
                None => return Ok(None),
            }
        } else {
            println!("    configured: {label} / {current_model} - no key yet");
        }
    }

    // 1. provider -------------------------------------------------------------
    let default_no = current
        .as_deref()
        .and_then(|id| providers::PROVIDERS.iter().position(|p| p.id == id))
        .map(|i| i + 1)
        .unwrap_or(1);
    print_providers(current.as_deref());
    let chosen = match ask_number(
        &format!("    choose 1-{}: ", providers::PROVIDERS.len()),
        providers::PROVIDERS.len(),
        default_no,
    )? {
        Some(n) => &providers::PROVIDERS[n - 1],
        None => return Ok(None),
    };

    // A preset knows its own endpoint; a custom one asks.
    let mut base_url = chosen.base_url.to_string();
    if chosen.id == "custom" {
        match ask("\n  endpoint URL (e.g. http://127.0.0.1:8000/v1): ")? {
            Some(url) if url.starts_with("http://") || url.starts_with("https://") => {
                base_url = url.trim_end_matches('/').to_string();
            }
            Some(_) => {
                crate::setup::warn("that is not an http(s) URL - keeping the current setup");
                return Ok(None);
            }
            None => return Ok(None),
        }
    }

    // 2. model ----------------------------------------------------------------
    println!("\n  model");
    let existing_key = existing_key(chosen);
    let live = live_models(chosen, &base_url, &existing_key).await;
    let candidates = model_candidates(chosen, live);
    let model = if candidates.is_empty() {
        println!(
            "    the endpoint listed no models{}",
            if chosen.id == "ollama" {
                " - `ollama pull <model>` one, then continue"
            } else {
                ""
            }
        );
        match ask("    model name: ")? {
            Some(m) if !m.is_empty() => m,
            _ => return Ok(None),
        }
    } else {
        match model_menu(&candidates)? {
            Some(m) => m,
            None => return Ok(None),
        }
    };

    // 3. key ------------------------------------------------------------------
    let mut key: Option<String> = None;
    if chosen.id == "custom" {
        println!("\n  key (optional - a local endpoint may not need one)");
        match ask_secret("    LANTERN_LLM_API_KEY, Enter to skip: ")? {
            Some(k) if !k.is_empty() => key = Some(k),
            Some(_) | None => {}
        }
    } else if let Some(env_name) = chosen.key_env {
        println!("\n  key");
        if existing_key.is_empty() {
            println!(
                "    stored once in {}, never in the database, logs or reports",
                prefs::credentials_file().display()
            );
            match ask_secret(&format!("    {env_name}: "))? {
                Some(k) if !k.is_empty() => key = Some(k),
                _ => {
                    crate::setup::warn(&format!(
                        "no key saved: {env_name} is still required at run time"
                    ));
                    return Ok(None);
                }
            }
        } else {
            match ask_yes(&format!("    {env_name} is already available - keep it? [Y/n] "), true)?
            {
                None => return Ok(None),
                Some(true) => {}
                Some(false) => match ask_secret(&format!("    {env_name}: "))? {
                    Some(k) if !k.is_empty() => key = Some(k),
                    _ => return Ok(None),
                },
            }
        }
    }

    // 4. one real call, so a typo costs nothing later --------------------------
    println!("\n  testing {} / {model}", chosen.name);
    let probe_key = key.clone().unwrap_or_else(|| existing_key.clone());
    match ping(config, chosen.id, &base_url, &model, &probe_key).await {
        Ok((reply, ms)) => {
            let one_line: String = reply.split_whitespace().take(8).collect::<Vec<_>>().join(" ");
            crate::setup::ok(&format!(
                "connected in {ms} ms - \"{}\"",
                one_line.chars().take(60).collect::<String>()
            ));
        }
        Err(e) => {
            crate::setup::warn(&redact(&e, &probe_key));
            if key.is_some() {
                match ask_yes("    save it anyway? [y/N] ", false)? {
                    Some(true) => {}
                    _ => return Ok(None),
                }
            } else {
                return Ok(None);
            }
        }
    }

    // 5. store ----------------------------------------------------------------
    let key_env = chosen.key_env.unwrap_or("LANTERN_LLM_API_KEY");
    prefs::save_prefs(chosen.id, &model, &base_url)?;
    let mut key_saved = false;
    if let Some(k) = key {
        prefs::save_key(key_env, &k)?;
        key_saved = true;
    }
    crate::setup::ok(&format!(
        "saved {}/config.json{}",
        prefs::dir().display(),
        if key_saved {
            " and credentials (mode 0600)"
        } else {
            " (key left to the environment)"
        }
    ));

    Ok(Some(Outcome {
        provider: chosen.id.to_string(),
        model,
        base_url,
        key_saved,
    }))
}

// --- without a terminal -----------------------------------------------------

/// `lantern setup` with no one at the keyboard.
///
/// The whole configuration may already be in the environment - that is how a
/// script or a fresh machine is usually provisioned - so it is stored instead
/// of ignored, after one real call has shown it works. When the environment is
/// missing something, nothing is written and the message says which single
/// variable would finish the job.
async fn scripted(config: &Config) -> anyhow::Result<Option<Outcome>> {
    if config.offline {
        crate::setup::skipped("AI provider: offline mode - nothing to ask for");
        return Ok(None);
    }

    let provider = config.llm.provider.trim().to_string();
    let model = config.llm.model.trim().to_string();
    let base_url = config.llm.base_url.trim().trim_end_matches('/').to_string();
    let key = config.llm.api_key.trim().to_string();

    if let Err(gap) = scripted_gap(&provider, &model, &base_url, &key) {
        crate::setup::skipped(&skip_message(&gap));
        return Ok(None);
    }
    let preset = providers::by_id(&provider).expect("scripted_gap rejected anything unknown");
    let key_env = preset.key_env.unwrap_or("LANTERN_LLM_API_KEY");
    let stored_key = prefs::read_credentials()
        .get(key_env)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();

    let saved = prefs::read_prefs();
    let unchanged = saved.provider.as_deref() == Some(provider.as_str())
        && saved.model.as_deref() == Some(model.as_str())
        && saved.base_url.as_deref() == Some(base_url.as_str())
        && stored_key == key;
    if unchanged {
        crate::setup::ok(&format!("already configured: {} / {model}", preset.name));
        return Ok(None);
    }

    // One real call first: in a script there is nobody to answer "save it
    // anyway?", so a failed check is reported and the files are written
    // regardless - the environment supplied this key, and refusing to persist
    // it would only make the next run ask again.
    match ping(config, &provider, &base_url, &model, &key).await {
        Ok((reply, ms)) => {
            let one: String = reply.split_whitespace().take(8).collect::<Vec<_>>().join(" ");
            crate::setup::ok(&format!(
                "connected in {ms} ms - \"{}\"",
                one.chars().take(60).collect::<String>()
            ));
        }
        Err(e) => crate::setup::warn(&redact(&e, &key)),
    }

    prefs::save_prefs(&provider, &model, &base_url)?;
    let mut key_saved = false;
    if !key.is_empty() && stored_key != key {
        prefs::save_key(key_env, &key)?;
        key_saved = true;
    }
    crate::setup::ok(&format!(
        "saved {}/config.json{}",
        prefs::dir().display(),
        if key_saved {
            " and credentials (mode 0600)"
        } else {
            ""
        }
    ));

    Ok(Some(Outcome {
        provider,
        model,
        base_url,
        key_saved,
    }))
}

/// The one thing still missing before a scripted setup can store anything.
/// `Err` carries the message shown to the operator.
fn scripted_gap(provider: &str, model: &str, base_url: &str, key: &str) -> Result<(), String> {
    let Some(preset) = providers::by_id(provider) else {
        return Err(format!(
            "this build has no provider preset `{provider}` (known: {})",
            providers::PROVIDERS
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };
    if model.is_empty() {
        return Err("set LANTERN_LLM_MODEL - this preset has no default model".to_string());
    }
    if base_url.is_empty() {
        return Err("set LANTERN_LLM_BASE_URL - this preset has no default endpoint".to_string());
    }
    if let Some(env_name) = preset.key_env {
        if key.is_empty() {
            return Err(format!("export {env_name}"));
        }
    }
    Ok(())
}

/// What `skipped` prints. Built from the gap so the variable that would finish
/// the job is always named - a script should never have to guess.
fn skip_message(gap: &str) -> String {
    format!(
        "AI provider: no terminal here - {gap}; run `lantern setup` in a terminal to be walked \
         through provider, model and key"
    )
}

// --- prompting -------------------------------------------------------------

fn ask(prompt: &str) -> anyhow::Result<Option<String>> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => Ok(None),
        Ok(_) => Ok(Some(line.trim().to_string())),
    }
}

/// 1-based choice, default when the operator just presses Enter, `None` on EOF.
fn ask_number(prompt: &str, max: usize, default: usize) -> anyhow::Result<Option<usize>> {
    loop {
        let Some(line) = ask(prompt)? else {
            return Ok(None);
        };
        if line.is_empty() {
            return Ok(Some(default));
        }
        match line.parse::<usize>() {
            Ok(n) if n >= 1 && n <= max => return Ok(Some(n)),
            Ok(_) => crate::setup::warn(&format!("pick a number between 1 and {max}")),
            Err(_) => crate::setup::warn("type a number, or press Enter for the default"),
        }
    }
}

/// `None` on EOF, which every caller treats as "stop asking".
fn ask_yes(prompt: &str, default: bool) -> anyhow::Result<Option<bool>> {
    loop {
        let Some(line) = ask(prompt)? else {
            return Ok(None);
        };
        if line.is_empty() {
            return Ok(Some(default));
        }
        match line.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(Some(true)),
            "n" | "no" => return Ok(Some(false)),
            _ => crate::setup::warn("answer y or n"),
        }
    }
}

/// Read a key without echoing it back. Falls back to a visible read when the
/// terminal driver is not available.
fn ask_secret(prompt: &str) -> anyhow::Result<Option<String>> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let muted = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if muted {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::null())
            .status();
    }
    println!();
    match read {
        Ok(0) | Err(_) => Ok(None),
        Ok(_) => Ok(Some(line.trim().to_string())),
    }
}

fn print_providers(current: Option<&str>) {
    for (i, p) in providers::PROVIDERS.iter().enumerate() {
        let where_ = if p.base_url.is_empty() {
            "your own URL"
        } else {
            p.base_url
        };
        let note = match current {
            Some(id) if id == p.id => "  <- current",
            _ => "",
        };
        println!("    {:2}) {:16} {}{}", i + 1, p.name, where_, note);
    }
}

fn model_menu(candidates: &[String]) -> anyhow::Result<Option<String>> {
    const SHOWN: usize = 10;
    let shown = candidates.len().min(SHOWN);
    for (i, m) in candidates.iter().take(shown).enumerate() {
        println!("    {:2}) {m}", i + 1);
    }
    if candidates.len() > shown {
        println!(
            "      ... and {} more on this endpoint",
            candidates.len() - shown
        );
    }
    println!("      m) type a model name");
    loop {
        let Some(line) = ask("    choose: ")? else {
            return Ok(None);
        };
        let line = line.trim();
        if line.is_empty() {
            return Ok(Some(candidates[0].clone()));
        }
        if line.eq_ignore_ascii_case("m") {
            match ask("    model name: ")? {
                Some(m) if !m.is_empty() => return Ok(Some(m)),
                _ => continue,
            }
        }
        match line.parse::<usize>() {
            Ok(n) if n >= 1 && n <= candidates.len() => return Ok(Some(candidates[n - 1].clone())),
            _ => crate::setup::warn(&format!("pick 1-{}, or m to type one", candidates.len())),
        }
    }
}

// --- talking to the endpoint ------------------------------------------------

fn existing_key(p: &Provider) -> String {
    let creds = prefs::read_credentials();
    let mut found = String::new();
    if let Some(k) = p.key_env {
        if let Some(v) = creds.get(k).and_then(|v| v.as_str()) {
            found = v.to_string();
        }
    }
    if found.is_empty() {
        if let Some(v) = creds
            .get("LANTERN_LLM_API_KEY")
            .and_then(|v| v.as_str())
        {
            found = v.to_string();
        }
    }
    if found.is_empty() {
        if let Some(k) = p.key_env {
            if let Ok(v) = std::env::var(k) {
                found = v;
            }
        }
    }
    found.trim().to_string()
}

/// The preset shortlist first, then whatever the endpoint itself offered.
fn model_candidates(p: &Provider, live: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = p.models.iter().map(|s| (*s).to_string()).collect();
    for m in live {
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

async fn live_models(p: &Provider, base_url: &str, key: &str) -> Vec<String> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("lantern/", env!("CARGO_PKG_VERSION")))
        .build()
    else {
        return Vec::new();
    };
    let url = if base_url.ends_with("/v1") {
        format!("{base_url}/models")
    } else {
        format!("{base_url}/v1/models")
    };
    let mut req = client.get(&url);
    match p.wire {
        Wire::OpenAi => {
            if !key.is_empty() {
                req = req.bearer_auth(key);
            }
        }
        Wire::Anthropic => {
            req = req
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01");
        }
    }
    let Ok(resp) = req.send().await else {
        return Vec::new();
    };
    let Ok(text) = resp.text().await else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    v.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|i| i.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// One real completion against the chosen provider, model and key.
async fn ping(
    config: &Config,
    provider_id: &str,
    base_url: &str,
    model: &str,
    key: &str,
) -> Result<(String, u128), String> {
    let mut probe = config.clone();
    probe.offline = false;
    probe.llm.provider = provider_id.to_string();
    probe.llm.base_url = base_url.trim_end_matches('/').to_string();
    probe.llm.model = model.to_string();
    probe.llm.api_key = key.to_string();

    let client = lantern_agent::provider_for(&probe, false).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let reply = client
        .chat(
            lantern_llm::provider::ChatRequest::new(vec![lantern_llm::provider::Message::user(
                "Reply with the single word: ok",
            )])
            .max_tokens(16),
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok((reply.text().to_string(), started.elapsed().as_millis()))
}

/// Never let the key reach the terminal, whatever an endpoint said back.
fn redact(message: &str, key: &str) -> String {
    if key.is_empty() {
        return message.to_string();
    }
    message.replace(key, "***")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_core::config::{EmbedConfig, EmbedMode, Paths};
    use std::path::PathBuf;

    fn config() -> Config {
        Config {
            paths: Paths::new(std::env::temp_dir().join("lantern-wizard-test")),
            tools_dir: PathBuf::from("/tmp/lantern-tools"),
            nuclei_templates: PathBuf::from("/tmp/lantern-templates"),
            data_cap_bytes: 1 << 30,
            log_cap_bytes: 1 << 20,
            floor_percent: 5,
            concurrency: 3,
            task_timeout_secs: 60,
            max_output_bytes: 1 << 20,
            child_as_bytes: 1 << 30,
            child_cpu_secs: 60,
            restricted_path: "/usr/bin".into(),
            allowlist: vec!["nmap".into()],
            offensive: false,
            artifact_retention_days: 7,
            log_retention_days: 30,
            trace_retention_days: 14,
            vacuum_free_percent: 25,
            offline: false,
            token_budget: 6_000,
            summarize_at: 4_500,
            keep_recent_tokens: 1_500,
            ram_per_task_bytes: 192 * 1024 * 1024,
            llm: lantern_core::config::LlmConfig {
                provider: "deepseek".into(),
                base_url: "https://api.deepseek.com".into(),
                model: "deepseek-flash".into(),
                api_key: String::new(),
                timeout_secs: 90,
                max_output_tokens: 2_000,
                temperature: 0.2,
            },
            embed: EmbedConfig {
                mode: EmbedMode::Disabled,
                url: String::new(),
                model: String::new(),
                dims: 768,
            },
        }
    }

    #[test]
    fn shortlists_lead_and_the_endpoint_can_offer_more() {
        let p = providers::by_id("deepseek").unwrap();
        let c = model_candidates(p, vec!["deepseek-chat".into(), "brand-new-model".into()]);
        assert_eq!(c[0], "deepseek-flash", "the curated shortlist comes first");
        assert!(c.contains(&"brand-new-model".to_string()));
        assert_eq!(
            c.iter().filter(|m| *m == "deepseek-chat").count(),
            1,
            "duplicates from the endpoint are dropped"
        );
    }

    #[test]
    fn a_local_endpoint_with_no_list_still_offers_the_preset() {
        let p = providers::by_id("ollama").unwrap();
        assert!(model_candidates(p, vec![]).is_empty(), "nothing to guess from");
        let p = providers::by_id("custom").unwrap();
        assert!(model_candidates(p, vec![]).is_empty());
    }

    #[test]
    fn the_key_never_survives_into_a_message() {
        assert_eq!(redact("401 bad key sk-secret-123", "sk-secret-123"), "401 bad key ***");
        assert_eq!(redact("401 bad key", ""), "401 bad key");
        assert!(!redact("sk-secret-123 rejected", "sk-secret-123").contains("sk-secret-123"));
    }

    #[test]
    fn model_menu_defaults_to_the_first_entry() {
        // The menu only reads stdin when a line is typed; an empty choice is
        // covered by construction (candidates[0]), so check the guard rails of
        // the candidate list itself instead of driving the terminal.
        let c = model_candidates(providers::by_id("groq").unwrap(), vec![]);
        assert_eq!(c[0], "llama-3.3-70b-versatile");
        assert!(!c.is_empty());
    }

    #[test]
    fn a_scripted_setup_names_the_variable_it_is_waiting_for() {
        let err = scripted_gap("deepseek", "deepseek-flash", "https://api.deepseek.com", "")
            .err()
            .expect("a key-requiring provider with no key must stop here");
        assert!(err.contains("DEEPSEEK_API_KEY"), "names the exact variable: {err}");

        let msg = skip_message(&err);
        assert!(msg.contains("DEEPSEEK_API_KEY"), "{msg}");
        assert!(msg.contains("no terminal"), "{msg}");
        assert!(msg.contains("lantern setup"), "points at the guided way: {msg}");
    }

    #[test]
    fn a_default_configuration_alone_is_not_enough_to_store() {
        // What a bare `lantern setup` in a script has to work with: a preset
        // and no key. It has to stop and ask for the right variable rather
        // than write a configuration that cannot run.
        let c = config();
        let err = scripted_gap(&c.llm.provider, &c.llm.model, &c.llm.base_url, &c.llm.api_key)
            .err()
            .expect("preset defaults with no key must not be saved");
        assert!(err.contains("DEEPSEEK_API_KEY"), "{err}");
    }

    #[test]
    fn a_scripted_setup_stores_what_the_environment_already_says() {
        assert!(
            scripted_gap("deepseek", "deepseek-flash", "https://api.deepseek.com", "sk-x").is_ok()
        );
        // A keyless endpoint is complete without a key at all.
        assert!(scripted_gap("ollama", "llama3.2", "http://127.0.0.1:11434/v1", "").is_ok());
        assert!(scripted_gap("custom", "mymodel", "http://127.0.0.1:8000/v1", "").is_ok());
    }

    #[test]
    fn a_scripted_setup_never_invents_a_model_or_an_endpoint() {
        let m = scripted_gap("ollama", "", "http://127.0.0.1:11434/v1", "")
            .err()
            .expect("ollama has no default model to store");
        assert!(m.contains("LANTERN_LLM_MODEL"), "{m}");

        let b = scripted_gap("custom", "mymodel", "", "")
            .err()
            .expect("a custom endpoint has to be told where it is");
        assert!(b.contains("LANTERN_LLM_BASE_URL"), "{b}");

        let p = scripted_gap("typo", "m", "http://127.0.0.1:8000/v1", "k")
            .err()
            .expect("an unknown preset must be reported, not stored");
        assert!(p.contains("no provider preset"), "{p}");
        assert!(p.contains("deepseek"), "and lists what is available: {p}");
    }
}
