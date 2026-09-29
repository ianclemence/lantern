//! `lantern doctor` - everything that must be true before an assessment runs.

use lantern_core::budget::{dir_size, Budget};
use lantern_core::config::Config;
use lantern_core::device::DeviceProfile;
use lantern_core::retention;
use lantern_llm::embed::OllamaEmbedder;
use lantern_tools::exec::resolve_binary;
use lantern_tools::registry::Registry;

const MB: f64 = 1_048_576.0;
const GB: f64 = 1e9;

fn gb(bytes: u64) -> String {
    format!("{:.2} GB", bytes as f64 / GB)
}

pub async fn run(config: &Config) -> anyhow::Result<()> {
    let device = DeviceProfile::detect(&config.paths.root);
    let used = dir_size(&config.paths.root);
    let budget = Budget::new(config.data_cap_bytes, used);
    let logs = dir_size(&config.paths.logs());
    let fs = retention::check_floor(config).ok();

    println!("lantern doctor\n");
    if device.cpu_model.is_empty() {
        // The only model string the kernel exposes names the board, so it is
        // withheld: report the machine itself instead.
        println!("  device    : {} cores, {}", device.cores, device.arch);
    } else {
        println!(
            "  device    : {} ({} cores, {})",
            device.cpu_model, device.cores, device.arch
        );
    }
    println!(
        "  host      : {} / {} / kernel {}",
        device.hostname, device.os_pretty, device.kernel
    );
    println!(
        "  memory    : {:.1} GiB total, {:.1} GiB available, swap {:.1} GiB",
        device.mem.total_bytes as f64 / GB,
        device.mem.available_bytes as f64 / GB,
        device.mem.swap_total_bytes as f64 / GB
    );
    println!("  gpu       : {}", device.gpu);
    println!("  inference : {}", device.inference_summary());
    println!(
        "  data root : {} ({:.1} MB of {:.1} MB cap, floor {}%)",
        config.paths.root.display(),
        budget.used_bytes() as f64 / MB,
        budget.cap_bytes() as f64 / MB,
        config.floor_percent
    );
    match fs {
        Some(f) => println!(
            "  disk      : {} free of {} (floor keeps {} free)",
            gb(f.free_bytes),
            gb(f.total_bytes),
            gb(f.floor_bytes(config.floor_percent))
        ),
        None => println!("  disk      : UNDER THE FLOOR - run `lantern gc` or free space"),
    }
    println!(
        "  logs      : {:.1} MB of {:.1} MB cap",
        logs as f64 / MB,
        config.log_cap_bytes as f64 / MB
    );

    // --- model integrations ------------------------------------------------
    let provider = if config.llm.provider.is_empty() {
        "none".to_string()
    } else {
        config.llm.provider.clone()
    };
    let model = if config.llm.model.is_empty() {
        "NO MODEL".to_string()
    } else {
        config.llm.model.clone()
    };
    let endpoint = if config.llm.base_url.is_empty() {
        "NO ENDPOINT".to_string()
    } else {
        config.llm.base_url.clone()
    };
    let key = if config.offline {
        "offline mode".to_string()
    } else {
        crate::prefs::key_source(config)
    };
    println!("  generation: {provider} / {model} @ {endpoint} [{key}]");

    let embed_status = if !config.embed.enabled() {
        None
    } else {
        Some(
            OllamaEmbedder::probe(&config.embed.url, &config.embed.model).await.is_some(),
        )
    };
    let embed_line = match &embed_status {
        None => "disabled (LANTERN_EMBED=0) - keyword search only".to_string(),
        Some(true) => format!(
            "ollama {} @ {} - {}-dim",
            config.embed.model, config.embed.url, config.embed.dims
        ),
        Some(false) => format!(
            "UNREACHABLE at {} - falling back to keyword search",
            config.embed.url
        ),
    };
    println!("  embeddings: {embed_line}");

    // --- tools -------------------------------------------------------------
    let registry = Registry::new(config)?;
    println!(
        "  tools     : {} native, allowlist: {}",
        registry
            .tools()
            .iter()
            .filter(|t| !is_host(t.name()))
            .count(),
        if config.allowlist.is_empty() {
            "(empty - host binaries disabled)".to_string()
        } else {
            config.allowlist.join(" ")
        }
    );
    let mut missing = Vec::new();
    for name in &config.allowlist {
        match resolve_binary(name, &config.restricted_path, &config.allowlist) {
            Ok(p) => {
                let gate = registry
                    .host_tool(name)
                    .map(|h| if h.offensive { " [requires --offensive]" } else { "" })
                    .unwrap_or("");
                println!("    {name:<8} : {}{gate}", p.display());
            }
            Err(e) => {
                println!("    {name:<8} : MISSING ({e})");
                missing.push(name.clone());
            }
        }
    }

    // --- warnings ----------------------------------------------------------
    let mut warnings: Vec<String> = Vec::new();
    if config.degraded() {
        warnings.push("no generation key: runs are limited to --dry-run".into());
    }
    if config.offline {
        warnings.push("offline mode: no external calls will be attempted".into());
    }
    if !missing.is_empty() {
        warnings.push(format!("missing host binaries: {}", missing.join(", ")));
    }
    if embed_status != Some(true) {
        warnings.push("semantic memory unavailable: keyword (FTS5) search only".into());
    }
    if retention::check_floor(config).is_err() {
        warnings.push("filesystem is under the free-space floor".into());
    }

    println!(
        "\n  runtime   : concurrency {} | task timeout {}s | child {} MB / {} CPU-s | token budget {}",
        config.concurrency,
        config.task_timeout_secs,
        config.child_as_bytes / MB as u64,
        config.child_cpu_secs,
        config.token_budget
    );
    if warnings.is_empty() {
        println!("  warnings  : none");
    } else {
        println!("  warnings  :");
        for w in warnings {
            println!("    - {w}");
        }
    }
    Ok(())
}

/// Host-binary tools are always exposed with a `host_` prefix.
fn is_host(name: &str) -> bool {
    name.starts_with("host_")
}
