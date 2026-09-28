//! Device profiling: the numbers that drive every sizing decision in Lantern.
//! Purely read-only; used by `lantern doctor` and logged at startup.

use crate::budget::FsStat;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct MemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceProfile {
    pub arch: String,
    pub hostname: String,
    pub kernel: String,
    pub os_pretty: String,
    pub libc: String,
    pub cores: usize,
    pub cpu_model: String,
    pub mem: MemInfo,
    pub fs_total_bytes: u64,
    pub fs_free_bytes: u64,
    pub fs_type: String,
    pub gpu: String,
    pub local_llm_possible: bool,
}

fn read_first(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn proc_meminfo() -> MemInfo {
    let mut m = MemInfo::default();
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            let mut it = line.split(':');
            let key = it.next().unwrap_or_default();
            let val = it.next().unwrap_or_default();
            let kb: u64 = val
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            match key {
                "MemTotal" => m.total_bytes = kb * 1024,
                "MemAvailable" => m.available_bytes = kb * 1024,
                "SwapTotal" => m.swap_total_bytes = kb * 1024,
                _ => {}
            }
        }
    }
    m
}

fn cpu_model() -> String {
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "model name" || k.trim() == "Model" {
                    return v.trim().to_string();
                }
            }
        }
        // ARM often only reports "Processor" / hardware strings.
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == "Hardware" || k.trim() == "Processor" {
                    return v.trim().to_string();
                }
            }
        }
    }
    "unknown".into()
}

fn os_pretty() -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                return v.trim().trim_matches('"').to_string();
            }
        }
    }
    "unknown".into()
}

/// The display controller is display-only: there is no compute device here.
/// Detection is intentionally conservative - if we cannot positively identify a
/// usable accelerator we report none, so nothing downstream assumes one exists.
fn gpu_summary() -> String {
    let mut found: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/drm") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("card") || name.contains('-') {
                continue;
            }
            let uevent = e.path().join("device/uevent");
            if let Ok(text) = std::fs::read_to_string(&uevent) {
                for line in text.lines() {
                    if let Some(v) = line.strip_prefix("OF_FULLNAME=") {
                        found.push(v.trim().to_string());
                    }
                }
            }
        }
    }
    if std::path::Path::new("/dev/nvidia0").exists() || std::path::Path::new("/dev/nvidiactl").exists() {
        return "NVIDIA device nodes present".into();
    }
    if found.is_empty() {
        "none".into()
    } else {
        format!(
            "display-only ({}) - no compute capability",
            found.join(", ")
        )
    }
}

fn libc_version() -> String {
    // glibc reports itself via gnu_get_libc_version; avoid a libc dependency by
    // parsing the loader's banner when available, else fall back to ldd.
    if let Ok(out) = std::process::Command::new("ldd").arg("--version").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(first) = text.lines().next() {
            return first.to_string();
        }
    }
    "unknown".into()
}

impl DeviceProfile {
    pub fn detect(root: &Path) -> Self {
        let fs = FsStat::for_path(root).unwrap_or(FsStat {
            total_bytes: 0,
            free_bytes: 0,
        });
        let arch = std::env::consts::ARCH.to_string();
        // No discrete GPU + <=8 cores + <=8 GiB RAM means local generation is a
        // poor trade: we only enable it when there is real headroom.
        let mem = proc_meminfo();
        let local_llm_possible = mem.total_bytes >= 16 * 1024 * 1024 * 1024;

        Self {
            arch: arch.clone(),
            hostname: read_first(Path::new("/proc/sys/kernel/hostname")).unwrap_or_else(|| "unknown".into()),
            kernel: read_first(Path::new("/proc/sys/kernel/osrelease")).unwrap_or_else(|| "unknown".into()),
            os_pretty: os_pretty(),
            libc: libc_version(),
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            cpu_model: cpu_model(),
            mem,
            fs_total_bytes: fs.total_bytes,
            fs_free_bytes: fs.free_bytes,
            fs_type: probe_fs_type(root),
            gpu: gpu_summary(),
            local_llm_possible,
        }
    }

    /// Honest answer for `lantern doctor`: external API is the only generation
    /// path unless the host grows a real accelerator.
    pub fn inference_summary(&self) -> String {
        if self.local_llm_possible {
            "local inference feasible (>=16 GiB RAM)".to_string()
        } else {
            format!(
                "external API only ({} GiB RAM, {} cores, GPU: {})",
                self.mem.total_bytes / 1024 / 1024 / 1024,
                self.cores,
                self.gpu
            )
        }
    }

    /// Device-sized concurrency: leave at least 1.5 GiB for the OS and the
    /// embedding model, then allow 192 MiB per task.
    pub fn recommended_concurrency(&self, task_ram_bytes: u64) -> usize {
        let reserve = 1_536 * 1024 * 1024u64;
        let usable = self.mem.available_bytes.saturating_sub(reserve);
        let by_ram = (usable / task_ram_bytes.max(1)) as usize;
        by_ram.clamp(1, 4)
    }
}

fn probe_fs_type(root: &Path) -> String {
    let c = match std::ffi::CString::new(root.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return "unknown".into(),
    };
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut st) != 0 {
            return "unknown".into();
        }
        // Linux filesystem magics (include/uapi/linux/magic.h).
        match st.f_type as u64 {
            0x0000_ef53 => "ext4".into(),
            0x9123_683e => "btrfs".into(),
            0x0102_1994 => "tmpfs".into(),
            0x5846_5342 => "f2fs".into(),
            0x0000_6969 => "nfs".into(),
            0x517b => "f2fs-alt".into(),
            0x794c_7630 => "overlayfs".into(),
            0x6573_5546 => "fuse".into(),
            other => format!("0x{other:x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_sane_values() {
        let p = DeviceProfile::detect(Path::new("/"));
        assert!(p.cores >= 1);
        assert!(p.mem.total_bytes > 0, "meminfo should parse");
        assert!(!p.gpu.is_empty());
        assert!(!p.arch.is_empty());
        println!(
            "{} | {} cores | {} GiB RAM | gpu={} | {}",
            p.arch,
            p.cores,
            p.mem.total_bytes / 1024 / 1024 / 1024,
            p.gpu,
            p.inference_summary()
        );
    }

    #[test]
    fn concurrency_is_device_bounded() {
        let mut p = DeviceProfile::detect(Path::new("/"));
        p.mem.total_bytes = 8 * 1024 * 1024 * 1024;
        p.mem.available_bytes = 6 * 1024 * 1024 * 1024;
        let c = p.recommended_concurrency(192 * 1024 * 1024);
        assert!((1..=4).contains(&c), "got {c}");
    }

    #[test]
    fn pathbuf_used() {
        let _ = PathBuf::from("/tmp");
    }
}
