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

/// CPU vendors this profile is willing to quote back. Anything else in the
/// `Model` line of `/proc/cpuinfo` describes the *board* rather than the CPU,
/// and the board is not what a device profile is about: those hosts get the
/// neutral "N cores, arch" line instead.
const CPU_VENDORS: &[&str] = &[
    "intel",
    "amd",
    "arm",
    "apple",
    "qualcomm",
    "mediatek",
    "nvidia",
    "hygon",
    "zhaoxin",
    "loongson",
    "rockchip",
    "phytium",
    "ampere",
    "fujitsu",
    "hisilicon",
    "samsung",
    "nxp",
    "marvell",
    "ibm",
    "centaur",
];

fn names_a_cpu(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    CPU_VENDORS.iter().any(|v| t.contains(v))
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

/// The CPU as reported by `/proc/cpuinfo`, or an empty string when the only
/// thing the kernel will say is the board's own name - that is withheld.
fn cpu_model() -> String {
    let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") else {
        return String::new();
    };
    for key in ["model name", "Model", "Hardware", "Processor"] {
        let found = text.lines().filter_map(|l| l.split_once(':')).find(
            |(k, _)| k.trim() == key,
        );
        if let Some((_, v)) = found {
            let v = v.trim();
            if !v.is_empty() && names_a_cpu(v) {
                return v.to_string();
            }
        }
    }
    String::new()
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
/// Device-tree node names are deliberately left out: they identify the board.
fn gpu_summary() -> String {
    if std::path::Path::new("/dev/nvidia0").exists() || std::path::Path::new("/dev/nvidiactl").exists()
    {
        return "NVIDIA device nodes present".into();
    }
    let has_display = std::fs::read_dir("/sys/class/drm").map(|rd| {
        rd.flatten().any(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("card") && !name.contains('-')
        })
    });
    match has_display {
        Ok(true) => "display-only - no compute capability".into(),
        _ => "none".into(),
    }
}

/// Kernel release without the packaging tags: the part after `+` is the
/// distro's local build, and a vendor suffix can name the board.
fn kernel_release() -> String {
    let raw = read_first(Path::new("/proc/sys/kernel/osrelease"))
        .unwrap_or_else(|| "unknown".into());
    kernel_release_of(&raw)
}

/// Reduce a kernel release string to the version proper: digits and dots only,
/// so everything a distribution appends to it (build tags, local flavour
/// names) describes *its* build of the kernel rather than the host.
fn kernel_release_of(raw: &str) -> String {
    let raw = raw.trim();
    if raw == "unknown" {
        return raw.to_string();
    }
    let digits: String = raw
        .trim_start_matches(|c: char| c.is_ascii_digit())
        .to_string();
    let major = &raw[..raw.len() - digits.len()];
    if major.is_empty() {
        return "unknown".into();
    }
    let mut out = major.to_string();
    for part in digits.trim_start_matches('.').split('.') {
        let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if numeric.is_empty() {
            break;
        }
        out.push('.');
        out.push_str(&numeric);
    }
    out
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
            kernel: kernel_release(),
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
    fn the_profile_reports_only_what_it_is_about() {
        let p = DeviceProfile::detect(Path::new("/"));
        // CPU: either withheld (this host only knows its board) or a vendor.
        if !p.cpu_model.is_empty() {
            assert!(
                names_a_cpu(&p.cpu_model),
                "quoted a string that is not a CPU: {}",
                p.cpu_model
            );
        }
        // Kernel: digits and dots, so no packaging tag can survive.
        assert!(!p.kernel.contains('+'), "packaging tag kept: {}", p.kernel);
        assert!(
            p.kernel.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "not a plain version: {}",
            p.kernel
        );
        // GPU: a status line, never a device path.
        assert!(!p.gpu.contains('/'), "path leaked: {}", p.gpu);
        assert!(
            !p.inference_summary().contains('/'),
            "path leaked: {}",
            p.inference_summary()
        );
    }

    #[test]
    fn pathbuf_used() {
        let _ = PathBuf::from("/tmp");
    }
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn kernel_version_drops_every_packaging_tag() {
        // The three shapes seen in the wild: distro build tag, flavour suffix,
        // and a plain version.
        for (raw, want) in [
            ("6.18.50+rpt-local", "6.18.50"),
            ("6.1.0-21-amd64", "6.1.0"),
            ("5.15.0", "5.15.0"),
        ] {
            let got = super::kernel_release_of(raw);
            assert_eq!(got, want, "input {raw}");
        }
        assert_eq!(super::kernel_release_of("unknown"), "unknown");
        assert_eq!(super::kernel_release_of("v8"), "unknown");
    }
}
