//! Native TCP connect scan (no raw sockets, no root).
//!
//! Runs as an ordinary unprivileged process: SYN scanning is impossible without
//! privileges, so this is a connect scan with per-connection timeouts and a
//! bounded worker pool.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Well-known ports scanned when the caller does not specify a set.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 873,
    993, 995, 1080, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000,
    3128, 3306, 3389, 4000, 4190, 4369, 4443, 4444, 4567, 5000, 5001, 5432, 5601, 5672, 5900,
    5984, 6000, 6379, 6666, 7001, 8000, 8001, 8008, 8080, 8081, 8088, 8090, 8443, 8500, 8888,
    9000, 9001, 9090, 9092, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 15672, 27017, 50000,
];

const SERVICE_MAP: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (81, "http-alt"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (389, "ldap"),
    (443, "https"),
    (445, "smb"),
    (465, "smtps"),
    (587, "submission"),
    (631, "ipp"),
    (873, "rsync"),
    (993, "imaps"),
    (995, "pop3s"),
    (1080, "socks"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (3000, "http-dev"),
    (3306, "mysql"),
    (3389, "rdp"),
    (3389, "rdp"),
    (4369, "epmd"),
    (5432, "postgres"),
    (5672, "amqp"),
    (5900, "vnc"),
    (5984, "couchdb"),
    (6379, "redis"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "http-alt"),
    (9090, "http-alt"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (9443, "https-alt"),
    (11211, "memcached"),
    (15672, "rabbitmq-mgmt"),
    (27017, "mongodb"),
];

pub fn service_for(port: u16) -> &'static str {
    SERVICE_MAP
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, s)| *s)
        .unwrap_or("unknown")
}

/// Parse `1-1024,8080,9000-9010` (or `top` for the built-in list).
pub fn parse_ports(spec: Option<&str>, limit: usize) -> anyhow::Result<Vec<u16>> {
    let spec = match spec {
        None | Some("") | Some("top") => {
            let mut v = DEFAULT_PORTS.to_vec();
            v.truncate(limit);
            return Ok(v);
        }
        Some(s) => s,
    };

    let mut ports: Vec<u16> = Vec::new();
    for part in spec.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| anyhow::anyhow!("invalid port `{part}`"))?;
            let end: u16 = b.trim().parse().map_err(|_| anyhow::anyhow!("invalid port `{part}`"))?;
            if start == 0 || end == 0 || start > end {
                anyhow::bail!("invalid port range `{part}`");
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port `{part}`"))?;
            if p == 0 {
                anyhow::bail!("port 0 is not valid");
            }
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        anyhow::bail!("no ports selected");
    }
    if ports.len() > limit {
        anyhow::bail!(
            "refusing to scan {} ports (limit {limit}); narrow the range",
            ports.len()
        );
    }
    Ok(ports)
}

async fn probe(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await,
        Ok(Ok(_))
    )
}

async fn banner(ip: IpAddr, port: u16) -> Option<String> {
    let mut stream = tokio::time::timeout(Duration::from_millis(600), TcpStream::connect((ip, port)))
        .await
        .ok()
        .and_then(|r| r.ok())?;
    let mut buf = [0u8; 256];
    // Some services speak first; HTTP services need a nudge.
    let n = match tokio::time::timeout(Duration::from_millis(400), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(n),
        _ => {
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: lantern\r\n\r\n").await;
            match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => Some(n),
                _ => None,
            }
        }
    }?;
    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    let text: String = text.chars().filter(|c| !c.is_control() || *c == '\n').take(160).collect();
    if text.trim().is_empty() {
        None
    } else {
        Some(text.trim().to_string())
    }
}

pub struct PortScan;

impl Tool for PortScan {
    fn name(&self) -> &'static str {
        "port_scan"
    }

    fn description(&self) -> &'static str {
        "TCP connect scan of a single in-scope host. Uses the built-in common-port \
         list unless a range is given. Returns open ports, service guesses and banners."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "IP or hostname, must be in scope"},
                "ports": {"type": "string", "description": "e.g. \"1-1024,3306,8080-8090\", or \"top\""},
                "timeout_ms": {"type": "integer", "description": "per-connection timeout, default 400"},
                "concurrency": {"type": "integer", "description": "default 128, max 512"}
            },
            "required": ["host"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let host = super::str_field(&input, "host")?;
            ctx.check_scope(&host)?;

            let ports = parse_ports(super::opt_str_field(&input, "ports").as_deref(), 2_000)?;
            let timeout_ms = super::opt_u64(&input, "timeout_ms", 400).clamp(50, 5_000);
            let concurrency = super::opt_u64(&input, "concurrency", 128).clamp(1, 512) as usize;

            let started = Instant::now();
            // Resolve once; scan every port against the first answer.
            let addr = format!("{host}:0");
            let addrs: Vec<IpAddr> = tokio::net::lookup_host(&addr)
                .await?
                .map(|a| a.ip())
                .collect();
            let Some(ip) = addrs.first().copied() else {
                return Ok(ToolOutput::failed(format!("could not resolve {host}")));
            };

            let timeout = Duration::from_millis(timeout_ms);
            let sem = std::sync::Arc::new(Semaphore::new(concurrency));
            let mut set = JoinSet::new();

            for &port in &ports {
                let sem = sem.clone();
                set.spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    probe(ip, port, timeout).await.then_some(port)
                });
            }

            let mut open: Vec<u16> = Vec::new();
            while let Some(res) = set.join_next().await {
                if let Ok(Some(port)) = res {
                    open.push(port);
                }
            }
            open.sort_unstable();

            // Banners for the first few open ports only (bounded work).
            let mut services = Vec::new();
            for &port in open.iter().take(12) {
                let b = banner(ip, port).await;
                services.push(json!({
                    "port": port,
                    "proto": "tcp",
                    "service": service_for(port),
                    "banner": b,
                }));
            }
            for &port in open.iter().skip(12) {
                services.push(json!({
                    "port": port,
                    "proto": "tcp",
                    "service": service_for(port),
                    "banner": null,
                }));
            }

            let elapsed = started.elapsed().as_millis() as u64;
            let summary = if open.is_empty() {
                format!(
                    "connect scan of {host} ({ip}): {ports_len} ports probed in {elapsed} ms, none open",
                    ports_len = ports.len()
                )
            } else {
                format!(
                    "connect scan of {host} ({ip}): {n} open of {total} probed in {elapsed} ms -> {}",
                    open.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                    n = open.len(),
                    total = ports.len()
                )
            };

            ctx.reserve(services.len() as u64 * 400)?;

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "host": host,
                    "ip": ip.to_string(),
                    "resolved": addrs.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                    "ports_scanned": ports.len(),
                    "open": services,
                    "method": "tcp_connect",
                    "duration_ms": elapsed,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_defaults() {
        let top = parse_ports(None, 2_000).unwrap();
        assert_eq!(top, DEFAULT_PORTS);
        assert_eq!(parse_ports(Some("top"), 2_000).unwrap(), DEFAULT_PORTS);

        let p = parse_ports(Some("22,80,443"), 2_000).unwrap();
        assert_eq!(p, vec![22, 80, 443]);

        let r = parse_ports(Some("8000-8005"), 2_000).unwrap();
        assert_eq!(r, vec![8000, 8001, 8002, 8003, 8004, 8005]);

        assert!(parse_ports(Some("0"), 2_000).is_err());
        assert!(parse_ports(Some("900-100"), 2_000).is_err());
        assert!(parse_ports(Some("abc"), 2_000).is_err());
        assert!(parse_ports(Some("1-3000"), 2_000).is_err(), "over limit");
    }

    #[test]
    fn service_lookup() {
        assert_eq!(service_for(22), "ssh");
        assert_eq!(service_for(27017), "mongodb");
        assert_eq!(service_for(12345), "unknown");
    }

    #[tokio::test]
    async fn scans_localhost() {
        // Nothing listens on 1 (tcpmux), so the scan must return an empty list
        // and still complete.
        let out = PortScan
            .execute(
                json!({"host": "127.0.0.1", "ports": "1", "timeout_ms": 200}),
                &super::super::test_ctx(),
            )
            .await
            .expect("scan should run");
        assert!(out.ok);
        assert_eq!(out.data["open"].as_array().unwrap().len(), 0);
        assert_eq!(out.data["ports_scanned"], 1);
    }

    #[tokio::test]
    async fn refuses_out_of_scope_target() {
        // Narrow scope: the check must reject before any packet leaves the box.
        let err = PortScan
            .execute(
                json!({"host": "10.99.99.99"}),
                &super::super::test_ctx_scoped("127.0.0.1/32, localhost"),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }
}
