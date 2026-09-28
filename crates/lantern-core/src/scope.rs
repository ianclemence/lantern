//! Target scope enforcement.
//!
//! Every flow declares exactly what it is allowed to touch. Tools reject any
//! target that is not covered, so a hallucinated or injected hostname can never
//! be scanned.

use crate::error::{CoreError, Result};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    /// Exact host name (case-insensitive), or a `*.suffix` wildcard.
    Host(String),
    /// IP address or CIDR network.
    Net { ip: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    entries: Vec<ScopeEntry>,
}

impl Scope {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a comma/whitespace separated scope specification.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut scope = Self::new();
        for raw in spec.split([',', ' ', '\t', '\n']).filter(|s| !s.trim().is_empty()) {
            scope.add(raw)?;
        }
        if scope.entries.is_empty() {
            return Err(CoreError::Config("empty scope".into()));
        }
        Ok(scope)
    }

    pub fn add(&mut self, entry: &str) -> Result<()> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        if let Some((addr, prefix)) = entry.split_once('/') {
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid address in scope: {entry}")))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| CoreError::Config(format!("invalid prefix in scope: {entry}")))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(CoreError::Config(format!("prefix /{prefix} out of range for {ip}")));
            }
            self.entries.push(ScopeEntry::Net { ip, prefix });
            return Ok(());
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            self.entries.push(ScopeEntry::Net { ip, prefix });
            return Ok(());
        }
        self.entries.push(ScopeEntry::Host(entry.to_ascii_lowercase()));
        Ok(())
    }

    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Is `target` (an IP literal or host name) inside this scope?
    pub fn allows(&self, target: &str) -> bool {
        let t = target.trim();
        if t.is_empty() {
            return false;
        }
        let lower = t.to_ascii_lowercase();
        // Strip a URL-ish prefix so `https://host/path` still matches `host`.
        let bare = lower
            .split("://")
            .nth(1)
            .unwrap_or(&lower)
            .split('/')
            .next()
            .unwrap_or(&lower);
        let bare = bare.split('@').next_back().unwrap_or(bare);
        let bare = strip_port(bare);

        if let Ok(ip) = bare.parse::<IpAddr>() {
            for e in &self.entries {
                if let ScopeEntry::Net { ip: net, prefix } = e {
                    if in_net(ip, *net, *prefix) {
                        return true;
                    }
                }
            }
            return false;
        }

        for e in &self.entries {
            match e {
                ScopeEntry::Host(h) => {
                    if let Some(suffix) = h.strip_prefix("*.") {
                        if bare == suffix || bare.ends_with(&format!(".{suffix}")) {
                            return true;
                        }
                    } else if bare == h {
                        return true;
                    }
                }
                ScopeEntry::Net { .. } => {}
            }
        }
        false
    }

    /// Validate, returning a typed error suitable for surfacing to the model.
    pub fn require(&self, target: &str) -> Result<()> {
        if self.allows(target) {
            Ok(())
        } else {
            Err(CoreError::OutOfScope(target.to_string()))
        }
    }

    pub fn render(&self) -> String {
        self.entries
            .iter()
            .map(|e| match e {
                ScopeEntry::Host(h) => h.clone(),
                ScopeEntry::Net { ip, prefix } => format!("{ip}/{prefix}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Remove a trailing `:port` without breaking IPv6 literals.
///
/// `host:443` and `10.0.0.1:8080` lose the port; `::1`, `fd00::1` and
/// `[::1]:443` keep their address intact.
fn strip_port(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match s.rsplit_once(':') {
        // A real port suffix: no further colons on the left, digits on the right.
        Some((host, port)) if !host.contains(':') && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => s,
    }
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if prefix == 0 {
                return true;
            }
            let bits = 32 - prefix;
            (u32::from(a) >> bits) == (u32::from(b) >> bits)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if prefix == 0 {
                return true;
            }
            let bits = 128 - prefix;
            (u128::from(a) >> bits) == (u128::from(b) >> bits)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let s = Scope::parse("192.168.0.0/24, 10.0.0.5, *.example.com").unwrap();
        assert!(s.allows("192.168.0.107"));
        assert!(s.allows("192.168.0.1"));
        assert!(!s.allows("192.168.1.1"));
        assert!(s.allows("10.0.0.5"));
        assert!(!s.allows("10.0.0.6"));
        assert!(s.allows("example.com"));
        assert!(s.allows("api.example.com"));
        assert!(!s.allows("notexample.com"));
    }

    #[test]
    fn url_and_port_stripped() {
        let s = Scope::parse("127.0.0.1").unwrap();
        assert!(s.allows("https://127.0.0.1:8443/login"));
        assert!(s.allows("127.0.0.1:8080"));
    }

    #[test]
    fn v6_supported() {
        let s = Scope::parse("::1/128, fd00::/8").unwrap();
        assert!(s.allows("::1"));
        assert!(s.allows("fd00::abcd"));
        assert!(!s.allows("fe80::1"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Scope::parse("").is_err());
        assert!(Scope::parse("999.1.1.1/33").is_err());
        assert!(Scope::parse("not-an-ip/24").is_err());
    }

    #[test]
    fn require_errors_outside() {
        let s = Scope::parse("10.0.0.0/8").unwrap();
        assert!(s.require("8.8.8.8").is_err());
        assert!(s.require("10.1.2.3").is_ok());
    }
}
