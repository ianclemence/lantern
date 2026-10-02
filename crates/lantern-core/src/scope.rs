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

    /// Is `target` (an IP literal, a CIDR range, or a host name) inside this
    /// scope?
    ///
    /// A bare `ip/prefix` target — the shape a tool like `msfconsole` takes
    /// for `RHOSTS` — is checked as a *network subset*, not as a single
    /// address: the whole range it names must fall inside one declared scope
    /// entry (`target_prefix >= entry_prefix`, same network). Naively
    /// stripping the `/prefix` as if it were a URL path (as this function
    /// used to) would validate only the network's base address, so a scope of
    /// `10.0.0.0/24` would wrongly wave through a target of `10.0.0.0/8` —
    /// a scope bypass that scans far more than was declared. See
    /// `widening_cidr_is_rejected_even_when_base_address_matches` below.
    pub fn allows(&self, target: &str) -> bool {
        let t = target.trim();
        if t.is_empty() {
            return false;
        }
        let lower = t.to_ascii_lowercase();
        let after_scheme = lower.split("://").nth(1).unwrap_or(&lower);

        // Bare CIDR shape: no scheme beyond an optional `proto://`, and
        // exactly one `/` separating an address from an all-digit prefix (so
        // `example.com/path` and `10.0.0.1/24/x` both fall through to the
        // ordinary host/IP handling below instead).
        if let Some((addr, prefix)) = after_scheme.split_once('/') {
            if !prefix.is_empty() && !prefix.contains('/') && prefix.chars().all(|c| c.is_ascii_digit()) {
                if let (Ok(ip), Ok(prefix)) = (addr.parse::<IpAddr>(), prefix.parse::<u8>()) {
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    if prefix <= max {
                        return self.entries.iter().any(|e| match e {
                            ScopeEntry::Net { ip: net, prefix: net_prefix } => {
                                prefix >= *net_prefix && in_net(ip, *net, *net_prefix)
                            }
                            ScopeEntry::Host(_) => false,
                        });
                    }
                }
            }
        }

        // Strip a URL-ish prefix so `https://host/path` still matches `host`.
        let bare = after_scheme.split('/').next().unwrap_or(after_scheme);
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

    #[test]
    fn cidr_target_must_be_a_subset_of_a_scope_entry() {
        let s = Scope::parse("10.0.0.0/24").unwrap();
        // Equal range and a narrower range both fall entirely inside /24.
        assert!(s.allows("10.0.0.0/24"));
        assert!(s.allows("10.0.0.0/25"));
        assert!(s.allows("10.0.0.128/25"));
        // A disjoint /24 next door is still out.
        assert!(!s.allows("10.0.1.0/24"));
    }

    #[test]
    fn widening_cidr_is_rejected_even_when_base_address_matches() {
        // Regression: the old implementation stripped `/prefix` the same way
        // it stripped a URL path, then checked only the bare base address
        // ("10.0.0.0") against scope entries. That base address legitimately
        // sits inside 10.0.0.0/24, so a target of 10.0.0.0/8 — a request to
        // touch roughly sixteen million addresses on a scope that authorised
        // 256 — was incorrectly accepted. It must now be rejected: the
        // target's own prefix has to be at least as narrow as the entry's.
        let s = Scope::parse("10.0.0.0/24").unwrap();
        assert!(!s.allows("10.0.0.0/8"), "a supernet must never pass a narrower scope");
        assert!(!s.allows("10.0.0.0/0"));
        assert!(!s.allows("0.0.0.0/0"));
    }

    #[test]
    fn cidr_target_outside_any_entry_is_rejected() {
        let s = Scope::parse("example.com, 192.168.1.5/32").unwrap();
        assert!(!s.allows("10.0.0.0/24"));
        // A single host entry (a /32) does not widen to cover a /24 either.
        assert!(!s.allows("192.168.1.0/24"));
    }
}
