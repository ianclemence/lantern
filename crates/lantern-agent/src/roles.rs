//! The cast: what each role is allowed to do, and how far it may go.
//!
//! Roles are metadata + prompts. Nothing here can execute anything by itself:
//! every capability goes through `lantern_tools::Registry::execute`, which is
//! the single choke point for scope and `--offensive` gating.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleId {
    Orchestrator,
    Planner,
    Researcher,
    Coder,
    Pentester,
    Reflector,
}

impl RoleId {
    pub const ALL: [RoleId; 6] = [
        RoleId::Orchestrator,
        RoleId::Planner,
        RoleId::Researcher,
        RoleId::Coder,
        RoleId::Pentester,
        RoleId::Reflector,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RoleId::Orchestrator => "orchestrator",
            RoleId::Planner => "planner",
            RoleId::Researcher => "researcher",
            RoleId::Coder => "coder",
            RoleId::Pentester => "pentester",
            RoleId::Reflector => "reflector",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let want = s.trim().to_ascii_lowercase();
        RoleId::ALL.into_iter().find(|r| r.as_str() == want)
    }
}

impl std::fmt::Display for RoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static description of a role.
#[derive(Debug, Clone, Copy)]
pub struct Role {
    pub id: RoleId,
    /// One sentence the runtime shows the model and the operator.
    pub mission: &'static str,
    /// Tools this role is steered toward (the registry still enforces scope).
    pub focus: &'static [&'static str],
    /// Hard cap on model turns inside one role.
    pub max_steps: usize,
    /// Whether the role's final text is parsed for `{"findings": [...]}`.
    pub emits_findings: bool,
}

static ROLES: [Role; 6] = [
    Role {
        id: RoleId::Orchestrator,
        mission: "Turn the engagement objective into a short written plan.",
        focus: &[],
        max_steps: 1,
        emits_findings: false,
    },
    Role {
        id: RoleId::Planner,
        mission: "Order the plan by risk and effort, naming the tool for each step.",
        focus: &[],
        max_steps: 1,
        emits_findings: false,
    },
    Role {
        id: RoleId::Researcher,
        mission: "Passive reconnaissance only: what exists, what it runs, what it says.",
        focus: &[
            "dns_lookup",
            "whois",
            "http_probe",
            "tls_inspect",
            "web_search",
            "port_scan",
        ],
        max_steps: 6,
        emits_findings: true,
    },
    Role {
        id: RoleId::Coder,
        mission: "Turn observations into reproducible check steps and remediation advice.",
        focus: &[],
        max_steps: 2,
        emits_findings: true,
    },
    Role {
        id: RoleId::Pentester,
        mission: "Active verification inside scope; never cross into exploitation.",
        focus: &[
            "port_scan",
            "dir_bruteforce",
            "host_nmap",
            "host_nikto",
            "host_tcpdump",
            "host_sqlmap",
            "host_hydra",
        ],
        max_steps: 6,
        emits_findings: true,
    },
    Role {
        id: RoleId::Reflector,
        mission: "Judge evidence quality and confidence of every finding.",
        focus: &[],
        max_steps: 1,
        emits_findings: false,
    },
];

pub fn roles() -> &'static [Role] {
    &ROLES
}

pub fn role(id: RoleId) -> &'static Role {
    ROLES
        .iter()
        .find(|r| r.id == id)
        .expect("every RoleId has metadata")
}

/// Order roles run in during a normal flow.
pub fn pipeline() -> [RoleId; 6] {
    RoleId::ALL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_role_is_described() {
        assert_eq!(roles().len(), 6);
        for id in RoleId::ALL {
            let r = role(id);
            assert_eq!(r.id, id);
            assert!(!r.mission.is_empty());
            assert!(r.max_steps >= 1);
        }
    }

    #[test]
    fn roles_round_trip_from_strings() {
        for id in RoleId::ALL {
            assert_eq!(RoleId::parse(id.as_str()), Some(id));
            assert_eq!(id.to_string(), id.as_str());
        }
        assert_eq!(RoleId::parse("RESEARCHER"), Some(RoleId::Researcher));
        assert_eq!(RoleId::parse("nobody"), None);
    }

    #[test]
    fn active_tools_only_reach_the_pentester() {
        // Belt and braces: offensive-gated host tools must not be in a passive
        // role's focus list.
        for r in roles() {
            if r.id == RoleId::Pentester {
                continue;
            }
            assert!(
                !r.focus.contains(&"host_sqlmap") && !r.focus.contains(&"host_hydra"),
                "{} must not be steered at active-attack tools",
                r.id
            );
        }
    }
}
