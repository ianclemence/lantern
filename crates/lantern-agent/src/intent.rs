//! Natural-language instruction handling: what the operator asked for, in the
//! operator's own words, reduced to the three decisions a flow needs.
//!
//! A prompt can say anything - including "exploit it" - but the model is never
//! the authority on what may run. This module only *reads* intent; the CLI
//! flag (or environment) still grants it. `resolve_offensive` is where those
//! two meet, and its rule is deliberate:
//!
//! * an explicit restraint in the prompt ("defensive only", "do not exploit")
//!   always wins, even when `--offensive` was passed - the flag permits, the
//!   instruction directs, and the narrower of the two governs;
//! * a request for active testing without the flag never enables anything -
//!   it downgrades to reconnaissance with a message naming the flag;
//! * silence means the flag decides alone.
//!
//! Everything here is deterministic string matching, no model call: intent
//! must be readable in tests and cost nothing to compute.

use crate::roles::RoleId;

/// The assessment contract (§1 of the framework prompt): the fields the
/// operator fills in. Every field is optional - a short instruction like
/// "check TLS on example.com" carries none of them and still runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contract {
    pub system_name: String,
    pub targets: String,
    pub authorized_assets: String,
    pub authorized_environments: String,
    pub out_of_scope: String,
    pub test_accounts: String,
    pub test_roles: String,
    pub test_tenants: String,
    pub test_data: String,
    pub known_architecture: String,
    pub known_technologies: String,
    pub known_integrations: String,
    pub rate_limit: String,
    pub safety_constraints: String,
    pub special_instructions: String,
}

impl Contract {
    /// Fields actually filled in, as `NAME=value` pairs for the intent card.
    pub fn present(&self) -> Vec<(&'static str, &str)> {
        let all = [
            ("SYSTEM_NAME", self.system_name.as_str()),
            ("TARGETS", self.targets.as_str()),
            ("AUTHORIZED_ASSETS", self.authorized_assets.as_str()),
            (
                "AUTHORIZED_ENVIRONMENTS",
                self.authorized_environments.as_str(),
            ),
            ("OUT_OF_SCOPE", self.out_of_scope.as_str()),
            ("TEST_ACCOUNTS", self.test_accounts.as_str()),
            ("TEST_ROLES", self.test_roles.as_str()),
            ("TEST_TENANTS", self.test_tenants.as_str()),
            ("TEST_DATA", self.test_data.as_str()),
            ("KNOWN_ARCHITECTURE", self.known_architecture.as_str()),
            ("KNOWN_TECHNOLOGIES", self.known_technologies.as_str()),
            ("KNOWN_INTEGRATIONS", self.known_integrations.as_str()),
            ("RATE_LIMIT", self.rate_limit.as_str()),
            (
                "PRODUCTION_SAFETY_CONSTRAINTS",
                self.safety_constraints.as_str(),
            ),
            ("SPECIAL_INSTRUCTIONS", self.special_instructions.as_str()),
        ];
        all.into_iter()
            .filter(|(_, v)| !v.trim().is_empty())
            .collect()
    }

    /// Declared targets, split for the mismatch check against `--target`.
    pub fn target_list(&self) -> Vec<String> {
        self.targets
            .split([',', ';', '\n'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .take(8)
            .collect()
    }
}

/// What a prompt asks for, as far as a flow can tell without a model.
#[derive(Debug, Clone, Default)]
pub struct Intent {
    /// The prompt asks for active testing: exploitation, brute force,
    /// intrusive tools by name, or the words themselves.
    pub wants_offensive: bool,
    /// The prompt explicitly restrains the assessment to defensive work.
    /// Wins over everything, including the flag.
    pub defensive_only: bool,
    /// Which signals fired, for the intent card and the tests.
    pub signals: Vec<String>,
    pub contract: Contract,
    /// Roles the prompt's vocabulary points at. Empty means "default
    /// pipeline" - most short instructions name no role at all.
    pub roles_hint: Vec<RoleId>,
}

/// Action verbs and tool names that mean "actively test", not "look and
/// report". Topic nouns alone ("privilege escalation" as a coverage item in a
/// framework) must not match: only language that directs action counts.
const OFFENSIVE_SIGNALS: &[&str] = &[
    "exploit",
    "payload",
    "reverse shell",
    "brute force",
    "brute-force",
    "bruteforce",
    "password spray",
    "credential attack",
    "credential stuffing",
    "crack the",
    "crack hashes",
    "sqlmap",
    "hydra",
    "msfconsole",
    "metasploit",
    "john the ripper",
    "active testing",
    "intrusive",
    "penetration test",
    "pentest",
    "red team",
];

/// Explicit restraint. Any one of these makes the run reconnaissance-only no
/// matter what the flag says.
const DEFENSIVE_SIGNALS: &[&str] = &[
    "defensive only",
    "defense only",
    "defence only",
    "do not exploit",
    "don't exploit",
    "do not attack",
    "no exploitation",
    "without exploit",
    "reconnaissance only",
    "recon only",
    "passive only",
    "read-only",
    "read only",
    "non-intrusive",
    "no intrusive",
];

/// (keyword, role) pairs mapping the framework's vocabulary onto the cast.
const ROLE_SIGNALS: &[(&str, RoleId)] = &[
    ("recon", RoleId::Researcher),
    ("discover", RoleId::Researcher),
    ("attack surface", RoleId::Researcher),
    ("fingerprint", RoleId::Researcher),
    ("subdomain", RoleId::Researcher),
    ("robots", RoleId::Researcher),
    ("sitemap", RoleId::Researcher),
    ("injection", RoleId::Pentester),
    ("exploit", RoleId::Pentester),
    ("payload", RoleId::Pentester),
    ("hydra", RoleId::Pentester),
    ("sqlmap", RoleId::Pentester),
    ("login", RoleId::Pentester),
    ("xss", RoleId::Pentester),
    ("csrf", RoleId::Pentester),
    ("ssrf", RoleId::Pentester),
    ("bypass", RoleId::Pentester),
    ("authorization", RoleId::Pentester),
    ("authentication", RoleId::Pentester),
    ("session", RoleId::Pentester),
    ("brute", RoleId::Pentester),
    ("upload", RoleId::Pentester),
    ("traversal", RoleId::Pentester),
    ("idor", RoleId::Pentester),
    ("broken access", RoleId::Pentester),
    ("privilege esc", RoleId::Pentester),
    ("business logic", RoleId::Coder),
    ("workflow", RoleId::Coder),
    ("transaction", RoleId::Coder),
    ("race condition", RoleId::Coder),
    ("state transition", RoleId::Coder),
    ("invariant", RoleId::Coder),
    ("remediation", RoleId::Coder),
    ("retest", RoleId::Coder),
    ("coverage", RoleId::Reflector),
    ("attack path", RoleId::Reflector),
    ("attack-path", RoleId::Reflector),
    ("systemic", RoleId::Reflector),
    ("root cause", RoleId::Reflector),
    ("severity", RoleId::Reflector),
    ("confidence", RoleId::Reflector),
    ("executive summary", RoleId::Reflector),
];

/// Contract keys, normalised (`KNOWN_TECHNOLOGIES`, case-insensitive,
///
/// spaces and dashes become underscores).
fn contract_key(raw: &str) -> String {
    raw.trim()
        .to_ascii_uppercase()
        .chars()
        .map(|c| if c == ' ' || c == '-' { '_' } else { c })
        .collect()
}

fn parse_contract(text: &str) -> Contract {
    let mut c = Contract::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let value = v.trim().to_string();
        if value.is_empty() {
            continue;
        }
        match contract_key(k).as_str() {
            "SYSTEM_NAME" => c.system_name = value,
            "TARGETS" => c.targets = value,
            "AUTHORIZED_ASSETS" => c.authorized_assets = value,
            "AUTHORIZED_ENVIRONMENTS" => c.authorized_environments = value,
            "OUT_OF_SCOPE" => c.out_of_scope = value,
            "TEST_ACCOUNTS" => c.test_accounts = value,
            "TEST_ROLES" => c.test_roles = value,
            "TEST_TENANTS" => c.test_tenants = value,
            "TEST_DATA" => c.test_data = value,
            "KNOWN_ARCHITECTURE" => c.known_architecture = value,
            "KNOWN_TECHNOLOGIES" => c.known_technologies = value,
            "KNOWN_INTEGRATIONS" => c.known_integrations = value,
            "RATE_LIMIT" => c.rate_limit = value,
            "PRODUCTION_SAFETY_CONSTRAINTS" => c.safety_constraints = value,
            "SPECIAL_INSTRUCTIONS" => c.special_instructions = value,
            _ => {}
        }
    }
    c
}

/// Reduce a prompt to intent. Deterministic, free, testable.
pub fn parse_intent(text: &str) -> Intent {
    let lower = text.to_ascii_lowercase();
    let mut intent = Intent {
        contract: parse_contract(text),
        ..Intent::default()
    };
    for s in DEFENSIVE_SIGNALS {
        if lower.contains(s) {
            intent.defensive_only = true;
            intent.signals.push(format!("restraint: {s}"));
        }
    }
    // A restraint stated anywhere governs the whole prompt: action verbs
    // later in the text do not override it.
    if !intent.defensive_only {
        for s in OFFENSIVE_SIGNALS {
            if lower.contains(s) {
                intent.wants_offensive = true;
                intent.signals.push(format!("active: {s}"));
            }
        }
    }
    for (kw, role) in ROLE_SIGNALS {
        if lower.contains(kw) && !intent.roles_hint.contains(role) {
            intent.roles_hint.push(*role);
        }
    }
    // Pipeline order, so a hint never reorders the cast.
    intent.roles_hint.sort_by_key(|r| *r as usize);
    intent
}

/// Merge the flag (authority) with the prompt (instruction). Returns the
/// effective mode plus a warning when the two disagreed, so the operator
/// always sees *why* a run stayed defensive.
pub fn resolve_offensive(flag: bool, intent: &Intent) -> (bool, Option<String>) {
    if intent.defensive_only {
        if flag {
            return (
                false,
                Some(
                    "prompt restricts this run to defensive work: --offensive is \
                     accepted but not used"
                        .to_string(),
                ),
            );
        }
        return (false, None);
    }
    if intent.wants_offensive && !flag {
        return (
            false,
            Some(
                "prompt asks for active testing but --offensive was not passed: \
                 running reconnaissance only (re-run with --offensive to allow it)"
                    .to_string(),
            ),
        );
    }
    (flag, None)
}

/// Characters of operator directive handed to each role objective. The working
/// set is budgeted at 6,000 tokens and every request already carries ~3,300 of
/// schemas and system prompt, so the brief is the head of the instruction -
/// mission and contract first - never the whole framework.
pub const DIRECTIVE_CHARS: usize = 3_000;

/// Head-clip the directive on a char boundary, saying so when it cut.
pub fn condense_directive(text: &str, max_chars: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let head: String = text.chars().take(max_chars).collect();
    format!(
        "{head}\n…[directive truncated to {max_chars} chars; \
         the full text is stored with the flow]"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_recon_asks_for_nothing() {
        let i = parse_intent("Check the TLS certificate and HTTP headers on example.com");
        assert!(!i.wants_offensive);
        assert!(!i.defensive_only);
        assert!(i.contract.present().is_empty());
    }

    #[test]
    fn exploit_language_is_offensive() {
        let i = parse_intent("Exploit the login form and try hydra against SSH");
        assert!(i.wants_offensive);
        assert!(!i.defensive_only);
        assert!(i.roles_hint.contains(&RoleId::Pentester));
    }

    #[test]
    fn coverage_nouns_alone_are_not_offensive() {
        // The framework lists "privilege escalation" as a coverage item; that
        // is a topic, not an instruction to escalate.
        let i = parse_intent(
            "Coverage: authentication, privilege escalation, severity, confidence",
        );
        assert!(!i.wants_offensive, "signals: {:?}", i.signals);
        assert!(i.roles_hint.contains(&RoleId::Reflector));
    }

    #[test]
    fn restraint_beats_action_verbs() {
        let i = parse_intent(
            "Defensive only assessment. Look for authentication bypass \
             but do not exploit anything.",
        );
        assert!(i.defensive_only);
        assert!(!i.wants_offensive);
    }

    #[test]
    fn the_flag_never_overrides_a_restraint() {
        let i = parse_intent("read-only review, no intrusive steps");
        let (eff, warn) = resolve_offensive(true, &i);
        assert!(!eff);
        assert!(warn.unwrap().contains("--offensive is"));
    }

    #[test]
    fn active_testing_without_the_flag_downgrades_loudly() {
        let i = parse_intent("Run sqlmap against the search form");
        let (eff, warn) = resolve_offensive(false, &i);
        assert!(!eff);
        assert!(warn.unwrap().contains("--offensive"));
    }

    #[test]
    fn flag_alone_decides_when_the_prompt_is_quiet() {
        let quiet = parse_intent("check DNS");
        assert_eq!(resolve_offensive(false, &quiet), (false, None));
        assert_eq!(resolve_offensive(true, &quiet), (true, None));
    }

    #[test]
    fn contract_fields_parse_and_list_targets() {
        let i = parse_intent(
            "SYSTEM_NAME: Shop\nTARGETS: shop.example.com, api.example.com\n\
             OUT_OF_SCOPE:\nRATE_LIMIT: 10 rps\n",
        );
        assert_eq!(i.contract.system_name, "Shop");
        assert_eq!(
            i.contract.target_list(),
            vec!["shop.example.com", "api.example.com"]
        );
        assert!(i.contract.rate_limit.contains("10 rps"));
        assert_eq!(i.contract.present().len(), 3, "empty values are dropped");
    }

    #[test]
    fn framework_vocabulary_maps_to_roles_in_pipeline_order() {
        let i = parse_intent("business logic and workflow integrity, then coverage and severity");
        assert_eq!(i.roles_hint, vec![RoleId::Coder, RoleId::Reflector]);
    }

    #[test]
    fn directive_condenses_from_the_head() {
        let long = format!("MISSION: test\n{}", "x".repeat(5_000));
        let c = condense_directive(&long, 3_000);
        assert!(c.starts_with("MISSION: test"));
        assert!(c.contains("truncated"), "{c}");
        assert_eq!(condense_directive("short", 3_000), "short");
    }
}
