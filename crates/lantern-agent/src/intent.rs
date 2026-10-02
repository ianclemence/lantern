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

/// Which kind of engagement the prompt's vocabulary sounds like. Feeds
/// `prompts::system`'s addendum, not tool access or scope - it only changes
/// how the role is told to think and what taxonomy to report against, never
/// what it is allowed to touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngagementProfile {
    /// No strong signal either way: the generic framing applies.
    #[default]
    General,
    WebApp,
    Api,
    InternalAd,
    Cloud,
    NetworkInfra,
}

/// (keyword, profile) pairs. Independent of `ROLE_SIGNALS`: a role hint says
/// *who* should pay attention, a profile says *what kind of engagement this
/// is* so the system prompt can name the right taxonomy and the right
/// honesty boundary (what this toolset cannot actually check for that
/// profile) instead of the same generic framing for every engagement.
const PROFILE_SIGNALS: &[(&str, EngagementProfile)] = &[
    // Web application.
    ("web application", EngagementProfile::WebApp),
    ("web app", EngagementProfile::WebApp),
    ("xss", EngagementProfile::WebApp),
    ("csrf", EngagementProfile::WebApp),
    ("sql injection", EngagementProfile::WebApp),
    ("sqlmap", EngagementProfile::WebApp),
    ("login form", EngagementProfile::WebApp),
    ("session cookie", EngagementProfile::WebApp),
    ("idor", EngagementProfile::WebApp),
    ("file upload", EngagementProfile::WebApp),
    ("broken access control", EngagementProfile::WebApp),
    // API.
    ("api security", EngagementProfile::Api),
    ("rest api", EngagementProfile::Api),
    ("graphql", EngagementProfile::Api),
    ("openapi", EngagementProfile::Api),
    ("swagger", EngagementProfile::Api),
    ("jwt", EngagementProfile::Api),
    ("oauth", EngagementProfile::Api),
    ("saml", EngagementProfile::Api),
    ("mass assignment", EngagementProfile::Api),
    ("bola", EngagementProfile::Api),
    ("bfla", EngagementProfile::Api),
    // Internal / Active Directory.
    ("active directory", EngagementProfile::InternalAd),
    ("domain controller", EngagementProfile::InternalAd),
    ("kerberoast", EngagementProfile::InternalAd),
    ("ntlm", EngagementProfile::InternalAd),
    ("lateral movement", EngagementProfile::InternalAd),
    ("golden ticket", EngagementProfile::InternalAd),
    ("ldap", EngagementProfile::InternalAd),
    ("domain admin", EngagementProfile::InternalAd),
    ("internal network assessment", EngagementProfile::InternalAd),
    ("ad environment", EngagementProfile::InternalAd),
    // Cloud posture.
    ("s3 bucket", EngagementProfile::Cloud),
    ("iam policy", EngagementProfile::Cloud),
    ("iam role", EngagementProfile::Cloud),
    ("instance metadata", EngagementProfile::Cloud),
    ("metadata service", EngagementProfile::Cloud),
    ("cloud storage", EngagementProfile::Cloud),
    ("aws account", EngagementProfile::Cloud),
    ("azure ad", EngagementProfile::Cloud),
    ("gcp project", EngagementProfile::Cloud),
    ("cloud misconfiguration", EngagementProfile::Cloud),
    // Network infrastructure.
    ("network segmentation", EngagementProfile::NetworkInfra),
    ("firewall rule", EngagementProfile::NetworkInfra),
    ("port scan", EngagementProfile::NetworkInfra),
    ("internal network", EngagementProfile::NetworkInfra),
    ("vpn gateway", EngagementProfile::NetworkInfra),
];

/// The profile whose vocabulary matched the most keywords; `General` when
/// nothing scored above zero. Ties go to whichever profile is declared last
/// among the tied entries in `PROFILE_SIGNALS` (the order above, read
/// top to bottom) - deterministic, and covered by
/// `tie_breaks_to_the_later_declared_profile` below so a reader never has to
/// take that on faith.
fn detect_profile(lower: &str) -> EngagementProfile {
    let mut counts: Vec<(EngagementProfile, usize)> = Vec::new();
    for (kw, profile) in PROFILE_SIGNALS {
        if lower.contains(kw) {
            match counts.iter_mut().find(|(p, _)| p == profile) {
                Some((_, n)) => *n += 1,
                None => counts.push((*profile, 1)),
            }
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(p, _)| p)
        .unwrap_or(EngagementProfile::General)
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
    /// How many distinct `ROLE_SIGNALS` keywords matched each role in
    /// `roles_hint`, in the same order. A short instruction names a role
    /// once or not at all; a long, detailed framework repeats a role's
    /// vocabulary many times over (several named injection classes, several
    /// named auth checks, ...). `step_boosts` turns that repetition into an
    /// actual larger step budget, so a rich prompt gets more room to work
    /// without the operator having to compute and pass `--steps` by hand.
    pub role_weight: Vec<(RoleId, usize)>,
    /// What kind of engagement the prompt's vocabulary sounds like. Feeds
    /// `prompts::system`'s addendum; `General` (the default) changes nothing
    /// about the prompt a plain `lantern run` or a short instruction gets.
    pub engagement_profile: EngagementProfile,
}

/// A role's step budget is never raised by more than this many steps from
/// vocabulary alone, however much of the prompt points at it - it is a
/// convenience for a detailed prompt, not a way to buy an unbounded model
/// budget by repeating keywords. The operator's own `--steps` cap, when
/// given, still wins over everything computed here (see `resolve_offensive`
/// for the same "flag is final authority, prompt only narrows or - for cost
/// convenience only - nudges within a hard ceiling" shape).
pub const MAX_ROLE_STEP_BOOST: usize = 4;

impl Intent {
    /// Per-role step increase earned by how much of the prompt's vocabulary
    /// pointed at that role, each capped at `MAX_ROLE_STEP_BOOST`. One
    /// keyword match earns no boost (that is just "this role is relevant",
    /// already captured by `roles_hint`); each additional match earns one
    /// more step, up to the cap.
    pub fn step_boosts(&self) -> Vec<(RoleId, usize)> {
        self.role_weight
            .iter()
            .map(|(r, n)| (*r, n.saturating_sub(1).min(MAX_ROLE_STEP_BOOST)))
            .filter(|(_, boost)| *boost > 0)
            .collect()
    }
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
    // Directed verbs for techniques a large firm would expect covered.
    // Topic nouns for the same territory ("kerberoasting" as a coverage
    // item, say) still only earn a role hint below, the same way "privilege
    // escalation" already does - only an instruction to *do* it counts here.
    "kerberoast",
    "pass-the-hash",
    "pass the hash",
    "ntlm relay",
    "golden ticket",
    "silver ticket",
    "dcsync",
    "lateral movement",
    "dump credentials",
    "dump hashes",
    "bypass mfa",
    "bypass authentication",
    "take over the bucket",
    "assume the role",
    "pivot into",
    "escalate to domain admin",
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
    // API security (OWASP API Top 10 vocabulary).
    ("api security", RoleId::Pentester),
    ("rest api", RoleId::Pentester),
    ("graphql", RoleId::Pentester),
    ("openapi", RoleId::Pentester),
    ("swagger", RoleId::Pentester),
    ("jwt", RoleId::Pentester),
    ("oauth", RoleId::Pentester),
    ("saml", RoleId::Pentester),
    ("rate limit", RoleId::Pentester),
    ("mass assignment", RoleId::Pentester),
    // Cloud posture.
    ("s3 bucket", RoleId::Pentester),
    ("cloud storage", RoleId::Pentester),
    ("iam policy", RoleId::Pentester),
    ("iam role", RoleId::Pentester),
    ("metadata service", RoleId::Pentester),
    ("instance metadata", RoleId::Pentester),
    ("misconfigured bucket", RoleId::Pentester),
    ("cloud misconfiguration", RoleId::Researcher),
    // Internal/Active Directory - msfconsole already carries real SMB,
    // Kerberos and LDAP modules; this only improves how reliably the
    // pentester role gets pointed at them.
    ("active directory", RoleId::Pentester),
    ("kerberoast", RoleId::Pentester),
    ("ntlm", RoleId::Pentester),
    ("smb relay", RoleId::Pentester),
    ("domain admin", RoleId::Pentester),
    ("lateral movement", RoleId::Pentester),
    ("golden ticket", RoleId::Pentester),
    // Container / orchestration.
    ("container escape", RoleId::Pentester),
    ("kubernetes", RoleId::Pentester),
    ("k8s", RoleId::Pentester),
    ("docker socket", RoleId::Pentester),
    // Certificate-transparency subdomain mapping (subdomain_enum); "subdomain"
    // and "attack surface" themselves are already covered above.
    ("certificate transparency", RoleId::Researcher),
    // Supply chain.
    ("dependency", RoleId::Coder),
    ("supply chain", RoleId::Coder),
    ("sbom", RoleId::Coder),
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
        if lower.contains(kw) {
            if !intent.roles_hint.contains(role) {
                intent.roles_hint.push(*role);
            }
            match intent.role_weight.iter_mut().find(|(r, _)| r == role) {
                Some((_, n)) => *n += 1,
                None => intent.role_weight.push((*role, 1)),
            }
        }
    }
    // Pipeline order, so a hint never reorders the cast.
    intent.roles_hint.sort_by_key(|r| *r as usize);
    intent.role_weight.sort_by_key(|(r, _)| *r as usize);
    intent.engagement_profile = detect_profile(&lower);
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
    fn step_boost_scales_with_how_much_of_the_prompt_points_at_a_role() {
        // One mention of pentester territory: relevant, but not enough
        // repetition to earn extra budget over the role's own default.
        let one_hit = parse_intent("Check the login page.");
        assert!(one_hit.step_boosts().is_empty(), "{:?}", one_hit.step_boosts());

        // A framework that repeatedly names pentester-territory checks earns
        // a bounded boost instead of making the operator compute --steps.
        let many_hits = parse_intent(
            "Cover injection, xss, csrf, ssrf, idor, broken access, session \
             handling and upload validation in detail.",
        );
        let boosts = many_hits.step_boosts();
        let pentester_boost = boosts
            .iter()
            .find(|(r, _)| *r == RoleId::Pentester)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        assert!(pentester_boost > 0, "{boosts:?}");
        assert!(pentester_boost <= MAX_ROLE_STEP_BOOST, "{boosts:?}");
    }

    #[test]
    fn step_boost_is_capped_regardless_of_how_much_vocabulary_repeats() {
        let kitchen_sink = parse_intent(
            "injection exploit payload xss csrf ssrf idor bypass authorization \
             authentication session brute upload traversal broken access \
             privilege esc api security rest api graphql openapi swagger jwt \
             oauth saml rate limit mass assignment s3 bucket cloud storage \
             iam policy iam role metadata service instance metadata \
             active directory kerberoast ntlm smb relay domain admin \
             lateral movement golden ticket container escape kubernetes \
             k8s docker socket login",
        );
        let boost = kitchen_sink
            .step_boosts()
            .into_iter()
            .find(|(r, _)| *r == RoleId::Pentester)
            .map(|(_, n)| n)
            .unwrap_or(0);
        assert_eq!(boost, MAX_ROLE_STEP_BOOST, "must cap, not scale unbounded");
    }

    #[test]
    fn modern_technique_vocabulary_points_at_the_pentester_role() {
        for text in [
            "Test the GraphQL API for broken object level authorization",
            "Check IAM role trust policies and S3 bucket ACLs",
            "Attempt Kerberoasting against the domain controllers",
            "Look for container escape paths from the Kubernetes pods",
            "Audit the JWT validation and OAuth flow",
        ] {
            let i = parse_intent(text);
            assert!(
                i.roles_hint.contains(&RoleId::Pentester),
                "expected pentester hint for: {text}"
            );
        }
    }

    #[test]
    fn engagement_profile_defaults_to_general() {
        assert_eq!(parse_intent("check DNS").engagement_profile, EngagementProfile::General);
        assert_eq!(
            parse_intent("Coverage: authentication, privilege escalation, severity")
                .engagement_profile,
            EngagementProfile::General,
            "a single stray mention of adjacent territory should not flip the profile"
        );
    }

    #[test]
    fn engagement_profile_detects_each_category() {
        let cases = [
            ("Look for XSS and CSRF on the login form session cookies", EngagementProfile::WebApp),
            ("Test the GraphQL API, check JWT and OAuth handling", EngagementProfile::Api),
            (
                "Kerberoast the domain controllers and check for NTLM relay, active directory",
                EngagementProfile::InternalAd,
            ),
            ("Audit S3 bucket ACLs and IAM policy/IAM role trust", EngagementProfile::Cloud),
            (
                "Review network segmentation, firewall rules and port scan the internal network",
                EngagementProfile::NetworkInfra,
            ),
        ];
        for (text, want) in cases {
            assert_eq!(parse_intent(text).engagement_profile, want, "text: {text}");
        }
    }

    #[test]
    fn tie_breaks_to_the_later_declared_profile() {
        // "web app" (WebApp) and "api security" (Api) are declared one match
        // each here; Vec::max_by_key keeps the later-seen entry on a tie, and
        // Api is declared after WebApp in PROFILE_SIGNALS.
        let i = parse_intent("Assess this web app and its api security surface");
        assert_eq!(i.engagement_profile, EngagementProfile::Api);
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
