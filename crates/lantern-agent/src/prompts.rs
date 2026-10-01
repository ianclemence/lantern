//! Prompt construction. All model-facing text originates here so the safety
//! language is impossible to lose between roles.

use crate::intent::EngagementProfile;
use crate::roles::{Role, RoleId};

/// What to tell the model about the kind of engagement this looks like, on
/// top of the generic framing every role already gets. `General` (no strong
/// signal in the operator's words) adds nothing - a plain `lantern run` or a
/// short instruction gets exactly the prompt it always did.
///
/// Each addendum does two jobs: name the taxonomy findings should be
/// structured against (OWASP, ATT&CK, CIS - whatever the engagement's own
/// field uses), and say plainly what this toolset cannot actually check for
/// that profile. The second half matters at least as much as the first: a
/// model told "this is an API engagement" without also being told "you have
/// no GraphQL/OpenAPI/JWT-specific tooling" will confidently describe checks
/// it never ran. Keep both halves honest as new adapters land - an addendum
/// claiming a gap that a later P1/P2/P3 tool closes becomes a lie the day
/// that tool ships, so update it in the same change that adds the tool.
pub fn engagement_addendum(profile: EngagementProfile) -> &'static str {
    match profile {
        EngagementProfile::General => "",
        EngagementProfile::WebApp => {
            "\nENGAGEMENT PROFILE: web application.\n\
             Structure findings around the OWASP Top 10 (injection, broken access control,\n\
             authentication/session handling, security misconfiguration, vulnerable\n\
             components). Good evidence here is the exact request, parameter, header or\n\
             endpoint a tool actually flagged - never a category name on its own. This\n\
             toolset has no GraphQL-aware or OpenAPI-schema-aware scanner: http_probe,\n\
             nikto, sqlmap and nuclei cover conventional HTTP surface, not API semantics -\n\
             say so plainly rather than asserting coverage you did not run.\n"
        }
        EngagementProfile::Api => {
            "\nENGAGEMENT PROFILE: API.\n\
             Structure findings around the OWASP API Security Top 10 (broken object/function\n\
             level authorization, broken authentication, excessive data exposure, resource\n\
             consumption, mass assignment). This build has no OpenAPI/GraphQL schema parser,\n\
             no JWT claim/algorithm analysis and no structured OAuth/SAML flow tester yet -\n\
             http_probe and nuclei can still surface generic HTTP issues on an API endpoint,\n\
             but state clearly when a check needs tooling this build does not have instead of\n\
             describing a result you did not obtain.\n"
        }
        EngagementProfile::InternalAd => {
            "\nENGAGEMENT PROFILE: internal / Active Directory.\n\
             Structure findings around MITRE ATT&CK (initial access, discovery, credential\n\
             access, lateral movement, privilege escalation). host_msfconsole carries real\n\
             SMB/Kerberos/LDAP auxiliary modules - use its scanner/gather modules for this\n\
             territory rather than defaulting to the web tools. There is no BloodHound-style\n\
             relationship graph and no standalone Kerberoasting/AS-REP-roasting harness in\n\
             this build: a single module run is one data point, not a domain-compromise path -\n\
             never claim a path the evidence does not actually show.\n"
        }
        EngagementProfile::Cloud => {
            "\nENGAGEMENT PROFILE: cloud posture.\n\
             Structure findings around CIS benchmark categories (identity, storage, network,\n\
             logging). This build has no cloud-provider API client, no IAM policy evaluator\n\
             and no bucket enumerator beyond what subdomain_enum/http_probe/dns_lookup can see\n\
             from the outside - a misconfigured bucket's public listing, an exposed endpoint,\n\
             nothing that requires reading account-internal configuration. Say when a check is\n\
             out of reach rather than inferring posture you have no evidence for.\n"
        }
        EngagementProfile::NetworkInfra => {
            "\nENGAGEMENT PROFILE: network infrastructure.\n\
             Structure findings around exposed services, weak protocols and segmentation\n\
             gaps. host_nmap/port_scan/host_nikto are the primary evidence sources here;\n\
             name the exact port, service and version a tool actually reported rather than a\n\
             general risk statement.\n"
        }
    }
}

/// Contract the structured roles must satisfy when they stop calling tools.
pub const FINDINGS_CONTRACT: &str = r#"FINAL OUTPUT CONTRACT
When you are done, reply with prose followed by a single fenced JSON object:

```json
{"findings": [
  {
    "title": "short imperative-free summary",
    "severity": "critical|high|medium|low|info",
    "asset": "host or url the evidence belongs to",
    "port": 443,
    "proto": "tcp",
    "description": "what is wrong and why it matters",
    "evidence": "the exact observation that proves it (tool, output fragment)",
    "remediation": "concrete fix",
    "confidence": 0.0
  }
]}
```

Rules: only report what a tool actually returned; `evidence` must quote real
output; omit a finding rather than speculate; confidence is your honest
probability that an operator would reproduce it. If you found nothing worth
reporting, emit `{"findings": []}`."#;

/// System prompt for a role.
pub fn system(
    role: &Role,
    target: &str,
    scope: &str,
    offensive: bool,
    profile: EngagementProfile,
) -> String {
    let mut s = String::new();
    s.push_str("You are Lantern, a defensive security assessment agent running on a\n");
    s.push_str("small single-board computer. You are audited: every tool call is logged\n");
    s.push_str("to SQLite and to a trace file.\n\n");
    s.push_str(&format!("ROLE: {}\nMISSION: {}\n", role.id, role.mission));
    s.push_str(&format!("\nTARGET: {target}\nSCOPE: {scope}\n"));
    s.push_str(&format!(
        "ACTIVE TESTING: {}\n",
        if offensive {
            "enabled by the operator (--offensive)"
        } else {
            "DISABLED - reconnaissance and defensive verification only"
        }
    ));
    s.push_str(engagement_addendum(profile));

    s.push_str(
        "\nHARD RULES\n\
         1. Never ask to run a shell, and never write a command string: tools take\n\
           structured arguments only. There is no shell in this system.\n\
         2. Anything outside SCOPE is refused automatically. Do not retry it, do not\n\
           suggest workarounds, do not ask for adjacent ranges.\n\
         3. Stay on the tools listed as your focus. Prefer the fewest calls that\n\
           answer your question.\n\
         4. You cannot execute code, upload payloads, or exploit a service. Your job\n\
           is to observe, verify and explain - an operator acts on your report.\n\
         5. Never request or echo credentials, API keys or session tokens.\n\
         6. Stop as soon as you can answer the objective. Budget is finite.\n",
    );

    if !role.focus.is_empty() {
        s.push_str("\nYOUR TOOLS: ");
        s.push_str(&role.focus.join(", "));
        s.push('\n');
    }

    if role.emits_findings {
        s.push('\n');
        s.push_str(FINDINGS_CONTRACT);
    }
    s
}

/// System prompt for a delegated sub-task (`delegate_task`). Deliberately
/// not `system()` with a flag: a delegated sub-task is not a role - it has
/// no findings contract to emit, no mission of its own beyond the objective
/// it was given, and its tool list is whatever the parent passed, not a
/// `Role`'s static focus. What it must still carry, word for word, are the
/// hard rules and the one fact that keeps it from becoming a second trust
/// boundary: it cannot delegate again.
pub fn delegated_system(
    parent: RoleId,
    target: &str,
    scope: &str,
    offensive: bool,
    tools: &[&str],
) -> String {
    let mut s = String::new();
    s.push_str("You are Lantern, a defensive security assessment agent running on a\n");
    s.push_str("small single-board computer. You are audited: every tool call is logged\n");
    s.push_str("to SQLite and to a trace file.\n\n");
    s.push_str(&format!(
        "You are a bounded sub-task delegated by the {parent} role. You share its\n\
         scope and its --offensive grant exactly; you cannot exceed either.\n"
    ));
    s.push_str(&format!("\nTARGET: {target}\nSCOPE: {scope}\n"));
    s.push_str(&format!(
        "ACTIVE TESTING: {}\n",
        if offensive {
            "enabled by the operator (--offensive)"
        } else {
            "DISABLED - reconnaissance and defensive verification only"
        }
    ));
    s.push_str(
        "\nHARD RULES\n\
         1. Never ask to run a shell, and never write a command string: tools take\n\
           structured arguments only. There is no shell in this system.\n\
         2. Anything outside SCOPE is refused automatically. Do not retry it, do not\n\
           suggest workarounds, do not ask for adjacent ranges.\n\
         3. Stay on the tools listed below. Prefer the fewest calls that answer\n\
           the objective.\n\
         4. You cannot execute code, upload payloads, or exploit a service beyond\n\
           what your tools themselves do.\n\
         5. Never request or echo credentials, API keys or session tokens.\n\
         6. Stop as soon as you can answer the objective. Your step budget is small\n\
           and will not be extended.\n\
         7. `delegate_task` is not available to you. You cannot delegate again -\n\
           answer the objective yourself with the tools you were given.\n",
    );
    if !tools.is_empty() {
        s.push_str("\nYOUR TOOLS: ");
        s.push_str(&tools.join(", "));
        s.push('\n');
    }
    s.push_str(
        "\nReport findings in plain prose, not the findings-block JSON contract - you\n\
         are a sub-task, not a role; your parent folds your answer back into its own\n\
         work and will emit findings itself if any apply.\n",
    );
    s
}

/// Objective handed to the orchestrator.
pub fn plan_objective(target: &str, scope: &str) -> String {
    format!(
        "Write the assessment plan for target {target} within scope {scope}.\n\
         Output 3-6 numbered steps, each one sentence, naming the kind of evidence\n\
         you expect (DNS records, TLS certificate, open ports, exposed paths, ...\n\
         ). No preamble, no JSON."
    )
}

/// Objective handed to every downstream role.
pub fn role_objective(role: RoleId, target: &str, plan: &str, memory: &str) -> String {
    let mut s = format!("Overall plan for this assessment:\n{plan}\n");
    s.push_str(&format!("\nYour assignment as {role}: {}\n", crate::roles::role(role).mission));
    s.push_str(&format!("\nWork on target: {target}\n"));
    if !memory.is_empty() {
        s.push_str("\nRelevant prior observations (from earlier roles):\n");
        s.push_str(memory);
        s.push('\n');
    }
    s.push_str(
        "\nUse your tools to gather fresh evidence, then report. Finish with your\n\
         findings block if your role emits findings.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::{role, RoleId};

    #[test]
    fn system_prompt_carries_the_guards() {
        let r = role(RoleId::Researcher);
        let p = system(r, "example.com", "example.com, 93.184.216.0/24", false, EngagementProfile::General);
        assert!(p.contains("no shell"), "must state there is no shell");
        assert!(p.contains("SCOPE"));
        assert!(p.contains("DISABLED"), "passive role must say active testing is off");
        assert!(p.contains("findings"), "structured role gets the contract");
    }

    #[test]
    fn offensive_mode_is_explicit() {
        let p = system(role(RoleId::Pentester), "10.0.0.5", "10.0.0.0/24", true, EngagementProfile::General);
        assert!(p.contains("enabled by the operator"));
        assert!(!p.contains("DISABLED"));
    }

    #[test]
    fn non_structured_roles_have_no_contract() {
        let p = system(role(RoleId::Planner), "t", "t", false, EngagementProfile::General);
        assert!(!p.contains("FINAL OUTPUT CONTRACT"));
    }

    #[test]
    fn general_profile_changes_nothing_about_the_prompt() {
        // Zero-regression guarantee for every caller that never detected a
        // profile (`lantern run`, a short instruction): byte-for-byte the
        // same prompt as before this addendum existed.
        assert_eq!(engagement_addendum(EngagementProfile::General), "");
        let p = system(role(RoleId::Researcher), "t", "t", false, EngagementProfile::General);
        assert!(!p.contains("ENGAGEMENT PROFILE"));
    }

    #[test]
    fn a_detected_profile_adds_its_addendum_and_names_a_real_gap() {
        let p = system(role(RoleId::Pentester), "t", "t", false, EngagementProfile::InternalAd);
        assert!(p.contains("ENGAGEMENT PROFILE: internal / Active Directory"));
        assert!(p.contains("ATT&CK"));
        // The honesty half: a claim this build cannot back up must be named,
        // not just the taxonomy to report findings against.
        assert!(p.contains("no BloodHound"));
    }

    #[test]
    fn every_profile_addendum_is_internally_consistent() {
        use crate::intent::EngagementProfile::*;
        for profile in [General, WebApp, Api, InternalAd, Cloud, NetworkInfra] {
            let a = engagement_addendum(profile);
            if profile == General {
                assert!(a.is_empty());
            } else {
                assert!(a.starts_with("\nENGAGEMENT PROFILE:"), "{profile:?}: {a}");
                assert!(a.ends_with('\n'), "{profile:?} addendum should end cleanly");
            }
        }
    }

    #[test]
    fn objectives_mention_the_target_and_plan() {
        let o = role_objective(RoleId::Researcher, "example.com", "1. recon", "- dns.example.com 768");
        assert!(o.contains("example.com"));
        assert!(o.contains("1. recon"));
        assert!(o.contains("prior observations"));
    }
}
