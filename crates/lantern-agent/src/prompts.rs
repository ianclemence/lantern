//! Prompt construction. All model-facing text originates here so the safety
//! language is impossible to lose between roles.

use crate::roles::{Role, RoleId};

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
pub fn system(role: &Role, target: &str, scope: &str, offensive: bool) -> String {
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

/// State document handed to the reflector (structured judgement client).
pub fn reflect_state(target: &str, findings: &str) -> String {
    format!("target: {target}\nfindings:\n{findings}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::{role, RoleId};

    #[test]
    fn system_prompt_carries_the_guards() {
        let r = role(RoleId::Researcher);
        let p = system(r, "example.com", "example.com, 93.184.216.0/24", false);
        assert!(p.contains("no shell"), "must state there is no shell");
        assert!(p.contains("SCOPE"));
        assert!(p.contains("DISABLED"), "passive role must say active testing is off");
        assert!(p.contains("findings"), "structured role gets the contract");
    }

    #[test]
    fn offensive_mode_is_explicit() {
        let p = system(role(RoleId::Pentester), "10.0.0.5", "10.0.0.0/24", true);
        assert!(p.contains("enabled by the operator"));
        assert!(!p.contains("DISABLED"));
    }

    #[test]
    fn non_structured_roles_have_no_contract() {
        let p = system(role(RoleId::Planner), "t", "t", false);
        assert!(!p.contains("FINAL OUTPUT CONTRACT"));
    }

    #[test]
    fn objectives_mention_the_target_and_plan() {
        let o = role_objective(RoleId::Researcher, "example.com", "1. recon", "- dns.example.com 768");
        assert!(o.contains("example.com"));
        assert!(o.contains("1. recon"));
        assert!(o.contains("prior observations"));
    }
}
