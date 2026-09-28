//! Findings extraction: the only path from model prose into the `findings`
//! table. Everything is validated here - a malformed block yields nothing
//! rather than a half-recorded finding.

use lantern_core::storage::models::NewFinding;
use serde_json::Value;

/// Normalise a severity word into the stored vocabulary.
pub fn severity_norm(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase();
    for (needle, norm) in [
        ("crit", "critical"),
        ("high", "high"),
        ("med", "medium"),
        ("low", "low"),
        ("info", "info"),
    ] {
        if s.starts_with(needle) {
            return norm.to_string();
        }
    }
    "info".to_string()
}

fn as_str(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn to_finding(v: &Value) -> Option<NewFinding> {
    let title = as_str(v.get("title"))?;
    let asset = as_str(v.get("asset")).unwrap_or_default();
    let description = as_str(v.get("description")).unwrap_or_default();
    if title.is_empty() && description.is_empty() {
        return None;
    }
    let port = v.get("port").and_then(|p| p.as_i64()).or_else(|| {
        v.get("port")
            .and_then(|p| p.as_str())
            .and_then(|p| p.trim().parse().ok())
    });
    Some(NewFinding {
        title: lantern_core::text_clip(&title, 60),
        severity: severity_norm(as_str(v.get("severity")).as_deref().unwrap_or("info")),
        asset,
        port,
        proto: as_str(v.get("proto")),
        description: lantern_core::text_clip(&description, 400),
        evidence: as_str(v.get("evidence")).map(|e| lantern_core::text_clip(&e, 600)),
        remediation: as_str(v.get("remediation")).map(|r| lantern_core::text_clip(&r, 400)),
        confidence: v
            .get("confidence")
            .and_then(|c| c.as_f64())
            .map(|c| c.clamp(0.0, 1.0)),
        judge: None,
    })
}

/// Find the JSON object that encloses the first occurrence of `needle`.
fn enclosing_object<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let idx = text.find(needle)?;
    let bytes = text.as_bytes();

    // Walk backwards to the `{` that opens the enclosing object.
    let mut depth = 0usize;
    let mut start = None;
    let mut i = idx;
    while i > 0 {
        i -= 1;
        if !text.is_char_boundary(i) {
            continue;
        }
        match bytes[i] {
            b'}' => depth += 1,
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let start = start?;

    // Walk forwards to its matching `}`.
    let mut depth = 0usize;
    for (off, ch) in text[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..start + off + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_block(block: &str) -> Vec<NewFinding> {
    let Ok(v) = serde_json::from_str::<Value>(block) else {
        return Vec::new();
    };
    let items = match &v {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o
            .get("findings")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    items.iter().filter_map(to_finding).collect()
}

/// Pull findings out of a role's final text. Never panics, never invents.
pub fn extract(text: &str) -> Vec<NewFinding> {
    if !text.contains("finding") && !text.contains("Finding") {
        return Vec::new();
    }

    // 1. Balanced scan of the whole message (works for fenced or bare JSON).
    if let Some(v) = lantern_llm::util::extract_json::<Value>(text) {
        let found = match &v {
            Value::Array(a) if !a.is_empty() => a.iter().filter_map(to_finding).collect(),
            Value::Object(_) if v.get("findings").is_some() => parse_block(&v.to_string()),
            _ => Vec::new(),
        };
        if !found.is_empty() {
            return found;
        }
    }

    // 2. The object may sit after prose: anchor on the `findings` key.
    for needle in ["\"findings\"", "'findings'"] {
        if let Some(block) = enclosing_object(text, needle) {
            let found = parse_block(block);
            if !found.is_empty() {
                return found;
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Here is what I found.

```json
{"findings": [
  {"title": "Directory listing enabled", "severity": "Medium", "asset": "example.com",
   "port": 443, "proto": "tcp", "description": "The /images path lists files.",
   "evidence": "GET /images -> 200 with index markup", "remediation": "Disable autoindex.",
   "confidence": 0.82},
  {"title": "", "description": "", "severity": "low"}
]}
```
"#;

    #[test]
    fn extracts_a_fenced_block() {
        let out = extract(SAMPLE);
        assert_eq!(out.len(), 1, "the empty finding must be dropped");
        assert_eq!(out[0].title, "Directory listing enabled");
        assert_eq!(out[0].severity, "medium", "severity is normalised");
        assert_eq!(out[0].port, Some(443));
        assert_eq!(out[0].confidence, Some(0.82));
        assert!(out[0].evidence.as_deref().unwrap().contains("GET /images"));
    }

    #[test]
    fn extracts_json_that_follows_prose() {
        let text = "I finished the pass. No shell was involved.\n\
                    Final answer: {\"findings\":[{\"title\":\"Missing HSTS\",\"severity\":\"low\",\
                    \"asset\":\"example.com\",\"description\":\"No Strict-Transport-Security header\"}]}";
        let out = extract(text);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, "Missing HSTS");
    }

    #[test]
    fn ignores_text_without_findings() {
        assert!(extract("Everything looks fine, no issues.").is_empty());
        assert!(extract("{\"findings\": []}").is_empty());
        assert!(extract("").is_empty());
    }

    #[test]
    fn clamps_and_defaults() {
        let out = extract(
            r#"{"findings":[{"title":"T","description":"D","severity":"urgent","confidence":3.1}]}"#,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, "info", "unknown severity becomes info");
        assert_eq!(out[0].confidence, Some(1.0), "confidence is clamped");
        assert!(out[0].judge.is_none());
    }

    #[test]
    fn string_ports_are_accepted() {
        let out = extract(r#"{"findings":[{"title":"T","description":"D","port":"8080"}]}"#);
        assert_eq!(out[0].port, Some(8080));
    }
}
