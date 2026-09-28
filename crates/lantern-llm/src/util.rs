//! Small parsing helpers shared by the model clients.

/// Extract the first balanced JSON object/array from a model response.
///
/// Models wrap JSON in prose, markdown fences, or both. Anything unparseable
/// returns `None` — callers decide whether that is fatal.
pub fn extract_json<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    let bytes = text.as_bytes();
    let mut best: Option<&str> = None;

    for (i, b) in bytes.iter().enumerate() {
        if *b != b'{' && *b != b'[' {
            continue;
        }
        let open = *b;
        let close = if open == b'{' { b'}' } else { b']' };
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc = false;
        for (j, c) in bytes[i..].iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match *c {
                b'\\' if in_str => esc = true,
                b'"' => in_str = !in_str,
                _ if !in_str => {
                    if *c == open {
                        depth += 1;
                    } else if *c == close {
                        depth -= 1;
                        if depth == 0 {
                            best = std::str::from_utf8(&bytes[i..i + j + 1]).ok();
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        if best.is_some() {
            break;
        }
    }

    let candidate = best?;
    serde_json::from_str(candidate).ok()
}

/// Strip markdown code fences from a response body.
pub fn strip_fences(text: &str) -> String {
    let t = text.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t.to_string();
    };
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix("json")
        .or_else(|| rest.strip_prefix("JSON"))
        .unwrap_or(rest);
    let rest = rest.trim_start();
    let rest = rest.strip_suffix("```").unwrap_or(rest);
    rest.trim().to_string()
}

/// Fold a model response into a bare text answer (drop fences, trim).
pub fn plain_text(text: &str) -> String {
    strip_fences(text).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Debug)]
    struct Probe {
        host: String,
        port: u16,
    }

    #[test]
    fn extracts_bare_json() {
        let p: Probe = extract_json(r#"{"host":"a","port":80}"#).unwrap();
        assert_eq!(p.port, 80);
    }

    #[test]
    fn extracts_from_prose_and_fences() {
        let text = "Sure! Here is the result:\n```json\n{\"host\":\"b\",\"port\":443}\n```\nHope that helps.";
        let p: Probe = extract_json(text).unwrap();
        assert_eq!(p.host, "b");
    }

    #[test]
    fn handles_nested_and_quoted_braces() {
        let text = r#"prefix {"host":"}not-json{","port":1} suffix"#;
        let p: Probe = extract_json(text).unwrap();
        assert_eq!(p.port, 1);
    }

    #[test]
    fn arrays_and_garbage() {
        let v: Vec<u32> = extract_json("values: [1, 2, 3]").unwrap();
        assert_eq!(v, vec![1, 2, 3]);
        assert!(extract_json::<Probe>("no json here").is_none());
        assert!(extract_json::<Probe>("{broken").is_none());
    }

    #[test]
    fn fence_stripping() {
        assert_eq!(strip_fences("```json\n{}\n```"), "{}");
        assert_eq!(plain_text("  hi  "), "hi");
    }
}
