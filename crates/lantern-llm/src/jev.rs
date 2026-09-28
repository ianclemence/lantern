//! Typed structured-judgement client.
//!
//! Instead of asking the generation model to grade its own work (slow, costly,
//! inconsistently formatted), Lantern sends a piece of state plus a set of typed
//! questions and gets back choices/scores/truth values with confidence. Used for
//! task routing, severity triage and the reflector's continue/stop decision.

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub enum Question {
    /// Pick exactly one option from `criteria`.
    Choice {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
    /// Rate `state` against an ordered rubric; the returned score is the index.
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
    /// Is this statement true? Returns 0.0 (false) ..= 1.0 (true).
    Noul { instructions: String },
}

impl Question {
    pub fn choice<'a>(
        instructions: impl Into<String>,
        criteria: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        Question::Choice {
            instructions: instructions.into(),
            criteria: criteria
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    pub fn score(instructions: impl Into<String>, criteria: &[&str]) -> Self {
        Question::Score {
            instructions: instructions.into(),
            criteria: criteria.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn noul(instructions: impl Into<String>) -> Self {
        Question::Noul {
            instructions: instructions.into(),
        }
    }

    fn wire(&self) -> serde_json::Value {
        match self {
            Question::Choice {
                instructions,
                criteria,
            } => serde_json::json!({
                "type": "choice",
                "instructions": instructions,
                "criteria": criteria,
            }),
            Question::Score {
                instructions,
                criteria,
            } => serde_json::json!({
                "type": "score",
                "instructions": instructions,
                "criteria": criteria,
            }),
            Question::Noul { instructions } => serde_json::json!({
                "type": "noul",
                "instructions": instructions,
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    Choice {
        choice: String,
        #[serde(default)]
        confidence: f64,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
    },
    Score {
        score: f64,
        #[serde(default)]
        confidence: f64,
        #[serde(default)]
        legend: BTreeMap<String, String>,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
    },
    Noul {
        noul: f64,
    },
}

impl Answer {
    pub fn confidence(&self) -> f64 {
        match self {
            Answer::Choice { confidence, .. } => *confidence,
            Answer::Score { confidence, .. } => *confidence,
            Answer::Noul { noul } => *noul,
        }
    }

    pub fn as_choice(&self) -> Option<&str> {
        match self {
            Answer::Choice { choice, .. } => Some(choice),
            _ => None,
        }
    }

    pub fn as_score(&self) -> Option<f64> {
        match self {
            Answer::Score { score, .. } => Some(*score),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Answer::Noul { noul } => Some(*noul >= 0.5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JevResponse {
    pub model: String,
    pub answers: BTreeMap<String, Answer>,
    #[serde(default)]
    pub usage: Option<serde_json::Value>,
}

impl JevResponse {
    pub fn get(&self, key: &str) -> Option<&Answer> {
        self.answers.get(key)
    }
    /// Mean confidence across answers that expose one.
    pub fn mean_confidence(&self) -> f64 {
        let vals: Vec<f64> = self.answers.values().map(|a| a.confidence()).collect();
        if vals.is_empty() {
            return 0.0;
        }
        vals.iter().sum::<f64>() / vals.len() as f64
    }
}

pub struct JevClient {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    api_key: String,
}

impl JevClient {
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .connect_timeout(Duration::from_secs(10))
                .user_agent(concat!("lantern/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("building jev client")?,
            endpoint: endpoint.into(),
            model: model.into(),
            api_key: api_key.into(),
        })
    }

    pub fn has_key(&self) -> bool {
        !self.api_key.is_empty()
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Evaluate every question against `state` in a single request.
    pub async fn evaluate(
        &self,
        state: &str,
        questions: BTreeMap<String, Question>,
    ) -> anyhow::Result<JevResponse> {
        if questions.is_empty() {
            bail!("no questions supplied");
        }
        let qs: BTreeMap<String, serde_json::Value> =
            questions.into_iter().map(|(k, q)| (k, q.wire())).collect();
        let body = serde_json::json!({
            "state": state,
            "model": self.model,
            "questions": qs,
        });

        let resp = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("POST jev")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = text.chars().take(300).collect();
            bail!("jev http {status}: {snippet}");
        }
        serde_json::from_str(&text).context("decoding jev response")
    }

    /// Convenience: single Noul truth check.
    pub async fn ask_bool(&self, state: &str, question: &str) -> anyhow::Result<(bool, f64)> {
        let mut qs = BTreeMap::new();
        qs.insert("q".to_string(), Question::noul(question));
        let resp = self.evaluate(state, qs).await?;
        let ans = resp.get("q").map(|a| (a.as_bool().unwrap_or(false), a.confidence()));
        ans.ok_or_else(|| anyhow::anyhow!("missing answer"))
    }

    /// Convenience: single Choice over a fixed set of labels.
    pub async fn ask_choice(
        &self,
        state: &str,
        question: &str,
        options: &[(&str, &str)],
    ) -> anyhow::Result<(String, f64)> {
        let mut qs = BTreeMap::new();
        qs.insert(
            "q".to_string(),
            Question::choice(question, options.iter().copied()),
        );
        let resp = self.evaluate(state, qs).await?;
        let ans = resp
            .get("q")
            .and_then(|a| a.as_choice().map(|c| (c.to_string(), a.confidence())));
        ans.ok_or_else(|| anyhow::anyhow!("missing answer"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_forms() {
        assert_eq!(Question::noul("x").wire()["type"], "noul");
        let c = Question::choice("pick", [("a", "A"), ("b", "B")]).wire();
        assert_eq!(c["type"], "choice");
        assert_eq!(c["criteria"]["a"], "A");
        let s = Question::score("rate", &["low", "high"]).wire();
        assert_eq!(s["type"], "score");
        assert_eq!(s["criteria"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn parses_real_response_shape() {
        let raw = r#"{
          "model": "jev-1.13.0",
          "answers": {
            "severity": {"type":"choice","choice":"low","confidence":0.89,
              "probabilities":{"high":0.05,"medium":0.02,"low":0.93}},
            "exposure": {"type":"score","score":1.0,"confidence":1.0,
              "legend":{"0":"none","1":"some"},"probabilities":{"0":0.0,"1":1.0}},
            "needs_followup": {"type":"noul","noul":0.47}
          },
          "usage": {"input_tokens": 425, "output_tokens": 74}
        }"#;
        let r: JevResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(r.get("severity").unwrap().as_choice(), Some("low"));
        assert!((r.get("severity").unwrap().confidence() - 0.89).abs() < 1e-9);
        assert_eq!(r.get("exposure").unwrap().as_score(), Some(1.0));
        assert_eq!(r.get("needs_followup").unwrap().as_bool(), Some(false)); // 0.47 < 0.5
        // (0.89 + 1.00 + 0.47) / 3
        assert!((r.mean_confidence() - 0.786_666).abs() < 1e-3);
    }

    #[test]
    fn integer_scores_deserialize() {
        let raw = r#"{"model":"m","answers":{"s":{"type":"score","score":2,"confidence":1}}}"#;
        let r: JevResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(r.get("s").unwrap().as_score(), Some(2.0));
    }
}
