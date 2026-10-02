//! Passive, outside-in cloud storage exposure checks: S3, Azure Blob, GCS.
//!
//! No credentials of any kind - every request is exactly what an anonymous
//! visitor's browser would send. A 200 with a listing body means the bucket
//! itself is configured to let anyone enumerate its contents; nothing here
//! downloads an object, only (at most) a list of their names.

use crate::ctx::ToolCtx;
use crate::registry::{Tool, ToolOutput};
use serde_json::json;

pub struct CloudBucketCheck;

fn valid_bucket_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

impl Tool for CloudBucketCheck {
    fn name(&self) -> &'static str {
        "cloud_bucket_check"
    }

    fn description(&self) -> &'static str {
        "Passive, credential-free check of whether an in-scope S3/Azure Blob/GCS bucket \
         allows anonymous listing. Never downloads an object."
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "s3, azure, or gcs"},
                "name": {"type": "string", "description": "bucket/account name, must be in scope"},
                "container": {"type": "string", "description": "azure only: container name"}
            },
            "required": ["provider", "name"]
        })
    }

    fn execute<'a>(
        &'a self,
        input: serde_json::Value,
        ctx: &'a ToolCtx,
    ) -> crate::exec::BoxFutureTool<'a, anyhow::Result<ToolOutput>> {
        Box::pin(async move {
            let provider = super::str_field(&input, "provider")?.to_ascii_lowercase();
            let name = super::str_field(&input, "name")?;
            if !valid_bucket_name(&name) {
                anyhow::bail!("invalid bucket/account name");
            }
            // The declared scope names the asset itself (the bucket/account
            // name), the same way `amass` scope-checks a domain even though
            // the DNS resolution it drives lands on third-party
            // infrastructure: the operator is attesting ownership of the
            // name, not of AWS's/Microsoft's/Google's own servers.
            ctx.check_scope(&name)?;

            let (url, provider_label) = match provider.as_str() {
                "s3" => (format!("https://{name}.s3.amazonaws.com/"), "s3"),
                "gcs" => (
                    format!("https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=1"),
                    "gcs",
                ),
                "azure" => {
                    let container = super::str_field(&input, "container")
                        .map_err(|_| anyhow::anyhow!("azure requires `container`"))?;
                    if !valid_bucket_name(&container) {
                        anyhow::bail!("invalid container name");
                    }
                    (
                        format!(
                            "https://{name}.blob.core.windows.net/{container}?restype=container&comp=list"
                        ),
                        "azure",
                    )
                }
                other => anyhow::bail!("provider must be s3, azure, or gcs (got `{other}`)"),
            };

            let resp = match ctx.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => return Ok(ToolOutput::failed(format!("request to {url} failed: {e}"))),
            };
            let status = resp.status();
            let (text, truncated) = crate::fetch::read_capped_text(resp, 256 * 1024).await;

            let (public, verdict) = match provider_label {
                "s3" => {
                    if status.is_success() && text.contains("<ListBucketResult") {
                        (true, "public - anonymous listing succeeded")
                    } else if status.as_u16() == 403 {
                        (false, "private (403 AccessDenied)")
                    } else if status.as_u16() == 404 {
                        (false, "bucket does not exist or name is wrong (404)")
                    } else {
                        (false, "not publicly listable")
                    }
                }
                "gcs" => {
                    if status.is_success() && text.contains("\"items\"") || status.as_u16() == 200
                    {
                        (true, "public - anonymous listing succeeded")
                    } else if status.as_u16() == 403 {
                        (false, "private (403 Forbidden)")
                    } else if status.as_u16() == 404 {
                        (false, "bucket does not exist or name is wrong (404)")
                    } else {
                        (false, "not publicly listable")
                    }
                }
                _ => {
                    if status.is_success() && text.contains("<EnumerationResults") {
                        (true, "public - anonymous listing succeeded")
                    } else if status.as_u16() == 403 {
                        (false, "private (403 AuthenticationFailed/ResourceNotFound anon access denied)")
                    } else if status.as_u16() == 404 {
                        (false, "container/account does not exist or name is wrong (404)")
                    } else {
                        (false, "not publicly listable")
                    }
                }
            };

            let summary = format!(
                "cloud_bucket_check: {provider_label}/{name} - {verdict} (HTTP {status}){}",
                if truncated { " (response truncated)" } else { "" }
            );

            Ok(ToolOutput::ok(
                summary,
                json!({
                    "provider": provider_label,
                    "name": name,
                    "url": url,
                    "status": status.as_u16(),
                    "publicly_listable": public,
                    "verdict": verdict,
                    "truncated": truncated,
                }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let err = CloudBucketCheck
            .execute(json!({"provider": "s3", "name": "not-in-scope-bucket"}), &super::super::test_ctx())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("scope"), "got: {err}");
    }

    #[tokio::test]
    async fn azure_requires_a_container_name() {
        let ctx = super::super::test_ctx_scoped("example-account");
        let err = CloudBucketCheck
            .execute(json!({"provider": "azure", "name": "example-account"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("container"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_providers_and_bad_names() {
        assert!(valid_bucket_name("my-bucket.1_2"));
        assert!(!valid_bucket_name("my bucket; rm -rf"));
        assert!(!valid_bucket_name(""));
    }
}
