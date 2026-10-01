//! Bounded reads for model-provider HTTP responses.
//!
//! The same shape as `lantern_tools::fetch` (not reused directly - these two
//! crates sit on opposite sides of the dependency graph: `lantern-tools`
//! depends on `lantern-core`, which `lantern-llm` also depends on, but
//! `lantern-llm` cannot depend on `lantern-tools` without a cycle). A
//! model-provider endpoint is operator-configured and generally trusted far
//! more than a pentest target is, but "trusted" is not the same as "cannot
//! return something huge" - a misbehaving provider, a `custom` endpoint
//! pointed at the wrong place, or a proxy in between can still serve an
//! oversized or endlessly-chunked response, and none of this process's
//! model-client code runs under any rlimit. Bounding it here costs little
//! and closes the same class of gap `lantern-tools::fetch` closes on the
//! target-facing side.

use reqwest::Response;

/// Read `resp`'s body up to `cap` bytes, lossily decoded as UTF-8. Stops the
/// instant the cap is hit rather than continuing to buffer a response
/// already decided against.
pub async fn read_capped_text(mut resp: Response, cap: usize) -> String {
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap.saturating_sub(buf.len());
                if room == 0 {
                    break;
                }
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stays_under_cap_against_a_response_larger_than_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let big = vec![b'a'; 2_000_000];
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = sock.read(&mut req).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                big.len()
            );
            let _ = sock.write_all(header.as_bytes()).await;
            let _ = sock.write_all(&big).await;
            let _ = sock.shutdown().await;
        });

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
        let text = read_capped_text(resp, 1_024).await;
        assert!(text.len() <= 1_024, "must never buffer past the cap: got {}", text.len());
    }
}
