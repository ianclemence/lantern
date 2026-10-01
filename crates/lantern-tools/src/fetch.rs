//! Bounded reads for in-process network fetches.
//!
//! `exec::read_capped` bounds what a sandboxed *child process* can hand
//! back, on top of its own `RLIMIT_AS`. A tool that talks HTTP/DNS/WHOIS
//! directly from this process (`http_probe`, `waf_fingerprint`,
//! `subdomain_enum`, `whois`) has no such rlimit protecting it - it is this
//! process's own heap. Lantern's target is, by definition, something the
//! operator does not yet fully trust; a compromised or simply hostile target
//! (or a man-in-the-middle) serving a multi-gigabyte or infinite-chunked
//! response is a real DoS surface against the agent itself unless every
//! in-process fetch is bounded the same deliberate way a child process's
//! output already is. This is that bound for HTTP.

use reqwest::Response;

/// Read `resp`'s body up to `cap` bytes. Unlike `exec::read_capped` (which
/// keeps draining a child's pipe after the cap so the child never blocks),
/// this stops reading the moment the cap is hit: there is no child process
/// to unblock, and continuing to download a response we have already
/// decided not to use would just be handing a hostile target more of this
/// process's bandwidth and time for nothing.
pub async fn read_capped_body(mut resp: Response, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    let mut truncated = false;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap.saturating_sub(buf.len());
                if room == 0 {
                    truncated = true;
                    break;
                }
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    (buf, truncated)
}

/// `read_capped_body`, lossily decoded as UTF-8 text (the common case for an
/// HTML/JSON body we only need to pattern-match against).
pub async fn read_capped_text(resp: Response, cap: usize) -> (String, bool) {
    let (bytes, truncated) = read_capped_body(resp, cap).await;
    (String::from_utf8_lossy(&bytes).into_owned(), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stays_under_cap_against_a_response_larger_than_it() {
        // A local server is the only honest way to test "the client never
        // buffers more than the cap" without actually reaching a network
        // target - this spins up nothing but a loopback TCP listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let big = vec![b'a'; 2_000_000]; // 2 MB body
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
        let (data, truncated) = read_capped_body(resp, 1_024).await;
        assert!(truncated, "a 2 MB body against a 1 KB cap must report truncation");
        assert!(data.len() <= 1_024, "must never buffer past the cap: got {}", data.len());
    }

    #[tokio::test]
    async fn a_body_smaller_than_the_cap_is_not_marked_truncated() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 1024];
            let _ = sock.read(&mut req).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                .await;
            let _ = sock.shutdown().await;
        });

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
        let (text, truncated) = read_capped_text(resp, 1_024).await;
        assert!(!truncated);
        assert_eq!(text, "hello");
    }
}
