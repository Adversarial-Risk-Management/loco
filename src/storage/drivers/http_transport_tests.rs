//! The HTTP-backed drivers reach the network.
//!
//! opendal 0.58 ships no HTTP client unless a transport is installed, and loco
//! enables opendal without its default features, so unless the `storage_*`
//! features turn the transport back on, every request fails with "default HTTP
//! transport is not installed" before anything is sent. These tests point a
//! real driver at a local endpoint and check the request arrives, which no
//! in-memory or filesystem test can show.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::aws;

/// Read one HTTP/1.1 request (head, then a `content-length` body) so the
/// response never races the client's upload.
async fn read_request(socket: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let body_len = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + body_len {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// A local endpoint that answers every request `200 OK` and counts them.
async fn mock_endpoint() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                if read_request(&mut socket).await.is_ok() {
                    seen.fetch_add(1, Ordering::SeqCst);
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                }
            });
        }
    });
    (format!("http://{addr}"), requests)
}

#[tokio::test]
async fn s3_driver_uploads_over_http() {
    let (endpoint, requests) = mock_endpoint().await;
    let store = aws::with_credentials_and_endpoint(
        "loco-transport-probe",
        "us-east-1",
        &endpoint,
        aws::Credential {
            key_id: "key".to_string(),
            secret_key: "secret".to_string(),
            token: None,
        },
    )
    .expect("build s3 driver");

    store
        .upload(Path::new("probe.txt"), &Bytes::from_static(b"probe"))
        .await
        .expect("upload reaches the endpoint");

    assert!(
        requests.load(Ordering::SeqCst) >= 1,
        "the upload must be sent over HTTP"
    );
}
