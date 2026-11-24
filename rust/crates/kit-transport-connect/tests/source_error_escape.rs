//! Hunt V5a: a hostile Connect server's error message must not reach a
//! terminal raw through the `kit-sync` `SourceError` a library embedder sees.
//!
//! The server below answers every request with a Connect `internal` error
//! whose message holds an OSC title sequence and a clear-screen CSI.

use std::io::{Read, Write};

use kit_core::protocol::{Transport, TransportError};
use kit_sync::{RemoteSource, SourceError};
use kit_transport_connect::ConnectTransport;

const HOSTILE_JSON: &str = r#"{"code":"internal","message":"\u001b]0;pwned\u0007\u001b[2J"}"#;

/// Answer every HTTP request with one Connect error, then close.
fn spawn_hostile_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            // Read the head, then the body named by Content-Length.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break None,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(i + 4);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
            let want = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < head_end + want {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HOSTILE_JSON}",
                HOSTILE_JSON.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn client(port: u16) -> ConnectTransport {
    ConnectTransport::connect_for_test(format!("http://127.0.0.1:{port}").parse().unwrap())
}

/// Control: the `Transport` trait path keeps `TransportError`, whose Display
/// escapes the message.
#[test]
fn transport_error_display_is_escaped() {
    let port = spawn_hostile_server();
    let error = client(port).list_refs("refs/heads/").unwrap_err();
    let text = error.to_string();
    assert!(matches!(error, TransportError::RemoteError(_)), "{text:?}");
    assert!(
        !text.contains('\u{1b}'),
        "TransportError leaked ESC: {text:?}"
    );
}

/// The `RemoteSource` path (what `kit clone`/`fetch` and kit-sync embedders
/// use) returns a `SourceError`. Its Display must not carry ESC either.
#[test]
fn source_error_from_hostile_connect_server_has_no_escape() {
    let port = spawn_hostile_server();
    let error = client(port)
        .with_source(|source: &dyn RemoteSource| source.list_refs("refs/heads/"))
        .expect("source prepared")
        .unwrap_err();
    let text = error.to_string();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "SourceError Display leaked control characters: {text:?} ({error:?})"
    );
}

/// Unit-level form of the same claim: the `From` impl keeps the raw text.
#[test]
fn source_error_from_transport_error_has_no_escape() {
    let error = SourceError::from(TransportError::RemoteError("\u{1b}[2J".into()));
    let text = error.to_string();
    assert!(
        !text.contains('\u{1b}'),
        "SourceError Display leaked ESC: {text:?}"
    );
}
