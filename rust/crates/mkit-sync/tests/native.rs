//! Pack-location fetches over the native HTTP channel, against a one-shot
//! loopback HTTP stub.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_sync::NativeHttp;

/// Serve exactly one plain HTTP response and retain its request headers.
fn location_response(
    response: &'static [u8],
    body_delay: std::time::Duration,
) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/pack?signature=test",
        listener.local_addr().unwrap()
    );
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        std::thread::sleep(body_delay);
        // A deadline may have already closed the receiving connection.
        let _ = stream.write_all(response);
        String::from_utf8(request).unwrap()
    });
    (url, thread)
}

#[test]
fn pack_location_fetch_never_sends_rpc_defaults_or_credentials() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::ZERO,
    );
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", "Bearer secret".parse().unwrap());
    headers.insert("cookie", "session=secret".parse().unwrap());
    headers.insert("x-kit-signature", "secret".parse().unwrap());
    headers.insert("x-host-default", "secret".parse().unwrap());
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_default_headers(headers);
    assert!(transport.supports_pack_locations());
    assert_eq!(
        transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .unwrap(),
        b"pack"
    );
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /pack?signature=test http/1.1\r\n"));
    assert!(request.contains("accept-encoding: identity\r\n"));
    assert!(!request.contains("secret"));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("cookie:"));
    assert!(!request.contains("x-kit-"));
    assert!(!request.contains("x-host-default:"));
}

#[test]
fn pack_location_fetch_refuses_redirects_encoding_and_oversize_bodies() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    for response in [
        &b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack"[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\npacks"[..],
    ] {
        let (url, server) = location_response(response, std::time::Duration::ZERO);
        assert!(
            transport
                .block_on(transport.fetch_pack_location(&url, 4, None))
                .is_err()
        );
        server.join().unwrap();
    }
}

#[test]
fn pack_location_fetch_enforces_its_own_scheme_and_transfer_deadline() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .allow_insecure_http(true)
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
        .with_metadata_timeout(std::time::Duration::from_secs(5))
        .with_transfer_timeout(std::time::Duration::from_millis(200));
    for url in [
        "http://example.invalid/pack",
        "ftp://127.0.0.1/pack",
        "https://user:secret@example.invalid/pack",
        "/relative/pack",
    ] {
        assert!(
            transport
                .block_on(transport.fetch_pack_location(url, 4, None))
                .is_err(),
            "{url}"
        );
    }
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(400),
    );
    let error = transport
        .block_on(transport.fetch_pack_location(&url, 4, None))
        .unwrap_err();
    assert!(error.contains("deadline"), "{error}");
    server.join().unwrap();
}

#[test]
fn pack_location_fetch_requires_explicit_test_opt_in_for_loopback_http() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/pack", listener.local_addr().unwrap());
    let transport = NativeHttp::new().unwrap().allow_insecure_http(true);
    assert!(!transport.allows_test_pack_location_http());
    let error = transport
        .block_on(transport.fetch_pack_location(&url, 4, None))
        .unwrap_err();
    assert!(error.contains("HTTPS"), "{error}");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let transport = transport
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    assert!(transport.allows_test_pack_location_http());
    let transport = transport.with_test_pack_location_http(false);
    assert!(!transport.allows_test_pack_location_http());
}

#[test]
fn pack_location_rejects_loopback_before_connecting() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(25));
    let url = format!("https://{}/pack", listener.local_addr().unwrap());
    assert!(
        transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .is_err()
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn pack_location_fetch_honors_shorter_local_budget() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true);
    let (url, server) = location_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npack",
        std::time::Duration::from_millis(300),
    );
    let start = std::time::Instant::now();
    let result = transport.block_on(transport.fetch_pack_location(
        &url,
        4,
        Some(std::time::Duration::from_millis(40)),
    ));
    assert!(start.elapsed() < std::time::Duration::from_millis(200));
    assert!(result.is_err());
    server.join().unwrap();
}

#[test]
fn pack_location_rejects_private_literals_before_dispatch() {
    use mkit_client::HttpTransport as _;
    use mkit_sync::Executor as _;
    let transport = NativeHttp::new()
        .unwrap()
        .with_transfer_timeout(std::time::Duration::from_millis(20));
    for host in [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.1.1",
        "[::ffff:127.0.0.1]",
        "[::10.1.2.3]",
    ] {
        let url = format!("https://{host}/pack");
        let error = transport
            .block_on(transport.fetch_pack_location(&url, 4, None))
            .unwrap_err();
        assert!(error.contains("destination refused"), "{host}: {error}");
    }
}
