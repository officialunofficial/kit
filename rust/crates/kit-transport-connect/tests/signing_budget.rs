//! Signing time on the host request policy.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use kit_core::protocol::{BackoffIterator, Transport, TransportError};
use kit_transport_connect::ConnectTransport;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

struct Fixture {
    client: ConnectTransport,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(status: &str, headers: &str, body: Vec<u8>) -> Self {
        Self::responses(vec![(status.into(), headers.into(), body)])
    }
    fn responses(responses: Vec<(String, String, Vec<u8>)>) -> Self {
        assert!(!responses.is_empty());
        let responses: Vec<_> = responses
            .into_iter()
            .map(|(status, headers, body)| {
                let head = format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                (head, body)
            })
            .collect();
        RETRIES.with(|count| count.set(0));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            'connections: while !stopped.load(Ordering::SeqCst) {
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                // Accepted sockets may inherit the listener's nonblocking mode.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = match socket.read(&mut buffer) {
                        Ok(0) => continue 'connections,
                        Ok(count) => count,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::WouldBlock
                            ) =>
                        {
                            continue 'connections;
                        }
                        Err(error) => panic!("read request: {error}"),
                    };
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 64 * 1024);
                }
                let header_end = request
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .expect("request headers")
                    + 4;
                if !drain_request_body(&mut socket, &mut request, header_end) {
                    continue 'connections;
                }
                let index = {
                    let mut requests = captured.lock().unwrap();
                    let index = requests.len();
                    requests.push(String::from_utf8_lossy(&request).into_owned());
                    index
                };
                let (head, body) = &responses[index.min(responses.len() - 1)];
                if socket.write_all(head.as_bytes()).is_ok() {
                    // A bounded client may close before the remaining body.
                    let _ = socket.write_all(body);
                }
            }
        });
        let client =
            ConnectTransport::connect_for_test(format!("http://{address}").parse().unwrap())
                .with_retry_hooks_for_test(one_retry, record_retry);
        Self {
            client,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Err(payload) = self.thread.take().unwrap().join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(payload);
        }
    }
}
fn receive_until(socket: &mut std::net::TcpStream, request: &mut Vec<u8>, end: usize) -> bool {
    let mut buffer = [0; 1024];
    while request.len() < end {
        match socket.read(&mut buffer) {
            Ok(0) => return false,
            Ok(count) => request.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return false;
            }
            Err(error) => panic!("read request body: {error}"),
        }
        assert!(request.len() < 64 * 1024);
    }
    true
}
fn request_line_end(
    socket: &mut std::net::TcpStream,
    request: &mut Vec<u8>,
    cursor: usize,
) -> Option<usize> {
    loop {
        if let Some(offset) = request[cursor..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
        {
            return Some(cursor + offset);
        }
        let next = request.len() + 1;
        if !receive_until(socket, request, next) {
            return None;
        }
    }
}
fn drain_request_body(
    socket: &mut std::net::TcpStream,
    request: &mut Vec<u8>,
    header_end: usize,
) -> bool {
    let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
    if headers.lines().any(|line| {
        line.strip_prefix("transfer-encoding:")
            .is_some_and(|value| value.split(',').any(|coding| coding.trim() == "chunked"))
    }) {
        let mut cursor = header_end;
        loop {
            let Some(end) = request_line_end(socket, request, cursor) else {
                return false;
            };
            let size = usize::from_str_radix(
                std::str::from_utf8(&request[cursor..end])
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .trim(),
                16,
            )
            .unwrap();
            cursor = end + 2;
            if size == 0 {
                loop {
                    let Some(end) = request_line_end(socket, request, cursor) else {
                        return false;
                    };
                    if end == cursor {
                        return true;
                    }
                    cursor = end + 2;
                }
            }
            if !receive_until(socket, request, cursor + size + 2) {
                return false;
            }
            assert_eq!(&request[cursor + size..cursor + size + 2], b"\r\n");
            cursor += size + 2;
        }
    }
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .map(|value| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    receive_until(socket, request, header_end + content_length)
}

thread_local! {
    static RETRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn record_retry(_: Duration) {
    RETRIES.with(|count| count.set(count.get() + 1));
}
fn one_retry() -> BackoffIterator {
    BackoffIterator::with(Duration::ZERO, Duration::ZERO, 1)
}

struct SlowSigner;
impl kit_transport_connect::EnvelopeSigner for SlowSigner {
    fn public_key_hex(&self) -> String {
        "ab".repeat(32)
    }
    fn sign_hex(&self, _: &[u8; 32]) -> Result<String, String> {
        std::thread::sleep(Duration::from_millis(30));
        Ok("cd".repeat(64))
    }
}
#[test]
fn signing_time_is_charged_to_the_existing_attempt_timeout() {
    let mut fixture = Fixture::new("200 OK", "", Vec::new());
    fixture.client = ConnectTransport::connect_for_test_with_signer(
        fixture.client.origin().parse().unwrap(),
        Some(Arc::new(SlowSigner)),
    )
    .with_unary_timeout(Duration::from_millis(5));
    assert!(
        matches!(fixture.client.read_ref("heads/main"), Err(TransportError::RemoteError(message)) if message == "client-side deadline exceeded")
    );
    assert!(fixture.requests.lock().unwrap().is_empty());
}
