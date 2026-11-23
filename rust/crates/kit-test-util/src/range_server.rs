//! A loopback HTTP server that answers each request from a script, for tests
//! of downloads that are interrupted and continued with `Range`.
//!
//! It serves one request per connection and closes the connection, so a
//! response can be cut anywhere in its body, as a dropped network would cut
//! it.

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{Shutdown, TcpListener};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

/// One request the server took: its target and its headers, names in lower
/// case.
#[derive(Clone, Debug)]
pub struct Request {
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The value of header `name` (lower case), if the request sent it.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The first byte of an open-ended `Range: bytes=N-` request.
    #[must_use]
    pub fn range_start(&self) -> Option<u64> {
        self.header("range")?
            .strip_prefix("bytes=")?
            .strip_suffix('-')?
            .parse()
            .ok()
    }
}

/// What the server sends for one request.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The `Content-Length` to declare. `None` declares the body's length.
    pub declared: Option<usize>,
    /// Close the connection after this many bytes of the body.
    pub cut: Option<usize>,
    /// Hold the connection this long after the body bytes, before closing
    /// it: a stall rather than a drop.
    pub hold: std::time::Duration,
}

impl Response {
    /// A response with no headers beyond those the server adds.
    #[must_use]
    pub fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
            declared: None,
            cut: None,
            hold: std::time::Duration::ZERO,
        }
    }

    /// Set header `name`, replacing any value it has.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Remove header `name`.
    #[must_use]
    pub fn without(mut self, name: &str) -> Self {
        self.headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self
    }

    /// Cut the connection after `bytes` bytes of the body.
    #[must_use]
    pub fn cut_after(mut self, bytes: usize) -> Self {
        self.cut = Some(bytes);
        self
    }

    /// Hold the connection for `hold` after the body bytes, before closing it.
    #[must_use]
    pub fn hold_for(mut self, hold: std::time::Duration) -> Self {
        self.hold = hold;
        self
    }
}

/// What an honest server with a strong entity tag answers: `200` with the
/// whole `object`, or `206` with the rest of it from the byte a `Range`
/// asks for, or `412` when `If-Match` names another tag.
#[must_use]
pub fn honest(object: &[u8], etag: &str, request: &Request) -> Response {
    if request.header("if-match").is_some_and(|tag| tag != etag) {
        return Response::new(412, b"");
    }
    match request
        .range_start()
        .and_then(|start| Some((start, usize::try_from(start).ok()?)))
    {
        Some((start, at)) if at < object.len() => {
            let rest = &object[at..];
            Response::new(206, rest).header("etag", etag).header(
                "content-range",
                &format!("bytes {start}-{}/{}", object.len() - 1, object.len()),
            )
        }
        Some(_) => Response::new(416, b""),
        None => Response::new(200, object).header("etag", etag),
    }
}

/// The scripted server. It stays up for the life of the process.
#[derive(Debug)]
pub struct RangeServer {
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl RangeServer {
    /// Start a server that answers the `n`th request (from zero) with
    /// `script(n, request)`.
    ///
    /// # Panics
    /// If the loopback port cannot be bound.
    pub fn start(script: impl Fn(usize, &Request) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let script = Arc::new(script);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (seen, script) = (Arc::clone(&seen), Arc::clone(&script));
                // One thread a connection, so a held connection does not
                // delay the request that follows it.
                thread::spawn(move || serve(stream, &seen, &*script));
            }
        });
        Self { address, requests }
    }

    /// `http://127.0.0.1:port`.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The requests taken so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Read one request from `stream`, record it, and send the scripted answer.
fn serve(
    stream: std::net::TcpStream,
    seen: &Mutex<Vec<Request>>,
    script: &(dyn Fn(usize, &Request) -> Response + Send + Sync),
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let target = line.split_whitespace().nth(1).unwrap_or("").to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let request = Request { target, headers };
    let index = {
        let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.push(request.clone());
        seen.len() - 1
    };
    let response = script(index, &request);
    let mut stream = reader.into_inner();
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        response.declared.unwrap_or(response.body.len()),
    );
    for (name, value) in &response.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");
    let sent = response
        .cut
        .unwrap_or(response.body.len())
        .min(response.body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body[..sent]);
    let _ = stream.flush();
    thread::sleep(response.hold);
    let _ = stream.shutdown(Shutdown::Both);
}
