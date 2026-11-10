//! Cost of `list_refs` as the number of refs grows.
//!
//! A local server answers the listing and delays each ref read by
//! [`READ_DELAY`], which stands in for the round trip to a store. The test
//! checks the request count and the number of reads in flight, and prints
//! the time of each listing. Run it with `--nocapture` to see the times.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use kit_core::protocol::Transport;
use kit_transport_s3::S3Transport;
use kit_transport_s3::sigv4::Credentials;

/// Delay of one ref read.
const READ_DELAY: Duration = Duration::from_millis(5);

/// The most ref reads the transport keeps in flight (SPEC-TRANSPORT §6).
const MAX_IN_FLIGHT: usize = 16;

#[derive(Default)]
struct Counters {
    requests: AtomicUsize,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

/// Serve a bucket that holds `refs` branches. Returns the endpoint.
fn serve(refs: usize, counters: Arc<Counters>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut listing = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
    for i in 0..refs {
        let _ = write!(
            listing,
            "<Contents><Key>refs/heads/b{i:04}</Key></Contents>"
        );
    }
    listing.push_str("</ListBucketResult>");
    let listing = Arc::new(listing);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let (counters, listing) = (Arc::clone(&counters), Arc::clone(&listing));
            thread::spawn(move || answer(stream, &counters, &listing));
        }
    });
    endpoint
}

/// Answer every request of one connection.
fn answer(stream: TcpStream, counters: &Counters, listing: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header == "\r\n" {
                break;
            }
        }
        counters.requests.fetch_add(1, Ordering::SeqCst);
        let target = request_line.split(' ').nth(1).unwrap_or_default();
        let body = if target.contains("list-type=2") {
            listing.to_owned()
        } else {
            let now = counters.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            counters.peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(READ_DELAY);
            counters.in_flight.fetch_sub(1, Ordering::SeqCst);
            format!("{}\n", "ab".repeat(32))
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(response.as_bytes()).is_err() {
            return;
        }
    }
}

#[test]
fn list_refs_reads_refs_in_parallel_with_one_request_each() {
    for refs in [10, 100, 1000] {
        let counters = Arc::new(Counters::default());
        let endpoint = serve(refs, Arc::clone(&counters));
        let transport = S3Transport::with_parts(
            &endpoint,
            "bucket",
            None,
            Credentials {
                access_key_id: "AKIA_TEST".into(),
                secret_access_key: "secret".into(),
                region: "us-east-1".into(),
            },
        )
        .unwrap();

        let start = Instant::now();
        let listed = transport.list_refs("refs/heads").unwrap();
        let elapsed = start.elapsed();

        let names: Vec<String> = listed.into_iter().map(|r| r.name).collect();
        let expected: Vec<String> = (0..refs).map(|i| format!("b{i:04}")).collect();
        assert_eq!(names, expected);
        let requests = counters.requests.load(Ordering::SeqCst);
        assert_eq!(requests, refs + 1, "one listing and one read per ref");
        let peak = counters.peak.load(Ordering::SeqCst);
        assert!(peak <= MAX_IN_FLIGHT, "{peak} reads in flight");
        assert!(peak > 1, "the reads ran one at a time");
        println!(
            "list_refs: {refs} refs, {requests} requests, {peak} in flight, {} ms",
            elapsed.as_millis()
        );
    }
}
