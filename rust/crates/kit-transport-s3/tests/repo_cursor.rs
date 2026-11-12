//! The repository cursor of the S3 transport (SPEC-TRANSPORT §6.8).
//!
//! A fake bucket answers `ListObjectsV2` (1,000 keys a page, with `ETag` and
//! `LastModified`), `GET` and `PUT`, and counts every request. The tests assert
//! the exact request counts of the cursor and of a listing.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use kit_core::hash::{Hash, to_hex};
use kit_core::protocol::Transport;
use kit_core::refs::RefWriteCondition;
use kit_transport_s3::S3Transport;
use kit_transport_s3::sigv4::Credentials;
use md5::{Digest as _, Md5};

const PAGE: usize = 1000;

/// One object: its body and the logical time of its last write.
type Object = (Vec<u8>, usize);

#[derive(Default)]
struct Bucket {
    objects: Mutex<BTreeMap<String, Object>>,
    clock: AtomicUsize,
    requests: AtomicUsize,
    /// Leave `ETag` out of every listed entry.
    omit_etag: std::sync::atomic::AtomicBool,
}

impl Bucket {
    fn put(&self, key: &str, body: &[u8]) {
        let now = self.clock.fetch_add(1, Ordering::SeqCst);
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_owned(), (body.to_vec(), now));
    }

    fn listing(&self, prefix: &str, after: &str) -> String {
        let objects = self.objects.lock().unwrap();
        let keys: Vec<(&String, &Object)> = objects
            .iter()
            .filter(|(k, _)| k.starts_with(prefix) && k.as_str() > after)
            .collect();
        let truncated = keys.len() > PAGE;
        let mut xml = format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>");
        for (key, (body, time)) in keys.iter().take(PAGE) {
            let _ = write!(xml, "<Contents><Key>{key}</Key>");
            if !self.omit_etag.load(Ordering::SeqCst) {
                let _ = write!(xml, "<ETag>&quot;{}&quot;</ETag>", hex(&Md5::digest(body)));
            }
            let _ = write!(xml, "<LastModified>t{time:08}</LastModified></Contents>");
        }
        if truncated {
            let last = keys[PAGE - 1].0;
            let _ = write!(xml, "<NextContinuationToken>{last}</NextContinuationToken>");
        }
        xml.push_str("</ListBucketResult>");
        xml
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn serve(bucket: Arc<Bucket>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let bucket = Arc::clone(&bucket);
            thread::spawn(move || answer(stream, &bucket));
        }
    });
    endpoint
}

fn answer(stream: TcpStream, bucket: &Bucket) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header == "\r\n" {
                break;
            }
            if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        bucket.requests.fetch_add(1, Ordering::SeqCst);
        let mut parts = request_line.split(' ');
        let (method, target) = (parts.next().unwrap(), parts.next().unwrap());
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let key = path.strip_prefix("/bucket/").unwrap_or_default();
        let (status, reply) = match method {
            "PUT" => {
                bucket.put(key, &body);
                ("200 OK", Vec::new())
            }
            "GET" if query.contains("list-type=2") => {
                let value = |name: &str| {
                    query
                        .split('&')
                        .find_map(|kv| kv.strip_prefix(name))
                        .unwrap_or_default()
                        .replace("%2F", "/")
                };
                let xml = bucket.listing(&value("prefix="), &value("continuation-token="));
                ("200 OK", xml.into_bytes())
            }
            "GET" => match bucket.objects.lock().unwrap().get(key) {
                Some((body, _)) => ("200 OK", body.clone()),
                None => ("404 Not Found", Vec::new()),
            },
            _ => ("405 Method Not Allowed", Vec::new()),
        };
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
            reply.len()
        );
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(&reply).is_err() {
            return;
        }
    }
}

fn transport(endpoint: &str) -> S3Transport {
    S3Transport::with_parts(
        endpoint,
        "bucket",
        None,
        Credentials {
            access_key_id: "AKIA_TEST".into(),
            secret_access_key: "secret".into(),
            region: "us-east-1".into(),
        },
    )
    .unwrap()
}

fn ref_body(n: u8) -> Vec<u8> {
    format!("{}\n", to_hex(&[n; 32])).into_bytes()
}

fn filled(refs: usize) -> (Arc<Bucket>, S3Transport) {
    let bucket = Arc::new(Bucket::default());
    for i in 0..refs {
        bucket.put(&format!("refs/heads/b{i:05}"), &ref_body(1));
    }
    bucket.put("packs/not-a-ref", b"pack");
    let transport = transport(&serve(Arc::clone(&bucket)));
    (bucket, transport)
}

fn requests_of(bucket: &Bucket, run: impl FnOnce()) -> usize {
    let before = bucket.requests.load(Ordering::SeqCst);
    run();
    bucket.requests.load(Ordering::SeqCst) - before
}

#[test]
fn an_unchanged_bucket_costs_one_request_per_thousand_refs() {
    for (refs, pages) in [(10, 1), (1000, 1), (1001, 2), (2500, 3)] {
        let (bucket, tx) = filled(refs);
        let mut first = None;
        let cost = requests_of(&bucket, || first = tx.repo_cursor().unwrap());
        assert_eq!(cost, pages, "cursor of {refs} refs");
        let mut second = None;
        let cost = requests_of(&bucket, || second = tx.repo_cursor().unwrap());
        assert_eq!(cost, pages);
        assert!(first.is_some());
        assert_eq!(first, second);
    }
}

#[test]
fn a_listing_costs_one_read_per_ref() {
    let (bucket, tx) = filled(1000);
    let cost = requests_of(&bucket, || {
        assert_eq!(tx.list_refs("refs/heads").unwrap().len(), 1000);
    });
    assert_eq!(cost, 1001);
}

#[test]
fn a_ref_written_by_another_writer_changes_the_cursor() {
    let (bucket, tx) = filled(20);
    let other = transport(&serve(Arc::clone(&bucket)));
    let before = tx.repo_cursor().unwrap().unwrap();
    let new_value: Hash = [2; 32];

    other
        .update_ref("refs/heads/b00003", RefWriteCondition::Any, &new_value)
        .unwrap();
    let moved = tx.repo_cursor().unwrap().unwrap();
    assert_ne!(before, moved, "a ref moved");

    other
        .update_ref("refs/heads/new", RefWriteCondition::Missing, &new_value)
        .unwrap();
    let created = tx.repo_cursor().unwrap().unwrap();
    assert_ne!(moved, created, "a ref was created");

    // A write outside `refs/` is not a ref.
    bucket.put("packs/another", b"pack");
    assert_eq!(tx.repo_cursor().unwrap().unwrap(), created);

    // A removed ref changes it too.
    bucket.objects.lock().unwrap().remove("refs/heads/new");
    assert_ne!(tx.repo_cursor().unwrap().unwrap(), created);
}

#[test]
fn a_bucket_rebuilt_with_the_same_refs_has_another_cursor() {
    let (bucket, tx) = filled(5);
    let before = tx.repo_cursor().unwrap().unwrap();
    let rebuilt: Vec<String> = bucket.objects.lock().unwrap().keys().cloned().collect();
    for key in rebuilt {
        bucket.put(&key, &ref_body(1));
    }
    assert_ne!(tx.repo_cursor().unwrap().unwrap(), before);
}

#[test]
fn a_listing_without_etags_offers_no_cursor() {
    let (bucket, tx) = filled(5);
    bucket.omit_etag.store(true, Ordering::SeqCst);
    assert_eq!(tx.repo_cursor().unwrap(), None);
}
