//! Extra S3 HTTPS trust, selected by the same environment variable as Connect.
use kit_core::protocol::{TransportError, TransportResult};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::path::Path;

pub(crate) fn certificates(path: Option<&Path>) -> TransportResult<Vec<reqwest::Certificate>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let invalid = || {
        TransportError::TlsConfiguration(format!(
            "CA file {}: cannot read or parse PEM certificates",
            path.display()
        ))
    };
    let bytes = std::fs::read(path).map_err(|_| invalid())?;
    if !matched_pem_sections(&bytes) {
        return Err(invalid());
    }
    let certificates = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|_| invalid())?;
    if certificates.is_empty() {
        return Err(invalid());
    }
    // reqwest checks PEM encoding here, but defers DER validation until use.
    // Reject malformed trust roots at construction, including mixed bundles.
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&bytes) {
        roots
            .add(cert.map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    }
    Ok(certificates)
}

fn matched_pem_sections(bytes: &[u8]) -> bool {
    let mut section = None;
    // Match the dependency parser's LF, CR and CRLF line delimiters.
    for line in bytes
        .split(|byte| *byte == b'\n' || *byte == b'\r')
        .map(<[u8]>::trim_ascii)
    {
        if line.starts_with(b"-----BEGIN") {
            let Some(label) = line
                .strip_prefix(b"-----BEGIN ")
                .and_then(|line| line.strip_suffix(b"-----"))
            else {
                return false;
            };
            if section.is_some() || label.is_empty() {
                return false;
            }
            section = Some(label);
        } else if line.starts_with(b"-----END") {
            let label = line
                .strip_prefix(b"-----END ")
                .and_then(|line| line.strip_suffix(b"-----"));
            if section.is_none() || label != section {
                return false;
            }
            section = None;
        }
    }
    section.is_none()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // assertions and TLS fixture setup
mod tests {
    use super::*;
    use kit_core::protocol::{PackKey, SliceBody, Transport};
    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ca/");

    #[test]
    fn invalid_bundles_fail_closed() {
        let path = std::env::temp_dir().join(format!("kit-ca-{}", std::process::id()));
        let ca = std::fs::read(format!("{FIXTURES}ca.crt")).unwrap();
        for bad in [
            b"".as_slice(),
            b"not PEM",
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\n",
        ] {
            for prefix in [b"".as_slice(), ca.as_slice()] {
                std::fs::write(&path, [prefix, bad].concat()).unwrap();
                if prefix.is_empty() || !bad.is_empty() && bad != b"not PEM" {
                    assert!(certificates(Some(&path)).is_err());
                }
            }
        }
        std::fs::remove_file(&path).unwrap();
        assert!(certificates(Some(&path)).is_err());
    }

    fn listener() -> (String, std::thread::JoinHandle<()>) {
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
        };
        use std::io::{BufRead, BufReader, Read, Write};
        let certs = CertificateDer::pem_slice_iter(
            &std::fs::read(format!("{FIXTURES}server.crt")).unwrap(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            std::fs::read(format!("{FIXTURES}server-pk8.der")).unwrap(),
        ));
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap(),
                socket,
            );
            let mut reader = BufReader::new(&mut stream);
            let mut length = 0;
            let mut expect_continue = false;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(len) = lower.strip_prefix("content-length:") {
                    length = len.trim().parse::<u64>().unwrap();
                }
                if lower.starts_with("expect:") {
                    expect_continue = true;
                }
            }
            if expect_continue {
                reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .unwrap();
                reader.get_mut().flush().unwrap();
            }
            assert_eq!(
                std::io::copy(&mut reader.by_ref().take(length), &mut std::io::sink()).unwrap(),
                length
            );
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            reader.get_mut().flush().unwrap();
        });
        (url, server)
    }

    #[test]
    fn private_ca_is_required_for_blocking_and_upload_clients() {
        const TEST: &str = "tls::tests::private_ca_is_required_for_blocking_and_upload_clients";
        if std::env::var_os("KIT_S3_TLS_CHILD").is_none() {
            for trusted in [false, true] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child.args(["--exact", TEST]).env(
                    "KIT_S3_TLS_CHILD",
                    if trusted { "trusted" } else { "untrusted" },
                );
                child
                    .env_remove("KIT_SSL_CA_FILE")
                    .env("NO_PROXY", "localhost,127.0.0.1")
                    .env(crate::ENV_ACCESS_KEY, "test-access")
                    .env(crate::ENV_SECRET_KEY, "test-secret");
                if trusted {
                    child.env("KIT_SSL_CA_FILE", format!("{FIXTURES}ca.crt"));
                }
                let output = child.output().unwrap();
                assert!(
                    output.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let trusted = std::env::var("KIT_S3_TLS_CHILD").unwrap() == "trusted";
        for correct_host in [true, false] {
            for upload in [false, true] {
                let (url, server) = listener();
                let url = if correct_host {
                    url
                } else {
                    url.replace("localhost", "127.0.0.1")
                };
                let url = format!("{}/bucket", url.replace("https://", "kit+s3://"));
                let mut transport = crate::S3Transport::connect(&url).unwrap();
                transport.set_sleeper(|_| {});
                let key = PackKey::new([0; 32]);
                let result = if upload {
                    transport
                        .upload_pack(&SliceBody(&[7; 1024]), &key, None)
                        .map(|()| true)
                } else {
                    transport.pack_exists(&key, None)
                };
                server.join().unwrap();
                assert_eq!(
                    result.is_ok(),
                    trusted && correct_host,
                    "upload={upload}, host={correct_host}: {result:?}"
                );
            }
        }
    }
}
