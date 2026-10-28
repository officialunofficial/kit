//! Open a transport from the URL of a remote.
//!
//! [`scheme`] reads the URL and decides which transport it names. It touches
//! neither the network nor the file system. [`open`] then builds the
//! transport. A URL comes from a config file or from a person, so the
//! reading is strict, and no message echoes the user information or the query
//! of a URL.

use std::sync::Arc;

use kit_core::protocol::Transport;
use kit_sync::RemoteSource;
use kit_transport_connect::{ConnectTransport, remote_identity_from_url};

use super::Error;
use crate::config::Config;

/// The transport that a URL names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scheme<'a> {
    /// `kit+file://<path>`: a repository on a local disk. Holds the path.
    File(&'a str),
    /// `kit+https://` or `kit+http://`: a Connect server. The repository
    /// identity of the URL is valid.
    Connect,
    /// `kit+s3://`: an object store.
    S3,
    /// `kit+ssh://`: a remote `kit serve` over `ssh(1)`.
    Ssh,
}

/// Decide which transport `url` names.
///
/// # Errors
/// The scheme is not a sync scheme, a Connect URL has an invalid repository
/// identity, or the URL is malformed. A git-bridge URL and a plain HTTP(S) URL
/// are refused with the advice that fits them.
pub fn scheme(url: &str) -> Result<Scheme<'_>, Error> {
    if url.starts_with("git+") {
        return Err(Error::UnsupportedScheme(format!(
            "'{}' is a git-bridge remote — native push/pull/fetch/clone do not \
             speak git transports; use `kit git export` / `kit git import` / \
             `kit git pull` (feature git-bridge)",
            shown(url)
        )));
    }
    if let Some(path) = url.strip_prefix("kit+file://") {
        return Ok(Scheme::File(path));
    }
    if url.starts_with("kit+memory://") {
        return Err(Error::UnsupportedScheme(
            "kit+memory:// must be driven via in-process harness (see tests)".to_owned(),
        ));
    }
    if is_connect_url(url) {
        validate_connect_repository(url)?;
        return Ok(Scheme::Connect);
    }
    if url.starts_with("kit+s3://") {
        return Ok(Scheme::S3);
    }
    if url.starts_with("kit+ssh://") {
        return Ok(Scheme::Ssh);
    }
    if let Some((scheme, rest)) = url
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "https" | "http"))
    {
        // Never echo the user information or the query of a URL. A URL that
        // carries user information gets the generic form instead of a rewrite.
        let rest = rest.split(['?', '#']).next().unwrap_or(rest);
        let display = if rest.contains('@') {
            "<host>/<namespace>/<name>"
        } else {
            rest
        };
        return Err(Error::UnsupportedScheme(format!(
            "`{scheme}://{display}` is not a sync remote: at a server's origin, plain HTTP(S) serves objects by repository path (SPEC-HTTP-OBJECTS); sync remotes use `kit+https://`, for example `kit+https://{display}`"
        )));
    }
    Err(Error::MalformedUrl(shown(url).to_owned()))
}

/// `url` for a message. A URL that carries user information or a query shows
/// none of its own text, because that text can hold a secret.
fn shown(url: &str) -> &str {
    if url.contains(['@', '?', '#']) {
        "<URL withheld: it carries user information or a query>"
    } else {
        url
    }
}

/// Whether `url` names a Connect server.
#[must_use]
pub fn is_connect_url(url: &str) -> bool {
    url.starts_with("kit+https://") || url.starts_with("kit+http://")
}

/// Check the repository identity in a Connect URL.
///
/// # Errors
/// [`Error::MalformedUrl`]. A URL that carries user information or a query
/// gets a generic message, because its segments cannot be trusted to exclude
/// credential text.
pub fn validate_connect_repository(url: &str) -> Result<(), Error> {
    remote_identity_from_url(url).map_err(|reason| {
        if url.contains(['@', '?', '#']) {
            return Error::MalformedUrl(
                "the remote URL is not a valid kit+https:// remote; use kit+https://<host>/<namespace>/<name> without userinfo or a query".to_owned(),
            );
        }
        let path = url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map_or("", |(_, path)| path)
            .trim_matches('/');
        Error::MalformedUrl(format!("repository identity `{path}` in {url}: {reason}"))
    })?;
    Ok(())
}

/// The three `ssh.*` trust-pinning keys of the config. An empty value means
/// "unset": `ssh(1)` gets no flag for it and keeps its own default.
#[cfg(feature = "transport-ssh")]
fn ssh_options(cfg: &Config) -> kit_transport_ssh::SshOptions {
    kit_transport_ssh::SshOptions {
        strict_host_key_checking: cfg.ssh_strict_host_key_checking.clone(),
        user_known_hosts_file: cfg.ssh_user_known_hosts_file.clone(),
        identity_file: cfg.ssh_identity_file.clone(),
    }
}

#[cfg(not(all(
    feature = "transport-file",
    feature = "transport-ssh",
    feature = "transport-s3"
)))]
fn unsupported(url: &str, feature: &str) -> Error {
    Error::UnsupportedScheme(format!(
        "'{}' needs the `{feature}` feature of the library",
        shown(url)
    ))
}

/// Open the transport that `url` names. A Connect URL opens with the bearer
/// token of the environment and without a request signer.
///
/// This does not run the credential-trust gate. A program that has a config
/// calls [`check_endpoint`](super::check_endpoint) first. `cfg` supplies the
/// `ssh.*` keys for the `ssh(1)` child of a `kit+ssh://` URL. The handshake
/// finishes inside this call, and a failure stops the child, so the caller
/// never sees a half-built transport.
///
/// # Errors
/// As [`scheme`], or the transport cannot start, or the library lacks the
/// feature of the scheme.
pub fn open(url: &str, cfg: &Config) -> Result<Arc<dyn Transport>, Error> {
    #[cfg(not(feature = "transport-ssh"))]
    let _ = cfg;
    match scheme(url)? {
        #[cfg(feature = "transport-file")]
        Scheme::File(path) => Ok(Arc::new(kit_transport_file::FileTransport::new(
            std::path::Path::new(path),
        ))),
        #[cfg(not(feature = "transport-file"))]
        Scheme::File(_) => Err(unsupported(url, "transport-file")),
        Scheme::Connect => Ok(Arc::new(ConnectTransport::connect_with_signer(url, None)?)),
        #[cfg(feature = "transport-s3")]
        Scheme::S3 => Ok(Arc::new(kit_transport_s3::S3Transport::connect(url)?)),
        #[cfg(not(feature = "transport-s3"))]
        Scheme::S3 => Err(unsupported(url, "transport-s3")),
        #[cfg(feature = "transport-ssh")]
        Scheme::Ssh => {
            let target = kit_transport_ssh::parse_kit_ssh_url(url)
                .map_err(kit_transport_ssh::SshInitError::from)?;
            Ok(Arc::new(
                kit_transport_ssh::SshTransport::connect_with_options(&target, &ssh_options(cfg))?,
            ))
        }
        #[cfg(not(feature = "transport-ssh"))]
        Scheme::Ssh => Err(unsupported(url, "transport-ssh")),
    }
}

/// A configured native remote. Connect operations use `ClientSource`. Other
/// schemes keep their synchronous transport adapter.
pub enum Remote {
    /// A Connect server.
    Connect(Arc<ConnectTransport>),
    /// Any other transport.
    Transport(Arc<dyn Transport>),
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Remote")
            .field("connect", &matches!(self, Self::Connect(_)))
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// Lend the configured source for one repository operation.
    ///
    /// # Errors
    /// The host adapter cannot prepare the operation.
    pub fn with_source<R>(
        &self,
        operation: impl FnOnce(&dyn RemoteSource) -> R,
    ) -> Result<R, Error> {
        match self {
            Self::Connect(transport) => transport.with_source(operation).map_err(Into::into),
            Self::Transport(transport) => Ok(operation(&super::source(transport.as_ref()))),
        }
    }

    /// The bounds that the interruption advice uses, from the cached
    /// discovery of the remote.
    #[must_use]
    pub fn upload_limits(&self) -> kit_core::protocol::UploadLimits {
        match self {
            Self::Connect(transport) => transport.upload_limits(),
            Self::Transport(transport) => transport.upload_limits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_default(url: &str) -> Result<Arc<dyn Transport>, Error> {
        open(url, &Config::default())
    }

    #[test]
    fn plain_https_remote_is_refused_with_sync_remote_guidance() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        let url = format!("https://vcs.example/{uuid}/repo");
        let error = open_default(&url).err().expect("plain https must fail");
        assert!(
            matches!(error, Error::UnsupportedScheme(_)),
            "plain https is an unsupported scheme, not a malformed URL: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&format!("kit+{url}")),
            "{message} must suggest the kit+ spelling"
        );
        assert!(message.contains("SPEC-HTTP-OBJECTS"), "{message}");

        // Userinfo and queries are never echoed.
        let error = open_default(&format!(
            "http://user:secret@vcs.example/{uuid}/repo?k=q1#f"
        ))
        .err()
        .expect("plain http must fail");
        let message = error.to_string();
        assert!(!message.contains("secret"), "{message}");
        assert!(
            !message.contains("q1") && !message.contains("#f"),
            "{message}"
        );
        assert!(message.contains("kit+https://"), "{message}");
        let error = open_default(&format!("http://vcs.example/{uuid}/repo?k=q1"))
            .err()
            .expect("plain http must fail");
        let message = error.to_string();
        assert!(!message.contains("q1"), "{message}");
        assert!(
            message.contains(&format!("kit+https://vcs.example/{uuid}/repo")),
            "{message}"
        );
        // A rejected identity does not echo the URL's userinfo or query.
        let error = open_default("kit+https://user:secret@vcs.example/Bad/repo?k=q1")
            .err()
            .expect("bad namespace must fail");
        let message = error.to_string();
        assert!(
            !message.contains("secret") && !message.contains("q1"),
            "{message}"
        );
        for url in [
            "kit+https://user:pa/ss@vcs.example/Bad/repo",
            "kit+https://user:12/ss@vcs.example/Bad/repo",
        ] {
            let message = open_default(url).err().expect("must fail").to_string();
            assert!(
                !message.contains("ss@") && !message.contains("pa/"),
                "{message}"
            );
        }
    }

    #[test]
    fn connect_url_validation_names_the_offending_segment() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        for (path, offending) in [("/Bad/repo", "`Bad`"), ("/repo/Name", "`Name`")] {
            let url = format!("kit+https://vcs.example{path}");
            let error = open_default(&url)
                .err()
                .unwrap_or_else(|| panic!("{url} must fail"));
            let message = error.to_string();
            assert!(message.contains(offending), "{message}");
            assert!(message.contains("§7.4"), "{message}");
        }
        // An opaque authority-mode namespace validates under the union
        // grammar and builds a transport.
        assert!(open_default(&format!("kit+https://vcs.example/{uuid}/repo")).is_ok());
    }

    #[cfg(feature = "transport-ssh")]
    #[test]
    fn populated_config_maps_to_ssh_options() {
        let cfg = Config {
            ssh_strict_host_key_checking: "yes".to_string(),
            ssh_user_known_hosts_file: "/path/to/project.known_hosts".to_string(),
            ssh_identity_file: "/path/to/id_ed25519".to_string(),
            ..Config::default()
        };
        let opts = ssh_options(&cfg);
        assert_eq!(opts.strict_host_key_checking, "yes");
        assert_eq!(opts.user_known_hosts_file, "/path/to/project.known_hosts");
        assert_eq!(opts.identity_file, "/path/to/id_ed25519");
    }

    #[cfg(feature = "transport-ssh")]
    /// Empty `ssh.*` fields must map to empty `SshOptions` fields so
    /// `build_ssh_command` emits NO `-o`/`-i` flags and the user's
    /// `ssh(1)` defaults are inherited unchanged.
    #[test]
    fn empty_config_maps_to_empty_ssh_options() {
        let opts = ssh_options(&Config::default());
        assert!(opts.strict_host_key_checking.is_empty());
        assert!(opts.user_known_hosts_file.is_empty());
        assert!(opts.identity_file.is_empty());
    }

    #[test]
    fn scheme_names_the_transport_of_each_url() {
        assert_eq!(
            scheme("kit+file:///srv/repo").unwrap(),
            Scheme::File("/srv/repo")
        );
        assert_eq!(
            scheme("kit+s3://s3.example.com/bucket/proj").unwrap(),
            Scheme::S3
        );
        assert_eq!(scheme("kit+ssh://git@host/repo").unwrap(), Scheme::Ssh);
        assert_eq!(
            scheme("kit+https://vcs.example/myproj").unwrap(),
            Scheme::Connect
        );
        assert_eq!(
            scheme("kit+http://127.0.0.1:1/myproj").unwrap(),
            Scheme::Connect
        );
    }

    #[test]
    fn a_refusal_never_echoes_user_information_or_a_query() {
        for url in [
            "git+https://user:secret@host/repo",
            "git+https://host/repo?token=secret",
            "ftp://user:secret@host/x",
            "kit+https://user:secret@host/Bad/repo",
            "https://user:secret@host/x",
            "https://host/x?token=secret#secret",
        ] {
            let message = scheme(url).unwrap_err().to_string();
            assert!(!message.contains("secret"), "{url}: {message}");
        }
    }

    #[test]
    fn scheme_refuses_what_a_sync_remote_cannot_use() {
        for url in ["git+https://host/repo", "kit+memory://x"] {
            assert!(
                matches!(scheme(url), Err(Error::UnsupportedScheme(_))),
                "{url}"
            );
        }
        for url in [
            "",
            "ftp://host/x",
            "/srv/repo",
            "kit+nope://x",
            "kit+https://",
        ] {
            assert!(matches!(scheme(url), Err(Error::MalformedUrl(_))), "{url}");
        }
    }
}
