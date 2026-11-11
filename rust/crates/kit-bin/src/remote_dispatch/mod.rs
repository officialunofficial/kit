//! The CLI wiring of a remote for `kit push`, `kit pull`, `kit fetch` and
//! `kit clone`.
//!
//! [`libkit::transfer`] holds the transfer operations, the reading of a
//! remote URL, the opening of a transport, the signer of a request envelope
//! and the credential-trust gate. This module connects them to the process of
//! the CLI: the terminal progress, the shutdown signal, the admission helper
//! and the warnings on stderr. The memory transport is in-process only, so
//! the integration tests drive it through `libkit::transfer::push_all` and
//! `libkit::transfer::pull_all` with an `Arc<MemoryTransport>`.
//!
//! Credentials / environment sources:
//! - HTTP(S): optional `KIT_API_TOKEN` bearer.
//! - S3: `KIT_S3_ACCESS_KEY_ID` + `KIT_S3_SECRET_ACCESS_KEY` (plus
//!   optional `KIT_S3_REGION`, default `us-east-1`). Missing creds do NOT
//!   fail at connect time; the first signed request returns
//!   `TransportError::AccessDenied`.
//! - SSH: spawns `ssh(1)` subprocess — inherits the user's agent / keys /
//!   `~/.ssh/config`. Per-repo `.kit/config` SSH options (host-key
//!   checking, known-hosts path, identity file) are wired through via
//!   `SshTransport::connect_with_options` when config is loaded.

mod packmap;

mod upload_receipts;

use std::path::Path;
use std::sync::Arc;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::protocol::{Transport, TransportError};
use kit_core::store::SyncPolicy;
use kit_sync::{Observer, PushLease, SyncEvent};
use kit_transport_connect::ConnectTransport;
use kit_transport_connect::admission::{AdmissionPolicy, is_reserved};
use libkit::grants::connect::{ConnectAuthority, LocalGrants};
use libkit::transfer::{self, Error, Remote, StepAuthority, is_connect_url};

use crate::progress::Terminal;

/// Open a transport for `endpoint` only after the per-endpoint
/// credential-trust gate approves it.
///
/// This is the single choke point through which push / fetch / pull
/// (and named-remote callers in) MUST build a transport: it runs
/// [`crate::config::endpoint_credential_trust`] — keyed on the resolved
/// ENDPOINT and its `repo_chosen` provenance — *before* constructing
/// the transport, so a credential-bearing HTTP/S3 transport is never
/// instantiated for a repo-chosen endpoint the user hasn't trusted.
///
/// `repo_chosen` is `true` when the endpoint came from repo-scoped
/// config (the flat `remote_endpoint` or a `remote.<name>.url`),
/// `false` when it came from the user / an explicit CLI argument. Trust
/// is per ENDPOINT, never per remote name.
///
/// `layout` is needed only to resolve a repo-key-file envelope signer
/// when `cfg.merged.transport_auth == "envelope"` (see
/// `transfer::envelope::envelope_signer`) — every caller already has it at
/// hand (it discovered the repo before building `cfg`).
pub fn open_trusted(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
    terminal: &Arc<Terminal>,
) -> Result<Remote, Error> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)?;
    open_with_config_for_remote(endpoint, &cfg.merged, layout, Some(remote_name), terminal)
}

/// A remote opened for `kit push`: the transport, and (for a signing Connect
/// client) the check that its stored grants authorize every advance of a split
/// push.
pub(crate) struct PushRemote {
    pub tx: Remote,
    pub authority: Option<Arc<dyn StepAuthority>>,
}

/// [`open_trusted`] for a push: the same trust gate and transport, plus the
/// grant pre-check a split push needs.
///
/// # Errors
/// As [`open_trusted`].
pub(crate) fn open_trusted_for_push(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
    terminal: &Arc<Terminal>,
) -> Result<PushRemote, Error> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)?;
    if !is_connect_url(endpoint) {
        return Ok(PushRemote {
            tx: open_with_config_for_remote(
                endpoint,
                &cfg.merged,
                layout,
                Some(remote_name),
                terminal,
            )?,
            authority: None,
        });
    }
    let parts = open_connect_parts(
        endpoint,
        &cfg.merged,
        layout,
        Some(remote_name),
        true,
        terminal,
    )?;
    let tx = Arc::new(parts.transport);
    let authority = parts
        .signer_key
        .zip(parts.grants)
        .map(|(signer_key, grants)| {
            Arc::new(ConnectAuthority::new(tx.clone(), grants, signer_key))
                as Arc<dyn StepAuthority>
        });
    Ok(PushRemote {
        tx: Remote::Connect(tx),
        authority,
    })
}

/// The single chokepoint that resolves SSH trust-pinning and
/// `kit+https://` envelope-signing config from `cfg` and opens a
/// transport. Every config-bearing caller — [`open_trusted`] (push /
/// fetch / pull) and `clone` — routes through here, so both are resolved
/// and threaded in exactly ONE place. A new remote command physically
/// cannot forget them as long as it opens through config; the only
/// un-pinned path is the config-less [`open`], which production never
/// uses for `ssh` or envelope auth.
pub(crate) fn open_with_config(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    terminal: &Arc<Terminal>,
) -> Result<Remote, Error> {
    open_with_config_for_remote(url, cfg, layout, None, terminal)
}

fn open_with_config_for_remote(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
    terminal: &Arc<Terminal>,
) -> Result<Remote, Error> {
    if is_connect_url(url) {
        return Ok(Remote::Connect(Arc::new(open_connect_with_config(
            url,
            cfg,
            layout,
            remote_name,
            true,
            terminal,
        )?)));
    }
    open_scheme(url, cfg).map(Remote::Transport)
}

/// [`open_trusted`] for a Connect endpoint, returning the concrete
/// [`ConnectTransport`] so callers can reach the epoch and visibility RPCs
/// `sign` chooses whether the ambient signing identity is used:
/// `kit epoch` and statement-mode `kit visibility set` send unsigned RPCs
/// and pass `false`; envelope-mode visibility passes `true` and so needs
/// `transport_auth = envelope` and a trusted remote, like `kit push`.
///
/// # Errors
/// The credential-trust gate, a non-Connect endpoint, or connection setup.
pub(crate) fn open_connect_trusted(
    endpoint: &str,
    remote_name: &str,
    repo_chosen: bool,
    cfg: &crate::config::LayeredConfig,
    layout: &RepoLayout,
    sign: bool,
    terminal: &Arc<Terminal>,
) -> Result<ConnectTransport, Error> {
    crate::config::endpoint_credential_trust(cfg, endpoint, repo_chosen)?;
    if !is_connect_url(endpoint) {
        return Err(Error::UnsupportedScheme(format!(
            "`{endpoint}` is not a kit+https:// or kit+http:// remote; grant epochs and repository visibility are served over Connect"
        )));
    }
    open_connect_with_config(
        endpoint,
        &cfg.merged,
        layout,
        Some(remote_name),
        sign,
        terminal,
    )
}

/// Build the Connect transport for `url` from `cfg`: envelope signing (when
/// `sign` and configured), the user grant store as the `GrantSource`, the
/// upload receipt store, progress observers and the admission helper.
pub(crate) fn open_connect_with_config(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
    sign: bool,
    terminal: &Arc<Terminal>,
) -> Result<ConnectTransport, Error> {
    Ok(open_connect_parts(url, cfg, layout, remote_name, sign, terminal)?.transport)
}

/// A Connect transport with what a push needs to check its authority.
struct ConnectParts {
    transport: ConnectTransport,
    /// The user grants installed on the transport (none without a signer).
    grants: Option<Arc<LocalGrants>>,
    /// The signing key's public hex, when requests are signed.
    signer_key: Option<String>,
}

fn open_connect_parts(
    url: &str,
    cfg: &crate::config::Config,
    layout: &RepoLayout,
    remote_name: Option<&str>,
    sign: bool,
    terminal: &Arc<Terminal>,
) -> Result<ConnectParts, Error> {
    let envelope_signer = if sign {
        if cfg.transport_auth_envelope() && cfg.trusted_remote_endpoint.trim() != url {
            return Err(Error::UntrustedRemote(format!(
                "refusing request signing for untrusted destination `{url}`; run `kit config trusted_remote_endpoint {url}` before using ambient signing identity"
            )));
        }
        transfer::envelope::envelope_signer(cfg, layout, &crate::environment::current())?
    } else {
        None
    };
    transfer::validate_connect_repository(url)?;
    let signed = envelope_signer.is_some();
    let signer_key = envelope_signer
        .as_ref()
        .map(|signer| signer.public_key_hex());
    // Resolve only the selected config fallback: an authoritative environment
    // path must not be defeated by an ignored fallback's tilde/HOME error.
    let ca_file = if url.starts_with("kit+https://")
        && std::env::var_os(kit_transport_connect::tls::CA_FILE_ENV).is_none()
    {
        crate::config::ssl_ca_file_path(cfg, layout).map_err(|error| {
            Error::Transport(TransportError::TlsConfiguration(error.to_string()))
        })?
    } else {
        None
    };
    let mut tx = ConnectTransport::connect_with_signer_and_ca_file(
        url,
        envelope_signer,
        ca_file.as_deref(),
    )?
    .with_receipt_store(Arc::new(upload_receipts::FilePartReceiptStore::new(
        layout.upload_parts_dir(),
    )))
    .with_pending_observer({
        let terminal = terminal.clone();
        move |event| {
            terminal.pending_event(event);
            !crate::signal::is_shutdown()
        }
    })
    .with_upload_observer({
        let terminal = terminal.clone();
        move |event| {
            terminal.upload_event(event);
            !crate::signal::is_shutdown()
        }
    })
    .with_admission_receipt_observer(|receipt| {
        eprintln!(
            "note: remote returned a {} receipt for {}",
            receipt.header,
            receipt
                .procedure
                .rsplit('/')
                .next()
                .unwrap_or(receipt.procedure)
        );
    });
    // Grants ride only on signed requests (SPEC-WRITE-GRANTS §4.2), so the
    // store is read only when there is a signer to present them with.
    let grants = signed.then(|| {
        let (grants, warnings) =
            LocalGrants::load(&cfg.grant_webauthn_rp, &crate::environment::current());
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        Arc::new(grants)
    });
    if let Some(grants) = &grants {
        tx = tx.with_grant_source(grants.clone());
    }
    if !cfg.admission_helper.is_empty() && cfg.trusted_remote_endpoint.trim() == url {
        let responder = Arc::new(crate::admission_helper::ExecResponder {
            path: cfg.admission_helper.clone().into(),
            terminal: terminal.clone(),
        });
        let mut policy = AdmissionPolicy::new(responder);
        if let Some(name) = remote_name
            && let Some(headers) = cfg.remote_admission_headers.get(name)
        {
            let bearer = std::env::var("KIT_API_TOKEN").is_ok_and(|s| !s.is_empty());
            for header in headers.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if is_reserved(header, bearer) {
                    eprintln!(
                        "warning: ignoring reserved header `{header}` in remote.{name}.admission_headers (see SPEC-TRANSPORT-CONNECT §5.1)"
                    );
                } else {
                    policy = policy.with_extra_allowed(header);
                }
            }
        }
        tx = tx.with_admission(policy);
    }
    Ok(ConnectParts {
        transport: tx,
        grants,
        signer_key,
    })
}

/// The CLI front of [`transfer::open`]. A build without `s3` names the CLI
/// feature in the refusal of a `kit+s3://` URL.
fn open_scheme(url: &str, cfg: &crate::config::Config) -> Result<Arc<dyn Transport>, Error> {
    #[cfg(not(feature = "s3"))]
    if url.starts_with("kit+s3://") {
        return Err(Error::UnsupportedScheme(format!(
            "'{url}' needs S3 support — rebuild with `--features s3`"
        )));
    }
    transfer::open(url, cfg)
}

/// Open a transport for the given URL with **no** SSH trust-pinning.
///
/// Low-level scheme dispatch only: it neither enforces the credential gate
/// nor threads `ssh.*` config. Any caller that has a [`Config`] must use
/// `open_with_config` (directly, or via `open_trusted`) so the trust-pinning
/// keys reach the spawned `ssh(1)`. `open` stays public only for the
/// integration tests that have no ambient config to resolve.
///
/// [`Config`]: crate::config::Config
pub fn open(url: &str) -> Result<Arc<dyn Transport>, Error> {
    open_scheme(url, &crate::config::Config::default())
}

/// The terminal observer, plus the one-time warning that opens a push.
struct PushObserver<'a> {
    terminal: &'a Terminal,
    warning: Option<String>,
}

impl Observer<SyncEvent> for PushObserver<'_> {
    fn event(&self, event: &SyncEvent) {
        if matches!(event, SyncEvent::PushBranchStarted { .. })
            && let Some(warning) = &self.warning
        {
            eprintln!("{warning}");
        }
        self.terminal.event(event);
    }
    fn cancelled(&self) -> bool {
        self.terminal.cancelled()
    }
}

/// The durability schedule of the object store, from the layered config. A
/// broken config falls back to the batched schedule rather than changing the
/// write semantics.
fn sync_policy(layout: &RepoLayout) -> SyncPolicy {
    crate::config::read_or_default(layout).map_or(SyncPolicy::Batch, |cfg| cfg.object_sync_policy())
}

/// Push every branch to the remote; see [`transfer::push_all_with_source`].
/// `remote` names the tracking refs, and `None` means `default`.
pub(crate) fn push_all_with_source(
    cwd: &Path,
    source: &dyn kit_sync::RemoteSource,
    remote: Option<&str>,
    force: bool,
    authority: Option<&dyn StepAuthority>,
    terminal: &Terminal,
) -> Result<transfer::Pushed, Error> {
    let layout = kit_core::layout::discover(cwd)?;
    let (settings, observer) = push_inputs(&layout, authority, terminal);
    transfer::push_all_with_source(
        cwd,
        source,
        remote.unwrap_or(kit_sync::DEFAULT_REMOTE_NAME),
        force,
        &settings,
        &observer,
    )
}

/// Push one branch to the remote; see [`transfer::push_branch_tracked_with_source`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn push_branch_tracked_source(
    cwd: &Path,
    source: &dyn kit_sync::RemoteSource,
    remote: &str,
    branch: &str,
    remote_branch: &str,
    lease: PushLease,
    authority: Option<&dyn StepAuthority>,
    terminal: &Terminal,
) -> Result<(Hash, usize), Error> {
    let layout = kit_core::layout::discover(cwd)?;
    let (settings, observer) = push_inputs(&layout, authority, terminal);
    transfer::push_branch_tracked_with_source(
        cwd,
        source,
        remote,
        branch,
        remote_branch,
        lease,
        &settings,
        &observer,
    )
}

/// The settings of a push from the config and the environment, and the observer
/// that shows it on the terminal.
fn push_inputs<'a>(
    layout: &RepoLayout,
    authority: Option<&'a dyn StepAuthority>,
    terminal: &'a Terminal,
) -> (transfer::PushSettings<'a>, PushObserver<'a>) {
    let (rebaseline_threshold, warning) = packmap::configured_depth();
    (
        transfer::PushSettings {
            sync_policy: sync_policy(layout),
            rebaseline_threshold,
            authority,
        },
        PushObserver { terminal, warning },
    )
}

/// Fetch the remote and fast-forward the current branch; see
/// [`transfer::pull_with_source`].
pub(crate) fn pull_all_with_source(
    cwd: &Path,
    source: &dyn kit_sync::RemoteSource,
    remote: &str,
    target_branch: Option<&str>,
    require_signed: bool,
    terminal: &Terminal,
) -> Result<kit_sync::PullReport, Error> {
    let layout = kit_core::layout::discover(cwd)?;
    let options = kit_sync::SyncOptions::default()
        .with_target_branch(target_branch.map(str::to_owned))
        .with_verify_signatures(require_signed)
        .with_sync_policy(sync_policy(&layout));
    Ok(kit_sync::pull(cwd, source, remote, &options, terminal)?)
}

/// Fetch the remote; see [`transfer::fetch_with_source`].
pub(crate) fn fetch_all_with_source(
    cwd: &Path,
    source: &dyn kit_sync::RemoteSource,
    remote: &str,
    require_signed: bool,
    prune: bool,
    terminal: &Terminal,
) -> Result<usize, Error> {
    let layout = kit_core::layout::discover(cwd)?;
    transfer::fetch_with_source(
        cwd,
        source,
        remote,
        require_signed,
        prune,
        sync_policy(&layout),
        terminal,
    )
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::progress::Terminal;
    use kit_core::layout::RepoLayout;

    #[test]
    fn envelope_destination_trust_precedes_missing_key_resolution() {
        let directory = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(directory.path());
        for endpoint in ["kit+https://untrusted.example", "kit+http://127.0.0.1:1"] {
            let mut cfg = Config {
                transport_auth: "envelope".into(),
                signer: "file".into(),
                signing_key: ".kit/keys/missing-signing-key".into(),
                ..Config::default()
            };
            let error = super::open_with_config(
                endpoint,
                &cfg,
                &layout,
                &std::sync::Arc::new(Terminal::detached()),
            )
            .expect_err("untrusted signing must fail");
            assert!(
                matches!(error, super::Error::UntrustedRemote(_)),
                "destination rejection must precede key access: {error}"
            );
            cfg.trusted_remote_endpoint = endpoint.into();
            let error = super::open_with_config(
                endpoint,
                &cfg,
                &layout,
                &std::sync::Arc::new(Terminal::detached()),
            )
            .expect_err("trusted endpoint now resolves the absent key");
            assert!(
                error.to_string().contains("requires a signing key"),
                "trusted destination should reach key resolution: {error}"
            );
        }
    }

    #[test]
    fn configured_connect_open_reports_malformed_repository_identity() {
        let directory = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(directory.path());
        let url = "kit+https://host/Uppercase";
        let error = super::open_with_config(
            url,
            &Config::default(),
            &layout,
            &std::sync::Arc::new(Terminal::detached()),
        )
        .expect_err("uppercase repository identity must be rejected");
        assert!(
            matches!(error, super::Error::MalformedUrl(_)),
            "expected malformed URL, got {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("Uppercase"), "{message}");
        assert!(!message.contains("invalid response"), "{message}");
    }
}
