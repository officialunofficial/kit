//! The CLI side of config loading.
//!
//! The rules live in [`libkit::config`]. This module binds them to the
//! process: it passes the [`libkit::Environment`] of the current command,
//! prints each [`ConfigEvent`] as a warning on stderr, and applies the
//! credential gate to the ambient credential variables.

use std::io::Write as _;
use std::path::PathBuf;

use kit_core::layout::RepoLayout;
use libkit::Observer;
pub use libkit::config::{
    AttestConfig, CONFIG_FILE, Config, ConfigError, ConfigEvent, ConfigScope, DEFAULT_BRANCH,
    DEFAULT_KEY_BACKEND, DEFAULT_KEY_REF, DEFAULT_P256_KEY_REF, DEFAULT_REMOTE_NAME,
    DEFAULT_SECP256K1_KEY_REF, DEFAULT_SIGNER, DEFAULT_SIGNING_KEY, KeyConfig, LayeredConfig,
    MAX_CONFIG_BYTES, REPO_FORBIDDEN_KEYS, RemoteEntry, ResolvedRemote, USER_CONFIG_SUBPATH,
    Upstream, apply_text, configured_remote_names, expand_user_identity, is_repo_forbidden_key,
    normalize_config_key, parse_pipe_list, resolve_remote, resolve_upstream, validate_key_path,
    validate_value, write,
};

use crate::environment;

/// Prints each config event as a warning on stderr.
struct StderrWarnings;

impl Observer<ConfigEvent> for StderrWarnings {
    fn event(&self, event: &ConfigEvent) {
        let mut stderr = std::io::stderr().lock();
        match event {
            ConfigEvent::IgnoredRepoKey { key, origin } => {
                let _ = writeln!(
                    stderr,
                    "warning: ignoring `{key}` from per-repo config at {} \
                     (security-sensitive keys are user-scoped only — see {} \
                     and docs/THREAT-MODEL.md)",
                    origin.display(),
                    user_config_display()
                );
            }
            ConfigEvent::IgnoredOverride { key } => {
                let _ = writeln!(
                    stderr,
                    "warning: ignoring `-c {key}=…` (security-sensitive keys cannot be set via -c; \
                     set it in your user config — see docs/THREAT-MODEL.md)"
                );
            }
            _ => {}
        }
    }
}

/// Read the merged config for the current command.
pub fn read_or_default(layout: &RepoLayout) -> Result<Config, ConfigError> {
    libkit::config::read_or_default(layout, &environment::current(), &StderrWarnings)
}

/// Read the user, repo and merged config for the current command.
pub fn read_layered(layout: &RepoLayout) -> Result<LayeredConfig, ConfigError> {
    libkit::config::read_layered(layout, &environment::current(), &StderrWarnings)
}

/// Resolve a configured signing-key path for the current command.
pub fn resolve_key_path(layout: &RepoLayout, value: &str) -> Result<PathBuf, ConfigError> {
    libkit::config::resolve_key_path(layout, &environment::current(), value)
}

/// Resolve `http.sslCAInfo` for the current command.
pub fn ssl_ca_file_path(cfg: &Config, layout: &RepoLayout) -> Result<Option<PathBuf>, ConfigError> {
    cfg.ssl_ca_file_path(layout, &environment::current())
}

/// Write one user-scoped key for the current command.
pub fn write_user_kv(key: &str, value: &str) -> Result<(), ConfigError> {
    libkit::config::write_user_kv(&environment::current(), key, value)
}

/// Remove one user-scoped key for the current command.
pub fn remove_user_kv(key: &str) -> Result<bool, ConfigError> {
    libkit::config::remove_user_kv(&environment::current(), key)
}

/// The user config file path for the current command.
pub fn user_config_path() -> Result<PathBuf, ConfigError> {
    libkit::config::user_config_path(&environment::current())
}

/// The XDG config base for the current command.
///
/// # Errors
/// As [`libkit::config::xdg_config_home`].
pub fn xdg_config_home() -> Result<PathBuf, String> {
    libkit::config::xdg_config_home(&environment::current())
}

/// The user-scoped config path for a message. It names the file when the
/// path resolves and the config scope otherwise.
#[must_use]
pub fn user_config_display() -> String {
    user_config_path().map_or_else(
        |_| "the user-scoped config".to_owned(),
        |p| p.display().to_string(),
    )
}

/// Real-environment getter used by the runtime credential gate: reads
/// the named environment variable, treating an empty value as absent.
fn real_getenv(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Per-endpoint credential trust check for the shared dispatch choke
/// point ([`crate::remote_dispatch::open_trusted`]) and named-remote
/// callers. `repo_chosen` is `true` when the endpoint was selected by
/// the repo-scoped config (the flat `remote_endpoint` or a
/// `remote.<name>.url` entry), `false` when it was supplied by the user
/// (user-scoped config or an explicit CLI argument). Trust is keyed on
/// the resolved ENDPOINT plus this provenance, never on a remote name.
pub fn endpoint_credential_trust(
    cfg: &LayeredConfig,
    endpoint: &str,
    repo_chosen: bool,
) -> Result<(), String> {
    match trusted_remote_error_for(
        endpoint.trim(),
        repo_chosen,
        cfg.user.trusted_remote_endpoint.trim(),
        &real_getenv,
    ) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}

/// Core gate, keyed on an explicit endpoint + provenance rather than a
/// `LayeredConfig`. Returns `Some(error)` when ambient HTTP/S3
/// credentials would be attached to a repo-chosen endpoint that the
/// user has not explicitly trusted.
///
/// * `endpoint` — the resolved, already-trimmed remote URL.
/// * `repo_chosen` — whether the repo-scoped config selected this
///   endpoint (the only case the gate fences; a user-chosen endpoint is
///   the user's own decision).
/// * `user_trusted` — the trimmed user-scoped `trusted_remote_endpoint`.
/// * `getenv` — credential probe (injected for tests).
fn trusted_remote_error_for<F>(
    endpoint: &str,
    repo_chosen: bool,
    user_trusted: &str,
    getenv: &F,
) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    if endpoint.is_empty() || !repo_chosen {
        return None;
    }
    if user_trusted == endpoint {
        return None;
    }

    if endpoint.starts_with("kit+http://") || endpoint.starts_with("kit+https://") {
        if getenv(kit_transport_connect::TOKEN_ENV).is_some() {
            return Some(format!(
                "refusing repo-configured remote `{endpoint}` with ambient {} bearer token; trust it explicitly with `kit config trusted_remote_endpoint {endpoint}` (writes {})",
                kit_transport_connect::TOKEN_ENV,
                user_config_display()
            ));
        }
        return None;
    }

    #[cfg(feature = "s3")]
    if endpoint.starts_with("kit+s3://")
        && (getenv(kit_transport_s3::ENV_ACCESS_KEY).is_some()
            || getenv(kit_transport_s3::ENV_SECRET_KEY).is_some())
    {
        return Some(format!(
            "refusing repo-configured remote `{endpoint}` with ambient S3 credentials; trust it explicitly with `kit config trusted_remote_endpoint {endpoint}` (writes {})",
            user_config_display()
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derives `repo_chosen` from the flat `remote_endpoint`, as the layered
    /// callers do.
    fn gate_for_flat<F>(repo_endpoint: &str, user_trusted: &str, getenv: &F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let endpoint = repo_endpoint.trim();
        trusted_remote_error_for(endpoint, true, user_trusted.trim(), getenv)
    }

    #[test]
    fn repo_http_remote_with_token_requires_user_trust() {
        let msg = gate_for_flat("kit+https://example.invalid/repo", "", &|name| {
            (name == kit_transport_connect::TOKEN_ENV).then(|| "token".to_string())
        })
        .expect("repo-scoped HTTP remote with token must be rejected");
        assert!(msg.contains("trusted_remote_endpoint"));
    }

    #[test]
    fn trusted_http_remote_is_allowed() {
        let msg = gate_for_flat(
            "kit+https://example.invalid/repo",
            "kit+https://example.invalid/repo",
            &|name| (name == kit_transport_connect::TOKEN_ENV).then(|| "token".to_string()),
        );
        assert!(msg.is_none());
    }

    #[cfg(feature = "s3")]
    #[test]
    fn repo_s3_remote_with_env_creds_requires_user_trust() {
        let msg = gate_for_flat(
            "kit+s3://s3.example.com/bucket/proj",
            "",
            &|name| match name {
                kit_transport_s3::ENV_ACCESS_KEY => Some("AKIA...".to_string()),
                _ => None,
            },
        )
        .expect("repo-scoped S3 remote with env creds must be rejected");
        assert!(msg.contains("trusted_remote_endpoint"));
    }

    /// The gate keys on PROVENANCE, not mere credential presence: a
    /// user-chosen endpoint (`repo_chosen == false`) with ambient creds
    /// is the user's own decision and must NOT be refused, even though
    /// the same endpoint+creds would be refused if the repo had chosen
    /// it.
    #[test]
    fn user_chosen_http_remote_with_token_is_allowed() {
        let token =
            |name: &str| (name == kit_transport_connect::TOKEN_ENV).then(|| "tok".to_string());
        let ep = "kit+https://example.invalid/repo";
        // repo_chosen = false (user-scoped or CLI-supplied endpoint).
        assert!(trusted_remote_error_for(ep, false, "", &token).is_none());
        // repo_chosen = true with no user trust → refused.
        assert!(trusted_remote_error_for(ep, true, "", &token).is_some());
    }

    /// Per-endpoint helper returns `None` when no ambient credentials
    /// are present, regardless of provenance — an unauthenticated push
    /// is always safe.
    #[test]
    fn repo_http_remote_without_token_is_allowed() {
        let none = |_: &str| None;
        let ep = "kit+https://example.invalid/repo";
        assert!(trusted_remote_error_for(ep, true, "", &none).is_none());
    }

    /// SSH and file endpoints never carry ambient HTTP/S3 creds, so the
    /// gate passes them through even when repo-chosen and untrusted.
    #[test]
    fn ssh_and_file_endpoints_bypass_credential_gate() {
        let all = |_: &str| Some("present".to_string());
        assert!(trusted_remote_error_for("kit+ssh://host/path", true, "", &all).is_none());
        assert!(trusted_remote_error_for("kit+file:///srv/mirror", true, "", &all).is_none());
    }

    /// `endpoint_credential_trust` is the public per-endpoint entry the
    /// dispatch choke point and named-remote callers use. A user-trusted
    /// endpoint is always allowed.
    #[test]
    fn endpoint_credential_trust_honours_user_trust() {
        let mut cfg = LayeredConfig::default();
        cfg.user.trusted_remote_endpoint = "kit+https://trusted.invalid/r".to_owned();
        assert!(endpoint_credential_trust(&cfg, "kit+https://trusted.invalid/r", true).is_ok());
    }
}
