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
pub(crate) struct StderrWarnings;

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

/// Record the upstream of a branch after a push, for the current command.
///
/// # Errors
/// As [`libkit::push::record_upstream`].
pub fn record_upstream(
    layout: &RepoLayout,
    cfg: &LayeredConfig,
    branch: &str,
    upstream: Upstream,
    replace: bool,
) -> Result<(), libkit::push::Error> {
    libkit::push::record_upstream(
        layout,
        cfg,
        &environment::current(),
        &StderrWarnings,
        branch,
        upstream,
        replace,
    )
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

/// Per-endpoint credential trust check for the shared dispatch choke
/// point ([`crate::remote_dispatch::open_trusted`]) and named-remote
/// callers. `repo_chosen` is `true` when the endpoint was selected by
/// the repo-scoped config (the flat `remote_endpoint` or a
/// `remote.<name>.url` entry), `false` when it was supplied by the user
/// (user-scoped config or an explicit CLI argument). Trust is keyed on
/// the resolved ENDPOINT plus this provenance, never on a remote name.
///
/// # Errors
/// As [`libkit::transfer::check_endpoint`].
pub fn endpoint_credential_trust(
    cfg: &LayeredConfig,
    endpoint: &str,
    repo_chosen: bool,
) -> Result<(), libkit::transfer::Error> {
    libkit::transfer::check_endpoint(
        endpoint,
        repo_chosen,
        &cfg.user.trusted_remote_endpoint,
        &user_config_display(),
        &|name| std::env::var(name).ok().filter(|value| !value.is_empty()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user-trusted endpoint is always allowed.
    #[test]
    fn endpoint_credential_trust_honours_user_trust() {
        let mut cfg = LayeredConfig::default();
        cfg.user.trusted_remote_endpoint = "kit+https://trusted.invalid/r".to_owned();
        assert!(endpoint_credential_trust(&cfg, "kit+https://trusted.invalid/r", true).is_ok());
    }
}
