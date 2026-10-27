//! `kit attest` — produce a signed DSSE attestation for a commit.
//!
//! ```text
//! kit attest [--commit <hash>] [--algorithm ed25519|secp256k1|p256]
//!             [--signer repo-key|external|keystore]
//!             [--predicate-type <URI>] [--predicate-file <path>]
//!             [--external-signer-arg <V>]...
//!             [--additional-signer "<spec>"]...
//! ```
//!
//! `--external-signer-arg` is repeatable; each instance adds one
//! argv token to the external signer subprocess. If any are passed,
//! they REPLACE (not append to) `attest.external_signer_args` from
//! `.kit/config` — per-invocation override for "sign with tag X
//! this one time" that avoids shell-quoting hell.
//!
//! Defaults:
//! * `--commit` — HEAD.
//! * `--algorithm` — `attest.default_algorithm` in config, else `ed25519`.
//! * `--signer` — `attest.signer` in config, else `repo-key`.
//! * `--predicate-type` —
//!   `https://kit.storage/spec/predicate/empty/v1`.
//! * `--predicate-file` — omitted ⇒ `{}`.
//!
//! Multi-signature envelopes are produced by passing one or more
//! `--additional-signer` flags after the primary signer. Each spec is
//! a comma-separated `key=value` list:
//!
//! ```text
//! --additional-signer "algorithm=<algo>,signer=<kind>[,path=<file-or-binary>][,args=<a>|<b>|<c>]"
//! ```
//!
//! The optional `args=` clause is pipe-separated (commas would clash
//! with the outer key=value separator) and applies only when
//! `signer=external`. Each pipe-separated token becomes one argv
//! entry for the child process, same as `--external-signer-arg` on
//! the primary signer.
//!
//! Signers are invoked in order (primary first, then each
//! `--additional-signer` as they appear on the command line) and the
//! resulting `{keyid, sig}` tuples are written into one envelope in
//! that same order. Any signer failure aborts the attest — no
//! partial envelopes are written to disk.
//!
//! On success, prints the att-id (64 hex chars) and exits 0.

use std::io::Write;

use clap::Parser;
use kit_core::hash as hash_mod;
use libkit::attest_signer;
use libkit::attestation::{self, Request, SignerSpec};

use crate::clap_args;
use crate::exit;
use crate::progress::ServedWarning;

#[derive(Debug, Parser)]
#[command(
    name = "kit attest",
    about = "Produce a signed DSSE attestation for a commit."
)]
#[allow(clippy::struct_field_names)]
struct Args {
    /// Commit hash to attest. Defaults to HEAD.
    #[arg(long, value_name = "HASH")]
    commit: Option<String>,
    /// Algorithm: `ed25519`, `secp256k1`, or `p256`.
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    /// Signer kind: `repo-key` (default), `external`, or `keystore`.
    #[arg(long, value_name = "KIND")]
    signer: Option<String>,
    /// Predicate type URI.
    #[arg(long = "predicate-type", value_name = "URI")]
    predicate_type: Option<String>,
    /// Path to a JSON predicate body.
    #[arg(long = "predicate-file", value_name = "PATH")]
    predicate_file: Option<String>,
    /// Repeatable `--additional-signer "<spec>"`. Each spec is a
    /// comma-separated `key=value` list parsed downstream — see the
    /// module docstring.
    #[arg(long = "additional-signer", value_name = "SPEC")]
    additional_signers: Vec<String>,
    /// Repeatable `--external-signer-arg <V>`. If any instance is
    /// supplied, the full list REPLACES `attest.external_signer_args`
    /// from config (not appended). Empty list ⇒ flag was not passed.
    ///
    /// `allow_hyphen_values` is set so users can pass values that
    /// start with `-` / `--` (e.g. `--external-signer-arg --tag`)
    /// without quoting — the hand-rolled parser this replaces
    /// accepted those literally and we preserve that.
    #[arg(
        long = "external-signer-arg",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    external_signer_args_vec: Vec<String>,
}

impl Args {
    /// Convert the raw `Vec<String>` form into `Option<Vec<…>>`:
    /// `None` means "flag was not passed; fall back to config";
    /// `Some(_)` means "flag was passed with these values".
    fn external_signer_args(&self) -> Option<Vec<String>> {
        if self.external_signer_args_vec.is_empty() {
            None
        } else {
            Some(self.external_signer_args_vec.clone())
        }
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let parsed = match clap_args::parse::<Args>("kit attest", args) {
        Ok(o) => o,
        Err(code) => return code,
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    if !layout.common_dir().is_dir() {
        return emit_err("not a kit repo", exit::GENERAL_ERROR);
    }

    let mut cfg = match crate::config::read_or_default(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // `--external-signer-arg` REPLACES `attest.external_signer_args`
    // when present. Per-invocation override, intentionally not additive
    // so a user can cleanly reproduce one signer invocation
    // without having to remember (or clobber) whatever's in config.
    if let Some(argv) = parsed.external_signer_args() {
        cfg.attest.external_signer_args = argv;
    }

    let request = match request_from(&parsed) {
        Ok(request) => request,
        Err(code) => return code,
    };
    match attestation::create(
        &layout,
        &crate::environment::current(),
        &cfg,
        &request,
        &ServedWarning,
    ) {
        Ok(created) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "attested {} → {} ({} signature(s))",
                hash_mod::to_hex(&created.id),
                created.path.display(),
                created.signatures
            );
            exit::OK
        }
        Err(e) => {
            let e = libkit::Error::from(e);
            emit_err(
                &crate::exit_map::message(&e),
                crate::exit_map::exit_code(&e),
            )
        }
    }
}

/// Turn the parsed flags into a request. A flag that does not parse gives
/// the usage exit code, before any signing starts.
fn request_from(parsed: &Args) -> Result<Request, u8> {
    let commit = match parsed.commit.as_deref() {
        Some(hex) => match hash_mod::from_hex(hex) {
            Ok(hash) => Some(hash),
            Err(e) => {
                return Err(emit_err(&format!("bad --commit hash: {e}"), exit::DATAERR));
            }
        },
        None => None,
    };
    let algorithm = parsed
        .algorithm
        .as_deref()
        .map(attest_signer::parse_algorithm)
        .transpose()
        .map_err(|e| emit_err(&e.to_string(), exit::USAGE))?;
    let signer = parsed
        .signer
        .as_deref()
        .map(str::parse::<attest_signer::Kind>)
        .transpose()
        .map_err(|e| emit_err(&e.to_string(), exit::USAGE))?;
    // Every spec is parsed before any signer is built, so a malformed spec
    // is a usage error with no crypto done.
    let additional = parsed
        .additional_signers
        .iter()
        .map(|spec| spec.parse::<SignerSpec>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| emit_err(&e.to_string(), exit::USAGE))?;
    Ok(Request {
        commit,
        algorithm,
        signer,
        predicate_type: parsed.predicate_type.clone(),
        predicate_file: parsed.predicate_file.as_deref().map(Into::into),
        additional,
    })
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Test-only adapter: drive the clap-derive parser with just the
    /// trailing args (no `kit attest` argv[0]).
    fn parse_args(args: &[String]) -> Result<Args, clap::Error> {
        let mut full: Vec<String> = vec!["kit attest".into()];
        full.extend_from_slice(args);
        Args::try_parse_from(full)
    }

    #[test]
    fn parse_args_accepts_all_flags() {
        let args = vec![
            "--commit".into(),
            "abc".into(),
            "--algorithm".into(),
            "p256".into(),
            "--signer".into(),
            "external".into(),
            "--predicate-type".into(),
            "https://example.com/p".into(),
            "--predicate-file".into(),
            "/tmp/x.json".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.commit.as_deref(), Some("abc"));
        assert_eq!(p.algorithm.as_deref(), Some("p256"));
        assert_eq!(p.signer.as_deref(), Some("external"));
        assert_eq!(p.predicate_type.as_deref(), Some("https://example.com/p"));
        assert_eq!(p.predicate_file.as_deref(), Some("/tmp/x.json"));
        assert!(p.additional_signers.is_empty());
    }

    #[test]
    fn parse_args_collects_repeatable_external_signer_args() {
        let args = vec![
            "--external-signer-arg".into(),
            "sign".into(),
            "--external-signer-arg".into(),
            "--tag".into(),
            "--external-signer-arg".into(),
            "demo".into(),
        ];
        let p = parse_args(&args).unwrap();
        let expected = vec!["sign".to_owned(), "--tag".to_owned(), "demo".to_owned()];
        assert_eq!(p.external_signer_args(), Some(expected));
    }

    #[test]
    fn parse_args_external_signer_arg_none_when_absent() {
        // Distinguishes "flag not passed" (None → fall through to config)
        // from "flag passed with no values" (impossible: the flag needs
        // a value).
        let p = parse_args(&[]).unwrap();
        assert!(p.external_signer_args().is_none());
    }

    #[test]
    fn parse_args_collects_multiple_additional_signers() {
        let args = vec![
            "--additional-signer".into(),
            "algorithm=ed25519,signer=repo-key".into(),
            "--additional-signer".into(),
            "algorithm=p256,signer=external,path=/x".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.additional_signers.len(), 2);
        assert_eq!(p.additional_signers[0], "algorithm=ed25519,signer=repo-key");
    }

    #[test]
    fn parse_args_rejects_unknown() {
        let args = vec!["--bogus".into(), "x".into()];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_all_defaults_when_empty() {
        let p = parse_args(&[]).unwrap();
        assert!(p.commit.is_none());
        assert!(p.algorithm.is_none());
        assert!(p.signer.is_none());
        assert!(p.predicate_type.is_none());
        assert!(p.predicate_file.is_none());
        assert!(p.additional_signers.is_empty());
    }
}
