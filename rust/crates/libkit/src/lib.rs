// The same attribute sits at the root of every library crate. This crate
// prints nothing.
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
//!
//! # Example
//!
//! Each module is the whole public API of its source crate.
//!
//! ```
//! use libkit::attest::Algorithm;
//! use libkit::core::hash::Hasher;
//!
//! let mut hasher = Hasher::new();
//! hasher.update(b"kit");
//! let _digest = hasher.finalize();
//! let _algorithm = Algorithm::Ed25519;
//! ```

pub mod blame;
pub mod config;
pub mod diff;
mod environment;
mod error;
pub mod head;
pub mod identity;
pub mod lock;
pub mod log;
pub mod repo;
pub mod revspec;
pub mod worktrees;

pub use environment::{CredentialSource, Environment, Identity, Token};
pub use error::Error;
pub use kit_core::observer::{NoopObserver, Observer};
pub use repo::Repo;

pub use kit_attest as attest;
pub use kit_core as core;
pub use kit_keystore as keystore;

#[cfg(feature = "git-bridge")]
#[cfg_attr(docsrs, doc(cfg(feature = "git-bridge")))]
pub use kit_git_bridge as git_bridge;

#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub use kit_sync as sync;

/// The transports that a program can opt into. Each one has its own feature.
#[cfg(any(
    feature = "transport-file",
    feature = "transport-ssh",
    feature = "transport-s3",
    feature = "transport-connect"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "transport-file",
        feature = "transport-ssh",
        feature = "transport-s3",
        feature = "transport-connect"
    )))
)]
pub mod transport {
    #[cfg(feature = "transport-connect")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transport-connect")))]
    pub use kit_transport_connect as connect;
    #[cfg(feature = "transport-file")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transport-file")))]
    pub use kit_transport_file as file;
    #[cfg(feature = "transport-s3")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transport-s3")))]
    pub use kit_transport_s3 as s3;
    #[cfg(feature = "transport-ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transport-ssh")))]
    pub use kit_transport_ssh as ssh;
}
