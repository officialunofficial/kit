//! The CLI side of signer construction.
//!
//! The rules live in [`libkit::attest_signer`]. This module binds them to the
//! environment of the current command and takes the signer kind as text,
//! the way `kit git` passes it.

use kit_attest::{Algorithm, Signer};
use kit_core::layout::RepoLayout;
pub use libkit::attest_signer::Error as FactoryError;
pub use libkit::attest_signer::parse_algorithm;

use crate::config::Config;

/// Build a signer. `signer_kind` is `repo-key`, `external` or `keystore`.
pub fn build_signer(
    layout: &RepoLayout,
    algorithm: Algorithm,
    signer_kind: &str,
    cfg: &Config,
) -> Result<Box<dyn Signer>, FactoryError> {
    libkit::attest_signer::build(
        layout,
        &crate::environment::current(),
        algorithm,
        signer_kind.parse()?,
        cfg,
    )
}
