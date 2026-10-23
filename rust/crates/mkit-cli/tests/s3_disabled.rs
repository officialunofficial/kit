//! Without the `s3` feature, an S3 remote fails with a message that names
//! the feature.
#![cfg(not(feature = "s3"))]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_cli::remote_dispatch::{DispatchError, open};

#[test]
fn s3_remote_needs_the_s3_feature() {
    let err = open("mkit+s3://r2.example.com/bucket/proj").err().unwrap();
    assert!(
        matches!(err, DispatchError::UnsupportedScheme(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("--features s3"), "{err}");
}
