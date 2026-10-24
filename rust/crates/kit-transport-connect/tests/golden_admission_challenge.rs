//! The native client's vendored proto must decode the server's STC §5.1 golden.

use std::fs;
use std::path::Path;

use buffa::Message;
use kit_transport_connect::generated::AdmissionChallenge;

#[test]
fn client_decodes_admission_challenge_golden() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/transport/admission-challenge.bin");
    let message = AdmissionChallenge::decode_from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(message.challenges.len(), 2);
    assert_eq!(message.challenges[0].scheme.as_deref(), Some("challenge-a"));
    assert_eq!(
        message.challenges[0].value.as_deref(),
        Some("Admission id=\"fake-example-not-valid\", request=\"fake-example-request-not-valid\"")
    );
    assert_eq!(message.challenges[1].scheme.as_deref(), Some("challenge-b"));
    assert_eq!(
        message.challenges[1].value.as_deref(),
        Some("fake-example-admission-required-not-valid")
    );
    assert_eq!(
        message.description.as_deref(),
        Some("Example upload admission required.")
    );
}
