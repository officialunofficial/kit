# kit-keystore

Platform-aware signing-key vault abstraction for kit: encrypted software keys
and OS keychains. See `docs/specs/SPEC-KEYSTORE.md` for the normative backend
contract.

This crate owns keystore backends and signer handles; `kit-core` remains
independent and continues to own canonical object signing bytes.

## Backends

- `software` &mdash; the default: key records encrypted at rest. An OS key
  protector wraps the data key of each record, so reading or writing a key needs
  the `backend-macos-keychain` feature on macOS, or the
  `backend-linux-secret-service` feature and a reachable Secret Service on Linux.
- `software-raw` &mdash; a raw key file on disk, for deterministic tests. It is
  never selected by default.
- `macOS` Keychain Services, behind the `backend-macos-keychain` feature.
- The Secret Service D-Bus API (GNOME Keyring, `KWallet`), behind the
  `backend-linux-secret-service` feature.

`open_backend` fails closed for every other `BackendKind`, including
`systemd-creds` and `YubiKey`, which no build implements.

External hardware signers that don't fit a native OS keystore API (Secure
Enclave, TPM 2.0, `FIDO2`/`WebAuthn`) are driven as subprocesses instead &mdash; see
`docs/specs/SPEC-EXTERNAL-SIGNER.md`.
