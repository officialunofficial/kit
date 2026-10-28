//! The credential-trust gate.
//!
//! A repository can choose the endpoint of a remote in its own config. A
//! credential-bearing transport must not go to such an endpoint unless the
//! user trusts it in the user config. Trust belongs to the endpoint, never to
//! the name of the remote. The gate runs before any transport exists.

use kit_transport_connect::TOKEN_ENV;

use super::Error;

/// Refuse `endpoint` when an ambient credential would reach an endpoint that
/// the repository chose and the user has not trusted.
///
/// * `repo_chosen` says whether the repo-scoped config selected the endpoint.
///   A user-chosen endpoint is the decision of the user, so the gate lets it
///   pass.
/// * `user_trusted` is `trusted_remote_endpoint` from the user config.
/// * `config_display` names the user config file in the advice.
/// * `getenv` reads the credential variables. An empty value counts as absent.
///
/// # Errors
/// [`Error::UntrustedRemote`] with the advice to trust the endpoint.
pub fn check_endpoint(
    endpoint: &str,
    repo_chosen: bool,
    user_trusted: &str,
    config_display: &str,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<(), Error> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || !repo_chosen || user_trusted.trim() == endpoint {
        return Ok(());
    }

    if endpoint.starts_with("kit+http://") || endpoint.starts_with("kit+https://") {
        if getenv(TOKEN_ENV).is_some() {
            return Err(Error::UntrustedRemote(format!(
                "refusing repo-configured remote `{endpoint}` with ambient {TOKEN_ENV} bearer token; trust it explicitly with `kit config trusted_remote_endpoint {endpoint}` (writes {config_display})"
            )));
        }
        return Ok(());
    }

    #[cfg(feature = "transport-s3")]
    if endpoint.starts_with("kit+s3://")
        && (getenv(kit_transport_s3::ENV_ACCESS_KEY).is_some()
            || getenv(kit_transport_s3::ENV_SECRET_KEY).is_some())
    {
        return Err(Error::UntrustedRemote(format!(
            "refusing repo-configured remote `{endpoint}` with ambient S3 credentials; trust it explicitly with `kit config trusted_remote_endpoint {endpoint}` (writes {config_display})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "/home/u/.config/kit/config";

    fn with_token(name: &str) -> Option<String> {
        (name == TOKEN_ENV).then(|| "s3cr3t-value".to_owned())
    }

    fn check(endpoint: &str, repo_chosen: bool, trusted: &str) -> Result<(), Error> {
        check_endpoint(endpoint, repo_chosen, trusted, CONFIG, &with_token)
    }

    #[test]
    fn repo_http_remote_with_token_requires_user_trust() {
        let Err(Error::UntrustedRemote(message)) =
            check("kit+https://example.invalid/repo", true, "")
        else {
            panic!("a repo-scoped HTTP remote with a token must be refused");
        };
        assert!(message.contains("trusted_remote_endpoint"), "{message}");
        assert!(message.contains(CONFIG), "{message}");
        assert!(
            !message.contains("s3cr3t-value"),
            "no secret in the advice: {message}"
        );
    }

    #[test]
    fn trusted_http_remote_is_allowed() {
        assert!(
            check(
                "kit+https://example.invalid/repo",
                true,
                "kit+https://example.invalid/repo"
            )
            .is_ok()
        );
    }

    #[test]
    fn the_gate_keys_on_provenance_not_on_the_credential() {
        let endpoint = "kit+https://example.invalid/repo";
        assert!(check(endpoint, false, "").is_ok());
        assert!(check(endpoint, true, "").is_err());
    }

    #[test]
    fn an_endpoint_without_an_ambient_credential_is_allowed() {
        let none = |_: &str| None;
        assert!(
            check_endpoint("kit+https://example.invalid/repo", true, "", CONFIG, &none).is_ok()
        );
    }

    #[test]
    fn spaces_around_the_endpoint_and_the_trust_do_not_matter() {
        assert!(
            check(
                " kit+https://example.invalid/repo ",
                true,
                "kit+https://example.invalid/repo\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn ssh_and_file_endpoints_bypass_the_gate() {
        let all = |_: &str| Some("present".to_owned());
        for endpoint in ["kit+ssh://host/path", "kit+file:///srv/mirror"] {
            assert!(check_endpoint(endpoint, true, "", CONFIG, &all).is_ok());
        }
    }

    #[cfg(feature = "transport-s3")]
    #[test]
    fn repo_s3_remote_with_env_credentials_requires_user_trust() {
        let keys =
            |name: &str| (name == kit_transport_s3::ENV_ACCESS_KEY).then(|| "AKIA".to_owned());
        let Err(Error::UntrustedRemote(message)) = check_endpoint(
            "kit+s3://s3.example.com/bucket/proj",
            true,
            "",
            CONFIG,
            &keys,
        ) else {
            panic!("a repo-scoped S3 remote with credentials must be refused");
        };
        assert!(message.contains("trusted_remote_endpoint"), "{message}");
        assert!(
            !message.contains("AKIA"),
            "no secret in the advice: {message}"
        );
    }
}
