//! The one place where the CLI reads the process and builds the library
//! [`libkit::Environment`].

use std::path::PathBuf;

use libkit::{CredentialSource, Environment, Token};

/// Environment variable that holds the bearer token for HTTP(S) remotes.
const API_TOKEN_VAR: &str = "KIT_API_TOKEN";

/// Build the environment from the process working directory, the process
/// environment and the `-c` overrides from the command line.
///
/// A working directory that cannot be read becomes `.`, so relative paths
/// keep their meaning. The CLI has no author name or email setting, so the
/// identity stays empty.
pub(crate) fn from_process(config_overrides: Vec<(String, String)>) -> Environment {
    let credentials = std::env::var(API_TOKEN_VAR)
        .ok()
        .filter(|token| !token.is_empty())
        .map(|token| CredentialSource::BearerToken(Token::new(token)))
        .into_iter()
        .collect();
    Environment {
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        home: std::env::var_os("HOME").map(PathBuf::from),
        config_overrides,
        identity: None,
        credentials,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_pass_through_unchanged() {
        let overrides = vec![("default_branch".to_owned(), "trunk".to_owned())];
        let environment = from_process(overrides.clone());
        assert_eq!(environment.config_overrides, overrides);
        assert!(environment.identity.is_none());
    }
}
