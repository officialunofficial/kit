//! The one place where the CLI reads the process and builds the library
//! [`libkit::Environment`].

use std::cell::RefCell;
use std::path::PathBuf;

use kit_transport_connect::TOKEN_ENV;
use libkit::{CredentialSource, Environment, Token};

/// Build the environment from the process working directory, the process
/// environment and the `-c` overrides from the command line.
///
/// A working directory that cannot be read becomes `.`, so relative paths
/// keep their meaning. The CLI has no author name or email setting, so the
/// identity stays empty.
pub(crate) fn from_process(config_overrides: Vec<(String, String)>) -> Environment {
    let credentials = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|token| !token.is_empty())
        .map(|token| CredentialSource::BearerToken(Token::new(token)))
        .into_iter()
        .collect();
    Environment {
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        home: std::env::var_os("HOME").map(PathBuf::from),
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        config_overrides,
        identity: None,
        credentials,
    }
}

thread_local! {
    /// The environment of the command that this thread runs.
    static CURRENT: RefCell<Option<Environment>> = const { RefCell::new(None) };
}

/// Make `environment` the environment of the command that this thread runs.
/// A later call replaces it.
pub(crate) fn install(environment: Environment) {
    CURRENT.with(|slot| *slot.borrow_mut() = Some(environment));
}

/// The environment of the command that this thread runs. A thread that
/// never called [`install`] gets a process environment with no `-c`
/// overrides.
pub(crate) fn current() -> Environment {
    CURRENT
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| from_process(Vec::new()))
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

    #[test]
    fn installed_environment_is_per_thread_and_replaceable() {
        let overrides = vec![("default_branch".to_owned(), "trunk".to_owned())];
        install(from_process(overrides.clone()));
        assert_eq!(current().config_overrides, overrides);
        std::thread::spawn(|| assert!(current().config_overrides.is_empty()))
            .join()
            .unwrap();
        install(from_process(Vec::new()));
        assert!(current().config_overrides.is_empty());
    }
}
