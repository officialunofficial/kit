//! The explicit inputs that a program gives to the library.

use std::fmt;
use std::path::PathBuf;

/// The name and email address that sign off new history entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The author name.
    pub name: String,
    /// The author email address.
    pub email: String,
}

/// A secret value. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Wrap a secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret value. Do not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// One place that the library may take a remote credential from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialSource {
    /// A bearer token that the program already holds.
    BearerToken(Token),
    /// A file that holds a bearer token.
    TokenFile(PathBuf),
}

/// Everything that the library would otherwise read from the process.
///
/// The library never reads environment variables, never reads or changes the
/// process working directory, and keeps no global state. The program fills
/// each field and passes the value in.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// The directory that resolves relative paths. It must be absolute.
    pub cwd: PathBuf,
    /// The home directory of the user, when the program knows one. A
    /// relative value is refused where the library needs a home directory.
    pub home: Option<PathBuf>,
    /// The XDG config directory, when the program has one. It wins over
    /// `home` for the user config. A relative value is an error.
    pub xdg_config_home: Option<PathBuf>,
    /// Configuration overrides as `(key, value)` pairs. They win over files.
    pub config_overrides: Vec<(String, String)>,
    /// The author identity, when the program knows one.
    pub identity: Option<Identity>,
    /// The credential sources, in the order that the library tries them.
    pub credentials: Vec<CredentialSource>,
}

impl Environment {
    /// An environment with `cwd` and no other input.
    #[must_use]
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_debug_hides_the_value() {
        let env = Environment {
            credentials: vec![CredentialSource::BearerToken(Token::new("s3cret"))],
            ..Environment::new("/work")
        };
        assert!(!format!("{env:?}").contains("s3cret"));
    }
}
