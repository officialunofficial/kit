//! Turning command-line spellings into the canonical statements of
//! SPEC-WRITE-GRANTS §3, §5.1 and §9.1.
//!
//! The statement codecs in `kit-attest` never sort or repair, so this
//! module does the canonicalizing a person expects: `--cap write,read` becomes
//! `read,write`, audiences and ref scopes are sorted and deduplicated, and ref
//! flags are put in `cufd` order.
//!
//! The text of an [`Error`] names the command-line spelling that produced it,
//! because the spellings are the input of this module.

use kit_attest::grant::text::encode_audiences;
use kit_attest::grant::{
    Capabilities, EpochStatement, Grant, GrantError, MAX_AUDIENCES, MAX_REF_SCOPES, Namespace,
    RefFlags, RefPattern, RefScopes, RepoScope, RepositoryIdentity, Visibility,
    VisibilityStatement,
};
use kit_core::repo_identity::IdentityError;

/// Errors from reading a spelling or building a statement.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The duration is empty.
    #[error("empty duration")]
    EmptyDuration,
    /// The duration is not a number with an optional unit.
    #[error("`{0}` is not a duration (use 30d, 12h, 90m or 3600s)")]
    BadDuration(String),
    /// The duration is zero or overflows.
    #[error("`{0}` is not a positive duration")]
    NotPositiveDuration(String),
    /// The duration is longer than a grant may live.
    #[error("`{0}` exceeds the 30-day maximum grant lifetime (SPEC-WRITE-GRANTS §1.1)")]
    DurationTooLong(String),
    /// The duration does not fit the millisecond count.
    #[error("duration out of range")]
    DurationOutOfRange,
    /// A capability is neither `read` nor `write`.
    #[error("capability `{0}` is not `read` or `write` (use --cap read, read,write or write)")]
    Capability(String),
    /// No audience, or more than the statement holds.
    #[error("expected 1 to {MAX_AUDIENCES} audiences")]
    AudienceCount,
    /// An audience breaks the origin rules.
    #[error("audience `{audience}`: {source}")]
    Audience {
        /// The audience.
        audience: String,
        /// The rule that failed.
        source: GrantError,
    },
    /// A ref scope has no `=`.
    #[error("--refs `{0}` must be `pattern=flags` (flags from cufd)")]
    RefScopeForm(String),
    /// The pattern of a ref scope is malformed.
    #[error("--refs `{item}`: {source}")]
    RefPattern {
        /// The ref scope.
        item: String,
        /// The rule that failed.
        source: GrantError,
    },
    /// A flag of a ref scope is not one of `c`, `u`, `f` and `d`.
    #[error("--refs `{item}`: flag `{flag}` is not one of c, u, f, d")]
    RefFlag {
        /// The ref scope.
        item: String,
        /// The flag.
        flag: char,
    },
    /// A ref scope has no flags.
    #[error("--refs `{0}`: no flags")]
    RefNoFlags(String),
    /// More ref scopes than a statement holds.
    #[error("at most {MAX_REF_SCOPES} ref scopes")]
    RefScopeCount,
    /// The merged ref scopes break a rule.
    #[error("--refs: {0}")]
    RefScopes(GrantError),
    /// A read-only grant has ref scopes.
    #[error(
        "a read-only grant takes no --refs (ref scopes apply to writes; SPEC-WRITE-GRANTS §3.3)"
    )]
    ReadWithRefScopes,
    /// A grant with write has no ref scopes.
    #[error(
        "a grant with write needs at least one --refs pattern=flags (for example --refs 'refs/heads/*=cuf')"
    )]
    WriteWithoutRefScopes,
    /// The repository name is malformed.
    #[error("--repo `{name}`: {source}")]
    Repository {
        /// The name.
        name: String,
        /// The rule that failed.
        source: IdentityError,
    },
    /// The lifetime overflows the expiry time.
    #[error("lifetime out of range")]
    LifetimeOutOfRange,
    /// The system has no entropy for the nonce.
    #[error("no entropy for the statement nonce: {0}")]
    NoEntropy(getrandom::Error),
}

/// Longest lifetime `--ttl` accepts (§1.1): 30 days.
pub const MAX_TTL_SECS: u64 = 2_592_000;
/// Default `--ttl` of a grant.
pub const DEFAULT_GRANT_TTL: &str = "7d";
/// Default lifetime of an epoch or visibility statement. Short on purpose:
/// the statement is signed for one command, and a shorter window narrows what
/// a leaked statement can do.
pub const DEFAULT_STATEMENT_TTL_MS: i64 = 10 * 60 * 1000;

/// Slack on top of `--timeout` so the last re-send still lands before expiry.
const STATEMENT_SLACK_MS: i64 = 2 * 60 * 1000;

/// How long an epoch or visibility statement stays valid: the default, or,
/// when the command will wait longer than that for the server, the wait plus a
/// little slack, so a re-send late in a long `--timeout` is not rejected as
/// expired. Never above the 30-day statement maximum.
#[must_use]
pub fn statement_lifetime_ms(wait: std::time::Duration) -> i64 {
    let wait_ms = i64::try_from(wait.as_millis()).unwrap_or(i64::MAX);
    wait_ms
        .saturating_add(STATEMENT_SLACK_MS)
        .clamp(DEFAULT_STATEMENT_TTL_MS, MAX_TTL_SECS.cast_signed() * 1000)
}

/// `30d`, `12h`, `90m`, `3600s`, or bare seconds; at most 30 days. Returns
/// milliseconds.
///
/// # Errors
/// An unparsable, zero or too-long duration.
pub fn parse_ttl(text: &str) -> Result<i64, Error> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, 'd')) => (&text[..i], 86_400),
        Some((i, 'h')) => (&text[..i], 3_600),
        Some((i, 'm')) => (&text[..i], 60),
        Some((i, 's')) => (&text[..i], 1),
        Some(_) => (text, 1),
        None => return Err(Error::EmptyDuration),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| Error::BadDuration(text.to_owned()))?;
    let seconds = value
        .checked_mul(unit)
        .filter(|s| *s > 0)
        .ok_or_else(|| Error::NotPositiveDuration(text.to_owned()))?;
    if seconds > MAX_TTL_SECS {
        return Err(Error::DurationTooLong(text.to_owned()));
    }
    i64::try_from(seconds * 1000).map_err(|_| Error::DurationOutOfRange)
}

/// Accept `read`, `write` or both in either order, and spell them
/// canonically (§3.2): `read`, `read,write` or `write`.
///
/// # Errors
/// Anything but a non-empty set of `read` and `write`.
pub fn canonical_capabilities(text: &str) -> Result<Capabilities, Error> {
    let (mut read, mut write) = (false, false);
    for part in text.split(',') {
        match part.trim() {
            "read" => read = true,
            "write" => write = true,
            other => return Err(Error::Capability(other.to_owned())),
        }
    }
    Ok(match (read, write) {
        (true, true) => Capabilities::ReadWrite,
        (true, false) => Capabilities::Read,
        _ => Capabilities::Write,
    })
}

/// Sort and deduplicate audiences, and check each against §3.2.
///
/// # Errors
/// An audience outside the auth v2 origin rules, or a count outside 1–8.
pub fn canonical_audiences(items: &[String]) -> Result<Vec<String>, Error> {
    let mut out: Vec<String> = items.iter().map(|a| a.trim().to_owned()).collect();
    out.sort();
    out.dedup();
    if out.is_empty() || out.len() > MAX_AUDIENCES {
        return Err(Error::AudienceCount);
    }
    for audience in &out {
        encode_audiences(std::slice::from_ref(audience)).map_err(|source| Error::Audience {
            audience: audience.clone(),
            source,
        })?;
    }
    Ok(out)
}

/// Parse `pattern=flags` entries, put the flags in `cufd` order, merge
/// entries with the same pattern (a union, which is what §8.1 computes anyway)
/// and sort.
///
/// # Errors
/// A malformed pattern or flag, or more than 16 distinct patterns.
pub fn canonical_ref_scopes(items: &[String]) -> Result<RefScopes, Error> {
    let mut merged: Vec<(RefPattern, RefFlags)> = Vec::new();
    for item in items {
        let (pattern, flags) = item
            .split_once('=')
            .ok_or_else(|| Error::RefScopeForm(item.clone()))?;
        let pattern = RefPattern::parse(pattern).map_err(|source| Error::RefPattern {
            item: item.clone(),
            source,
        })?;
        let mut set = RefFlags::EMPTY;
        for c in flags.chars() {
            set = set.union(match c {
                'c' => RefFlags::CREATE,
                'u' => RefFlags::UPDATE,
                'f' => RefFlags::FORCE,
                'd' => RefFlags::DELETE,
                flag => {
                    return Err(Error::RefFlag {
                        item: item.clone(),
                        flag,
                    });
                }
            });
        }
        if set.is_empty() {
            return Err(Error::RefNoFlags(item.clone()));
        }
        match merged.iter_mut().find(|(p, _)| *p == pattern) {
            Some((_, existing)) => *existing = existing.union(set),
            None => merged.push((pattern, set)),
        }
    }
    merged.sort_by_key(|(pattern, flags)| format!("{pattern}={flags}"));
    if merged.len() > MAX_REF_SCOPES {
        return Err(Error::RefScopeCount);
    }
    RefScopes::new(merged).map_err(Error::RefScopes)
}

/// The repositories a new grant covers.
#[derive(Debug, Clone)]
pub enum RepoSelector {
    /// One repository of the namespace.
    Name(String),
    /// Every repository of the namespace.
    All,
}

/// Everything `kit grant create` collects before the owner is known.
#[derive(Debug, Clone)]
pub struct GrantSpec {
    /// The repositories that the grant covers.
    pub repo: RepoSelector,
    /// The public key of the grantee.
    pub grantee: [u8; 32],
    /// What the grant allows.
    pub capabilities: Capabilities,
    /// The audiences, as [`canonical_audiences`] returns them.
    pub audiences: Vec<String>,
    /// The ref scopes, as [`canonical_ref_scopes`] returns them.
    pub ref_scopes: Option<RefScopes>,
    /// The epoch of the namespace.
    pub epoch: u64,
    /// The lifetime in milliseconds, as [`parse_ttl`] returns it.
    pub ttl_ms: i64,
}

fn nonce() -> Result<[u8; 32], Error> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(Error::NoEntropy)?;
    Ok(nonce)
}

/// §3.3: ref scopes go with write and only with write.
///
/// # Errors
/// A read-only grant with `--refs`, or a write grant without.
pub fn check_ref_scopes(
    capabilities: Capabilities,
    ref_scopes: Option<&RefScopes>,
) -> Result<(), Error> {
    match (capabilities, ref_scopes) {
        (Capabilities::Read, Some(_)) => Err(Error::ReadWithRefScopes),
        (Capabilities::ReadWrite | Capabilities::Write, None) => Err(Error::WriteWithoutRefScopes),
        _ => Ok(()),
    }
}

/// Build the grant for `namespace`, created at `now_ms`.
///
/// # Errors
/// A scope, ref-scope or lifetime the statement rules refuse.
pub fn build_grant(spec: &GrantSpec, namespace: &Namespace, now_ms: i64) -> Result<Grant, Error> {
    let scope = match &spec.repo {
        RepoSelector::All => RepoScope::Namespace,
        RepoSelector::Name(name) => RepoScope::Repository(
            RepositoryIdentity::parse(&format!("{namespace}/{name}")).map_err(|source| {
                Error::Repository {
                    name: name.clone(),
                    source,
                }
            })?,
        ),
    };
    check_ref_scopes(spec.capabilities, spec.ref_scopes.as_ref())?;
    Ok(Grant {
        namespace: *namespace,
        scope,
        grantee: spec.grantee,
        capabilities: spec.capabilities,
        audiences: spec.audiences.clone(),
        ref_scopes: spec.ref_scopes.clone(),
        epoch: spec.epoch,
        created_ms: now_ms,
        expiry_ms: now_ms
            .checked_add(spec.ttl_ms)
            .ok_or(Error::LifetimeOutOfRange)?,
        nonce: nonce()?,
    })
}

/// Build an epoch statement raising `namespace` to `new_epoch`.
///
/// # Errors
/// No entropy for the nonce.
pub fn build_epoch(
    namespace: &Namespace,
    new_epoch: u64,
    audiences: &[String],
    now_ms: i64,
    lifetime_ms: i64,
) -> Result<EpochStatement, Error> {
    Ok(EpochStatement {
        namespace: *namespace,
        new_epoch,
        audiences: audiences.to_vec(),
        created_ms: now_ms,
        expiry_ms: now_ms.saturating_add(lifetime_ms),
        nonce: nonce()?,
    })
}

/// Build a visibility statement for `repository`.
///
/// # Errors
/// No entropy for the nonce.
pub fn build_visibility(
    repository: &RepositoryIdentity,
    visibility: Visibility,
    audiences: &[String],
    now_ms: i64,
    lifetime_ms: i64,
) -> Result<VisibilityStatement, Error> {
    Ok(VisibilityStatement {
        repository: repository.clone(),
        visibility,
        audiences: audiences.to_vec(),
        created_ms: now_ms,
        expiry_ms: now_ms.saturating_add(lifetime_ms),
        nonce: nonce()?,
    })
}

/// A statement the codec refused, phrased for a person.
#[must_use]
pub fn statement_error(error: GrantError) -> String {
    format!("invalid statement: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_canonicalized() {
        for (input, want) in [
            ("read", Capabilities::Read),
            ("write", Capabilities::Write),
            ("read,write", Capabilities::ReadWrite),
            ("write,read", Capabilities::ReadWrite),
            ("write, read", Capabilities::ReadWrite),
            ("read,read", Capabilities::Read),
        ] {
            assert_eq!(canonical_capabilities(input).unwrap(), want, "{input}");
        }
        for bad in ["", "admin", "read;write", "read,"] {
            assert!(canonical_capabilities(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            canonical_capabilities("write,read").unwrap().token(),
            "read,write"
        );
    }

    #[test]
    fn audiences_are_sorted_deduped_and_bounded() {
        let got = canonical_audiences(&[
            "https://b.example.com".to_owned(),
            "https://a.example.com".to_owned(),
            "https://b.example.com".to_owned(),
        ])
        .unwrap();
        assert_eq!(got, ["https://a.example.com", "https://b.example.com"]);
        assert!(canonical_audiences(&[]).is_err());
        assert!(canonical_audiences(&["https://*.example.com".to_owned()]).is_err());
        assert!(canonical_audiences(&["git.example.com".to_owned()]).is_err());
        let nine: Vec<String> = (0..9)
            .map(|i| format!("https://h{i}.example.com"))
            .collect();
        assert!(canonical_audiences(&nine).is_err());
    }

    #[test]
    fn ref_scopes_are_sorted_merged_and_flag_ordered() {
        let scopes = canonical_ref_scopes(&[
            "refs/heads/wip/*=dfuc".to_owned(),
            "refs/heads/main=u".to_owned(),
            "refs/heads/main=c".to_owned(),
        ])
        .unwrap();
        let text = scopes
            .entries()
            .iter()
            .map(|(p, f)| format!("{p}={f}"))
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(text, "refs/heads/main=cu;refs/heads/wip/*=cufd");
        for bad in [
            "refs/heads/main",
            "refs/heads/main=x",
            "refs/heads/main=",
            "*=c",
        ] {
            assert!(canonical_ref_scopes(&[bad.to_owned()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn statement_lifetime_covers_the_wait_and_stays_in_bounds() {
        use std::time::Duration;
        assert_eq!(
            statement_lifetime_ms(Duration::from_secs(5)),
            DEFAULT_STATEMENT_TTL_MS
        );
        assert_eq!(
            statement_lifetime_ms(Duration::from_mins(5)),
            DEFAULT_STATEMENT_TTL_MS
        );
        // A 30 minute wait needs a statement that outlives it.
        assert_eq!(
            statement_lifetime_ms(Duration::from_mins(30)),
            32 * 60 * 1000
        );
        assert_eq!(
            statement_lifetime_ms(Duration::from_secs(u64::MAX / 4)),
            2_592_000_000
        );
    }

    #[test]
    fn ttl_parses_units_and_enforces_the_bound() {
        assert_eq!(parse_ttl("30d").unwrap(), 2_592_000_000);
        assert_eq!(parse_ttl("12h").unwrap(), 43_200_000);
        assert_eq!(parse_ttl("90m").unwrap(), 5_400_000);
        assert_eq!(parse_ttl("3600s").unwrap(), 3_600_000);
        assert_eq!(parse_ttl("60").unwrap(), 60_000);
        assert!(parse_ttl("31d").is_err());
        assert!(parse_ttl("0d").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("abc").is_err());
    }
}
