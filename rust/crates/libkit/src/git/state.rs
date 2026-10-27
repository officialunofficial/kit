//! The state directories of the bridge.
//!
//! A state directory is `<git state dir>/<remote name>`. [`resolve`] finds
//! the one that a command names, or the only one that exists. [`status`]
//! reads each one.

use std::path::{Path, PathBuf};

use kit_core::layout::RepoLayout;
use kit_core::refs::ATTESTATIONS_REF;
use kit_git_bridge::gitobj::{bytes_hex, sha1_hex};
use kit_git_bridge::map;

use super::{Class, Error, open_repo, plain};

/// Longest stamp file that the bridge reads. A stamp holds one short line,
/// such as a remote identity or a version number.
pub const MAX_STAMP_BYTES: u64 = 4096;

/// Read a short stamp file from a state directory.
///
/// # Errors
/// An I/O error when the file is missing, or when it is longer than
/// [`MAX_STAMP_BYTES`].
pub fn read_stamp(path: &Path) -> std::io::Result<String> {
    kit_core::bounded_read::read_capped_string(path, MAX_STAMP_BYTES)
}

/// The names of the state directories, in order.
///
/// An entry whose name starts with a dot is never a state. It is debris of a
/// `remote rename` that stopped half way, and it must not make a lookup of
/// the only state fail with "multiple bridge states".
pub(crate) fn state_names(layout: &RepoLayout) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(layout.git_state_dir()) {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && let Some(name) = entry.file_name().to_str()
                && !name.starts_with('.')
            {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names
}

/// Find the state directory that `remote_name` names. With no name, find the
/// only one.
///
/// # Errors
/// An error when the name is not valid, when the state does not exist, or
/// when no name is given and the repository has no state or more than one.
pub fn resolve(layout: &RepoLayout, remote_name: Option<&str>) -> Result<(String, PathBuf), Error> {
    if let Some(name) = remote_name {
        let state = map::state_dir(layout, name).map_err(|e| plain(Class::Usage, e))?;
        if !state.is_dir() {
            return Err(plain(
                Class::NoInput,
                format!("no bridge state for '{name}'"),
            ));
        }
        return Ok((name.to_owned(), state));
    }
    let names = state_names(layout);
    match names.as_slice() {
        [] => Err(plain(
            Class::NoInput,
            "no git bridge state (run `kit git import` or `kit git export` first)",
        )),
        [one] => Ok((one.clone(), layout.git_state_dir().join(one))),
        many => Err(plain(
            Class::Usage,
            format!(
                "multiple bridge states ({}); pick one with --remote-name",
                many.join(", ")
            ),
        )),
    }
}

/// One state directory, as `kit git status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// The remote name.
    pub name: String,
    /// The recorded direction: `import`, `export`, `fork` or `unknown`.
    pub direction: &'static str,
    /// The remote identity that the state imports from.
    pub source: Option<String>,
    /// The remote identity that the state exports to.
    pub dest: Option<String>,
    /// The first 16 hex digits of the pinned importer key.
    pub importer_key: Option<String>,
    /// The imported refs, each with the first 12 hex digits of its git id.
    pub tracking: Vec<(String, String)>,
    /// The exported refs, each with the first 12 hex digits of its git id.
    pub exported: Vec<(String, String)>,
    /// Whether the staging repository exists.
    pub staging_present: bool,
}

/// Read every state directory of the repository at `cwd`.
///
/// # Errors
/// An error when `cwd` is not inside a kit repository.
pub fn status(cwd: &Path) -> Result<Vec<State>, Error> {
    let (layout, _store) = open_repo(cwd)?;
    let mut states = Vec::new();
    for name in state_names(&layout) {
        let dir = layout.git_state_dir().join(&name);
        let direction = map::read_direction(&dir)
            .ok()
            .flatten()
            .map_or("unknown", |d| d.as_str());
        let stamp = |file: &str| {
            read_stamp(&dir.join(file))
                .ok()
                .map(|v| v.trim().to_owned())
        };
        let importer_key = match map::read_signer(&dir) {
            Ok(Some(key)) => Some(bytes_hex(&key)[..16].to_owned()),
            _ => None,
        };
        let tracking = map::load_import_ref_state(&dir)
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.ref_name, sha1_hex(&s.git_id)[..12].to_owned()))
            .collect();
        let exported = map::load_ref_state(&dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.ref_name != ATTESTATIONS_REF)
            .map(|s| (s.ref_name, sha1_hex(&s.git_id)[..12].to_owned()))
            .collect();
        states.push(State {
            direction,
            source: stamp("source"),
            dest: stamp("dest"),
            importer_key,
            tracking,
            exported,
            staging_present: dir.join("repo.git/objects").is_dir(),
            name,
        });
    }
    Ok(states)
}
