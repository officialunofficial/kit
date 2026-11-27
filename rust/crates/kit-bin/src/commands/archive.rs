//! `kit archive` — write the tree of a revision as a tar or tar.gz
//! archive, for release builds. The archive itself is built by
//! [`libkit::archive`]; this command picks the format and the output.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use libkit::archive::{self, Error, Request};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit archive",
    about = "Write the tree of a revision as a tar or tar.gz archive."
)]
struct ArchiveOpts {
    /// `tar` or `tar.gz` (also `tgz`). The default comes from `-o`, else
    /// `tar`.
    #[arg(long, value_name = "format")]
    format: Option<String>,
    /// Text put before every path, such as `name-1.0/`.
    #[arg(long, value_name = "dir/", default_value = "")]
    prefix: String,
    /// Write the archive to this file instead of standard output.
    #[arg(short = 'o', long = "output", value_name = "file")]
    output: Option<PathBuf>,
    /// The revision, then paths to keep.
    args: Vec<String>,
}

/// The format of the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Tar,
    TarGz,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<ArchiveOpts>("kit archive", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let Some((revision, raw_paths)) = opts.args.split_first() else {
        return super::usage_error(
            "usage: kit archive [--format=<f>] [--prefix=<dir>/] [-o <file>] <tree-ish> [<path>...]",
        );
    };
    let format = match format_of(opts.format.as_deref(), opts.output.as_deref()) {
        Ok(f) => f,
        Err(msg) => return super::usage_error(&msg),
    };
    if opts.output.is_none() && std::io::stdout().is_terminal() {
        return super::usage_error("refusing to write an archive to a terminal; use -o <file>");
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let root = repo.layout().worktree_root();
    let mut paths = Vec::with_capacity(raw_paths.len());
    for raw in raw_paths {
        match super::index_path_for_arg(root, &cwd.join(raw)) {
            Ok(p) => paths.push(p),
            Err(e) => return super::usage_error(&format!("{raw}: {e}")),
        }
    }
    let request = Request {
        revision,
        prefix: &opts.prefix,
        paths: &paths,
    };
    let result = if let Some(path) = &opts.output {
        to_file(&repo, &request, format, path)
    } else {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        write_format(&repo, &request, format, &mut out)
    };
    match result {
        Ok(()) => exit::OK,
        Err(e) => super::error(&e.to_string(), code_of(&e)),
    }
}

/// The format from `--format`, else from the extension of `-o`, else tar.
fn format_of(flag: Option<&str>, output: Option<&Path>) -> Result<Format, String> {
    match flag {
        Some("tar") => return Ok(Format::Tar),
        Some("tar.gz" | "tgz") => return Ok(Format::TarGz),
        Some(other) => {
            return Err(format!(
                "unknown archive format '{other}'; use tar or tar.gz"
            ));
        }
        None => {}
    }
    let Some(path) = output else {
        return Ok(Format::Tar);
    };
    let name = path.to_string_lossy();
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Ok(Format::TarGz)
    } else if name.ends_with(".tar") {
        Ok(Format::Tar)
    } else {
        Err(format!(
            "cannot tell the format of '{name}'; name it .tar, .tar.gz or .tgz, or use --format"
        ))
    }
}

/// Write the archive to `path` through a temporary file beside it, so a
/// failed run leaves no partial archive.
fn to_file(
    repo: &libkit::Repo,
    request: &Request<'_>,
    format: Format,
    path: &Path,
) -> Result<(), Error> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(format!(".kit-tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp_name);
    let result = (|| {
        let file = std::fs::File::create(&tmp)?;
        let mut out = std::io::BufWriter::new(file);
        write_format(repo, request, format, &mut out)?;
        out.into_inner()
            .map_err(std::io::IntoInnerError::into_error)?
            .sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Write the archive in `format` to `out`.
fn write_format(
    repo: &libkit::Repo,
    request: &Request<'_>,
    format: Format,
    out: &mut dyn Write,
) -> Result<(), Error> {
    match format {
        Format::Tar => {
            archive::write(repo, request, out)?;
        }
        Format::TarGz => {
            // mtime 0, no file name and an unknown OS, so the bytes do not
            // depend on the machine or the time of the run.
            let mut gz = flate2::GzBuilder::new()
                .mtime(0)
                .operating_system(255)
                .write(out, flate2::Compression::default());
            archive::write(repo, request, &mut gz)?;
            gz.try_finish()?;
        }
    }
    Ok(())
}

/// The exit code of an error.
fn code_of(e: &Error) -> u8 {
    match e {
        Error::BadRevision { .. }
        | Error::NotATree(_)
        | Error::BadPrefix(_)
        | Error::NoMatch(_) => exit::USAGE,
        Error::Io(_) => exit::IOERR,
        _ => exit::DATAERR,
    }
}
