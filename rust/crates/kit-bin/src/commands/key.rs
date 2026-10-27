//! `kit key` keystore management commands.

use std::io::Write as _;
use std::path::Path;

use clap::{Parser, Subcommand};
use kit_keystore::{Algorithm, Capabilities, KeyAttrs};
use libkit::keys;

use crate::clap_args;
use crate::config::{self, Config};
use crate::exit;

#[derive(Debug, Parser)]
#[command(name = "kit key", about = "Manage keystore signing keys.")]
struct KeyOpts {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate a new signing key.
    Generate(GenerateOpts),
    /// List keys visible to a backend.
    List(ListOpts),
    /// Import 32-byte signing key material.
    Import(ImportOpts),
    /// Export extractable signing key material.
    Export(ExportOpts),
    /// Delete exactly one signing key.
    Delete(DeleteOpts),
}

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
struct GenerateOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long, conflicts_with = "non_extractable")]
    extractable: bool,
    #[arg(long, conflicts_with = "extractable")]
    non_extractable: bool,
    #[arg(long)]
    device_bound: bool,
    #[arg(long)]
    require_user_presence: bool,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    print_pubkey: bool,
}

#[derive(Debug, Parser)]
struct ListOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
struct ImportOpts {
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "HEX")]
    hex: Option<String>,
    #[arg(long, value_name = "PATH")]
    file: Option<String>,
    #[arg(long, conflicts_with = "non_extractable")]
    extractable: bool,
    #[arg(long, conflicts_with = "extractable")]
    non_extractable: bool,
    #[arg(long)]
    device_bound: bool,
    #[arg(long)]
    require_user_presence: bool,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Parser)]
struct ExportOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long)]
    unsafe_print_secret: bool,
}

#[derive(Debug, Parser)]
struct DeleteOpts {
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    #[arg(long, value_name = "LABEL")]
    label: Option<String>,
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<KeyOpts>("kit key", args) {
        Ok(opts) => opts,
        Err(code) => return code,
    };
    match opts.command {
        KeyCommand::Generate(opts) => generate(opts),
        KeyCommand::List(opts) => list(&opts),
        KeyCommand::Import(opts) => import(opts),
        KeyCommand::Export(opts) => export(opts),
        KeyCommand::Delete(opts) => delete(opts),
    }
}

fn generate(opts: GenerateOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm_or_default(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };

    let attrs = attrs_from_flags(
        opts.extractable,
        opts.non_extractable,
        opts.device_bound,
        opts.require_user_presence,
    );
    let selection = match keys::select(&cfg, opts.backend.as_deref(), opts.label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(error) => return key_error(error),
    };
    let store = match keys::open(selection.backend) {
        Ok(store) => store,
        Err(error) => return key_error(error),
    };
    let metadata = match keys::generate(&*store, &selection.label, algorithm, attrs, opts.force) {
        Ok(metadata) => metadata,
        Err(error) => return key_error(error),
    };
    print_metadata(&metadata);
    print_capabilities(&store.capabilities());
    if opts.print_pubkey {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", metadata.keyid());
    }
    exit::OK
}

fn list(opts: &ListOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let backend = match keys::backend(&cfg, opts.backend.as_deref()) {
        Ok(backend) => backend,
        Err(error) => return key_error(error),
    };
    let store = match keys::open(backend) {
        Ok(store) => store,
        Err(error) => return key_error(error),
    };
    let listed = match keys::list(&*store) {
        Ok(listed) => listed,
        Err(error) => return key_error(error),
    };
    let capabilities = store.capabilities();
    let mut stdout = std::io::stdout().lock();
    if opts.json {
        let _ = write!(stdout, "[");
        for (index, key) in listed.iter().enumerate() {
            if index > 0 {
                let _ = write!(stdout, ",");
            }
            let _ = write!(
                stdout,
                "{{\"backend\":\"{}\",\"label\":\"{}\",\"algorithm\":\"{}\",\"keyid\":\"{}\",\"extractable\":{},\"require_user_presence\":{},\"device_bound\":{},\"capabilities\":{}}}",
                key.backend(),
                json_escape(key.label()),
                key.algorithm(),
                json_escape(key.keyid()),
                key.extractable,
                key.require_user_presence,
                key.device_bound,
                json_capabilities(&capabilities)
            );
        }
        let _ = writeln!(stdout, "]");
    } else {
        for key in listed {
            let _ = writeln!(
                stdout,
                "{} {} {} {} extractable={} user_presence={} device_bound={} can_generate={} can_import={} can_export={} can_delete={} supports_listing={} supports_user_presence={} supports_device_bound={} supports_non_extractable={}",
                key.backend(),
                key.label(),
                key.algorithm(),
                key.keyid(),
                key.extractable,
                key.require_user_presence,
                key.device_bound,
                capabilities.can_generate,
                capabilities.can_import,
                capabilities.can_export,
                capabilities.can_delete,
                capabilities.supports_listing,
                capabilities.supports_user_presence,
                capabilities.supports_device_bound,
                capabilities.supports_non_extractable
            );
        }
    }
    exit::OK
}

fn import(opts: ImportOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let Some(algorithm) = opts.algorithm.as_deref() else {
        return emit_err("kit key import requires --algorithm", exit::USAGE);
    };
    let algorithm = match parse_algorithm(algorithm) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if opts.hex.is_some() == opts.file.is_some() {
        return emit_err(
            "kit key import requires exactly one of --hex or --file",
            exit::USAGE,
        );
    }
    let attrs = attrs_from_flags(
        opts.extractable,
        opts.non_extractable,
        opts.device_bound,
        opts.require_user_presence,
    );
    let selection = match keys::select(&cfg, opts.backend.as_deref(), opts.label, Some(algorithm)) {
        Ok(selection) => selection,
        Err(error) => return key_error(error),
    };
    let secret = match (opts.hex, opts.file) {
        (Some(hex), None) => keys::parse_secret_hex(algorithm, &hex),
        (None, Some(file)) => keys::read_secret_file(algorithm, Path::new(&file)),
        _ => unreachable!(),
    };
    let secret = match secret {
        Ok(secret) => secret,
        Err(error) => return key_error(error),
    };
    let store = match keys::open(selection.backend) {
        Ok(store) => store,
        Err(error) => return key_error(error),
    };
    match keys::import(&*store, &selection.label, secret, attrs, opts.force) {
        Ok(metadata) => {
            print_metadata(&metadata);
            exit::OK
        }
        Err(error) => key_error(error),
    }
}

fn export(opts: ExportOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if !opts.unsafe_print_secret {
        return emit_err("kit key export requires --unsafe-print-secret", exit::USAGE);
    }
    let selection = match keys::select(&cfg, opts.backend.as_deref(), opts.label, algorithm) {
        Ok(selection) => selection,
        Err(error) => return key_error(error),
    };
    let store = match keys::open(selection.backend) {
        Ok(store) => store,
        Err(error) => return key_error(error),
    };
    let secret = match keys::export(&*store, selection.label, algorithm) {
        Ok(secret) => secret,
        Err(error) => return key_error(error),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "warning: printing secret key material to stdout");
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{}", hex_lower(secret.expose_secret())) {
        return emit_err(&format!("write exported secret: {error}"), exit::CANTCREAT);
    }
    exit::OK
}

fn delete(opts: DeleteOpts) -> u8 {
    let cfg = match read_config() {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let algorithm = match optional_algorithm(opts.algorithm.as_deref()) {
        Ok(algorithm) => algorithm,
        Err(code) => return code,
    };
    if !opts.yes {
        return emit_err("kit key delete requires --yes", exit::USAGE);
    }
    let selection = match keys::select(&cfg, opts.backend.as_deref(), opts.label, algorithm) {
        Ok(selection) => selection,
        Err(error) => return key_error(error),
    };
    let store = match keys::open(selection.backend) {
        Ok(store) => store,
        Err(error) => return key_error(error),
    };
    match keys::delete(&*store, selection.label.clone(), algorithm) {
        Ok(()) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "deleted {}:{}", selection.backend, selection.label);
            exit::OK
        }
        Err(error) => key_error(error),
    }
}

fn read_config() -> Result<Config, u8> {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => return Err(emit_err(&format!("cwd: {error}"), exit::NOINPUT)),
    };
    let layout = super::resolve_layout(&cwd)?;
    config::read_or_default(&layout)
        .map_err(|error| emit_err(&format!("config: {error}"), exit::CONFIG_ERROR))
}

fn parse_algorithm(value: &str) -> Result<Algorithm, u8> {
    value
        .parse()
        .map_err(|error| emit_err(&format!("algorithm: {error}"), exit::USAGE))
}

fn optional_algorithm(value: Option<&str>) -> Result<Option<Algorithm>, u8> {
    value.map(parse_algorithm).transpose()
}

fn optional_algorithm_or_default(value: Option<&str>) -> Result<Algorithm, u8> {
    match optional_algorithm(value)? {
        Some(algorithm) => Ok(algorithm),
        None => Ok(Algorithm::Ed25519),
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn attrs_from_flags(
    extractable: bool,
    non_extractable: bool,
    device_bound: bool,
    require_user_presence: bool,
) -> KeyAttrs {
    let mut attrs = KeyAttrs::default();
    if extractable {
        attrs.extractable = true;
    }
    if non_extractable {
        attrs.extractable = false;
    }
    attrs.device_bound = device_bound;
    attrs.require_user_presence = require_user_presence;
    attrs
}

fn print_metadata(metadata: &kit_keystore::KeyMetadata) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "backend = {}", metadata.backend());
    let _ = writeln!(stdout, "label = {}", metadata.label());
    let _ = writeln!(stdout, "algorithm = {}", metadata.algorithm());
    let _ = writeln!(stdout, "public_key = {}", hex_lower(metadata.public_key()));
    let _ = writeln!(stdout, "keyid = {}", metadata.keyid());
    let _ = writeln!(stdout, "extractable = {}", metadata.extractable);
    let _ = writeln!(
        stdout,
        "require_user_presence = {}",
        metadata.require_user_presence
    );
    let _ = writeln!(stdout, "device_bound = {}", metadata.device_bound);
}

fn print_capabilities(capabilities: &Capabilities) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "capabilities.backend = {}", capabilities.backend);
    let _ = writeln!(
        stdout,
        "capabilities.algorithms = {}",
        algorithms_csv(capabilities)
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_generate = {}",
        capabilities.can_generate
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_import = {}",
        capabilities.can_import
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_export = {}",
        capabilities.can_export
    );
    let _ = writeln!(
        stdout,
        "capabilities.can_delete = {}",
        capabilities.can_delete
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_listing = {}",
        capabilities.supports_listing
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_user_presence = {}",
        capabilities.supports_user_presence
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_device_bound = {}",
        capabilities.supports_device_bound
    );
    let _ = writeln!(
        stdout,
        "capabilities.supports_non_extractable = {}",
        capabilities.supports_non_extractable
    );
}

fn algorithms_csv(capabilities: &Capabilities) -> String {
    capabilities
        .algorithms
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn json_capabilities(capabilities: &Capabilities) -> String {
    let algorithms = capabilities
        .algorithms
        .iter()
        .map(|algorithm| format!("\"{algorithm}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"backend\":\"{}\",\"algorithms\":[{}],\"can_generate\":{},\"can_import\":{},\"can_export\":{},\"can_delete\":{},\"supports_listing\":{},\"supports_user_presence\":{},\"supports_device_bound\":{},\"supports_non_extractable\":{}}}",
        capabilities.backend,
        algorithms,
        capabilities.can_generate,
        capabilities.can_import,
        capabilities.can_export,
        capabilities.can_delete,
        capabilities.supports_listing,
        capabilities.supports_user_presence,
        capabilities.supports_device_bound,
        capabilities.supports_non_extractable
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out
}

/// Print a library error and give its exit code.
fn key_error(error: keys::Error) -> u8 {
    let error = libkit::Error::from(error);
    emit_err(
        &crate::exit_map::message(&error),
        crate::exit_map::exit_code(&error),
    )
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<KeyOpts, clap::Error> {
        KeyOpts::try_parse_from(
            std::iter::once("kit key".to_owned()).chain(args.iter().map(|arg| (*arg).to_owned())),
        )
    }

    #[test]
    fn generate_accepts_equals_options() {
        let opts = parse(&["generate", "--backend=software-raw", "--algorithm=ed25519"]).unwrap();
        let KeyCommand::Generate(generate) = opts.command else {
            panic!("expected generate command");
        };
        assert_eq!(generate.backend.as_deref(), Some("software-raw"));
        assert_eq!(generate.algorithm.as_deref(), Some("ed25519"));
    }

    #[test]
    fn import_accepts_equals_options() {
        let secret = "03".repeat(32);
        let opts = parse(&["import", "--algorithm=ed25519", &format!("--hex={secret}")]).unwrap();
        let KeyCommand::Import(import) = opts.command else {
            panic!("expected import command");
        };
        assert_eq!(import.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(import.hex.as_deref(), Some(secret.as_str()));
    }

    #[test]
    fn extractable_flags_conflict() {
        assert!(parse(&["generate", "--extractable", "--non-extractable"]).is_err());
        assert!(parse(&["import", "--extractable", "--non-extractable"]).is_err());
    }
}
