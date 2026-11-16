//! Private shell completion: names only, no object reads or network access.
use kit_core::{layout, refs};
use std::io::Write;

#[derive(Debug, PartialEq, Eq)]
enum Names {
    Branches,
    Tags,
    Remotes,
    None,
}

fn selection(args: &[String]) -> Names {
    let Some((command, args)) = args.split_first() else {
        return Names::None;
    };
    let last = args.last().map_or("", String::as_str);
    if args.iter().any(|s| {
        matches!(
            s.as_str(),
            "--" | "--continue" | "--abort" | "--skip" | "--help"
        )
    }) {
        return Names::None;
    }
    let mut positional = Vec::new();
    let mut value = false;
    for arg in args {
        if value {
            value = false;
            continue;
        }
        if matches!(
            arg.as_str(),
            "--format"
                | "--message"
                | "--onto"
                | "--create"
                | "--force-create"
                | "-c"
                | "-C"
                | "-b"
                | "-B"
        ) || arg == "-m" && command == "merge"
        {
            value = true;
        } else if !arg.starts_with('-') {
            positional.push(arg);
        }
    }
    if value {
        return if last == "--onto" {
            Names::Branches
        } else {
            Names::None
        };
    }
    match command.as_str() {
        "switch" | "checkout" | "merge" if positional.is_empty() => Names::Branches,
        "rebase"
            if positional.len()
                < if args
                    .iter()
                    .any(|s| s == "--onto" || s.starts_with("--onto="))
                {
                    2
                } else {
                    1
                } =>
        {
            Names::Branches
        }
        "branch"
            if positional.is_empty()
                && args.iter().any(|s| {
                    matches!(s.as_str(), "-d" | "-D" | "--delete" | "-m" | "--rename")
                }) =>
        {
            Names::Branches
        }
        "tag"
            if positional.is_empty()
                && args.iter().any(|s| matches!(s.as_str(), "-d" | "--delete")) =>
        {
            Names::Tags
        }
        "remote"
            if positional.len() == 1
                && matches!(
                    last,
                    "remove" | "rename" | "rm" | "mv" | "get-url" | "set-url"
                ) =>
        {
            Names::Remotes
        }
        "fetch" | "pull" if args.iter().any(|s| s == "--all") => Names::None,
        "push" | "fetch" | "pull" => match positional.as_slice() {
            [] => Names::Remotes,
            [_] if command == "push"
                && !args
                    .iter()
                    .any(|s| matches!(s.as_str(), "--all" | "--tags")) =>
            {
                Names::Branches
            }
            _ => Names::None,
        },
        _ => Names::None,
    }
}

pub(crate) fn run(args: &[String]) -> u8 {
    let mut invocation = vec!["kit".to_owned()];
    invocation.extend_from_slice(args);
    let Ok((command, overrides)) = crate::parse_global_flags(&invocation) else {
        return 0;
    };
    crate::environment::install(crate::environment::from_process(overrides));
    let args = &invocation[command..];
    let Ok(cwd) = std::env::current_dir() else {
        return 0;
    };
    // Match command discovery, including linked worktrees. Do not emit its
    // normal diagnostic when the shell is outside a repository.
    let Some(root) = cwd.ancestors().find(|p| p.join(".kit").exists()) else {
        return 0;
    };
    let Ok(layout) = layout::discover(root) else {
        return 0;
    };
    let names = match selection(args) {
        Names::Branches => refs::list_refs(&layout),
        Names::Tags => refs::list_tags(&layout),
        Names::Remotes => {
            if let Ok(config) = libkit::config::read_layered(
                &layout,
                &crate::environment::current(),
                &libkit::NoopObserver,
            ) {
                let mut out = std::io::stdout().lock();
                for name in libkit::config::configured_remote_names(&config) {
                    let _ = writeln!(out, "{name}");
                }
            }
            return 0;
        }
        Names::None => return 0,
    };
    if let Ok(names) = names {
        let mut out = std::io::stdout().lock();
        for name in names {
            if name.hash.is_some() {
                let _ = writeln!(out, "{}", name.name);
            }
        }
    }
    0
}
