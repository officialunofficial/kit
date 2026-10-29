//! Open the repository that contains a directory and hash a message.
//!
//! Run it with `cargo run -p libkit --example open_repo -- <directory>`.

use std::path::PathBuf;

use libkit::core::hash;
use libkit::{Environment, Repo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let environment = Environment::new(std::env::current_dir()?);

    let repo = Repo::discover(&start, &environment)?;
    println!("opened {:?}", repo.layout());
    println!("blake3 of \"kit\": {}", hash::to_hex(&hash::hash(b"kit")));
    Ok(())
}
