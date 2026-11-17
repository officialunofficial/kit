//! Cleanup for fixtures deeper than a recursive remover's descriptor budget.

use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct DeepRefCleanup {
    leaf: PathBuf,
    root: PathBuf,
}

impl DeepRefCleanup {
    pub(crate) fn new(leaf: PathBuf, root: PathBuf) -> Self {
        assert!(leaf.starts_with(&root));
        Self { leaf, root }
    }
}

impl Drop for DeepRefCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.leaf);
        for dir in self.leaf.ancestors().skip(1) {
            if dir == self.root || !dir.starts_with(&self.root) {
                break;
            }
            if std::fs::remove_dir(dir).is_err() {
                break;
            }
        }
    }
}
