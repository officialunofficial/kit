# Blame and stash golden outputs

The two files hold the text that `blame` and `stash show` print for fixed
histories. They pin the output of an operation. They do not pin a wire format
or an on-disk format. No spec defines this text, so a reference check has
nothing to read.

The objects that the operations read are pinned by the `objects` vectors. The
tests in `crates/kit-core/tests/ops2_integration.rs` build the histories and
compare the output with these files. The tests are the only check.
