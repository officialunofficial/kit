# kit-fuzz

Bounded property tests for kit-core, cargo-fuzz compatible. A workspace
member (not published), so `libfuzzer-sys` stays behind the optional
`libfuzzer` feature and the default `cargo build` / `cargo test` never pulls
it in.

## Targets

`delta`, `pack`, `tree`, `merkle_packlist`, `merkle_proof`,
`software_key_record`, `rpc_decode`, `git_commit_parse`, `git_tag_parse`,
`git_tree_parse`, `config_parse`, `stash_list`, `bridge_map`,
`envelope_decode`, `ref_wire_decode`, `fetch_cursor_record`, `index_decode`, `history_order_decode`, `conflict_state_decode`, `sparse_wire_decode`, `git_object_parse`, `repo_identity_parse`, `commitment_parse`, `ignore_parse`, `grant_parse`, `epoch_visibility_parse`, `pack_cursor_decode`, `chunked_blob_build`, `trust_roots_parse`, `ssh_url_parse`, `ssh_cursor_reply`, `grant_fields_parse`, `read_to_end_capped`, `self_update_extract`, `self_update_version`, `absolute_config_home`, `revspec_parse`, `log_parse`, `diff_args`, `blame_line_range`, `branch_glob`, `index_path_arg`, `identity_parse`, `rebase_todo_parse`, `secret_hex_parse`, `signer_spec_parse`, `git_patch_text`, `git_url_shape`, `git_claim`.

## Two execution paths

```sh
# libfuzzer-sys harness (nightly)
cd rust/fuzz && cargo +nightly fuzz run --features libfuzzer delta

# plain unit-test harness over the same target bodies — what CI runs,
# no nightly required
cd rust && cargo test --manifest-path fuzz/Cargo.toml
```

Every target enforces the guardrails documented in `docs/FUZZ.md`: ≤100
iterations per invocation, ≤64 KiB input per iteration, bounded per-op
allocations, a 100 ms per-iteration cap, no unbounded loops, seeded PRNG.
