//! Integration tests for `kit mcp` — the stdio Model Context Protocol
//! server. We spawn the real binary and speak newline-delimited
//! JSON-RPC over its stdin/stdout, exercising the full
//! initialize → tools/list → tools/call lifecycle against temp repos.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

/// A live `kit mcp` subprocess with helpers to exchange JSON-RPC.
struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    _xdg: tempfile::TempDir,
}

impl McpClient {
    fn spawn(repository: Option<&Path>) -> Self {
        // Isolated XDG so the developer's real kit config never
        // bleeds into tool subprocesses (the server passes env down).
        let xdg = tempfile::tempdir().expect("xdg tempdir");
        let mut cmd = Command::new(kit_bin());
        cmd.arg("mcp");
        if let Some(repo) = repository {
            cmd.args(["--repository", repo.to_str().unwrap()]);
        }
        let mut child = cmd
            .env("XDG_CONFIG_HOME", xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn kit mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            _xdg: xdg,
        };
        // Standard MCP handshake.
        let init = client.request(
            "initialize",
            &json!({ "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }),
        );
        assert_eq!(
            init.pointer("/result/serverInfo/name")
                .and_then(Value::as_str),
            Some("kit-repo")
        );
        client.notify("notifications/initialized");
        client
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{msg}").expect("write request");
        self.stdin.flush().unwrap();
        // Responses are strictly ordered (sequential server), so the
        // next line is ours; assert the id to be safe.
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let resp: Value = serde_json::from_str(&line).expect("response is JSON");
        assert_eq!(
            resp.get("id").and_then(Value::as_i64),
            Some(id),
            "id mismatch: {line}"
        );
        resp
    }

    fn notify(&mut self, method: &str) {
        let msg = json!({ "jsonrpc": "2.0", "method": method });
        writeln!(self.stdin, "{msg}").expect("write notification");
        self.stdin.flush().unwrap();
    }

    /// Call a tool; returns `(text, is_error)`.
    fn call(&mut self, tool: &str, args: &Value) -> (String, bool) {
        let resp = self.request("tools/call", &json!({ "name": tool, "arguments": args }));
        let result = resp
            .get("result")
            .unwrap_or_else(|| panic!("no result: {resp}"));
        let text = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        (text, is_error)
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Closing stdin ends the serve loop; reap the child.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ok(client: &mut McpClient, tool: &str, args: &Value) -> String {
    let (text, is_error) = client.call(tool, args);
    assert!(!is_error, "{tool} unexpectedly failed: {text}");
    text
}

fn err(client: &mut McpClient, tool: &str, args: &Value) -> String {
    let (text, is_error) = client.call(tool, args);
    assert!(is_error, "{tool} unexpectedly succeeded: {text}");
    text
}

#[test]
fn lists_all_tools_with_annotations() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));

    let resp = client.request("tools/list", &json!({}));
    let tools = resp.pointer("/result/tools").unwrap().as_array().unwrap();
    assert_eq!(tools.len(), 21);

    let names: Vec<&str> = tools
        .iter()
        .map(|t| t.get("name").unwrap().as_str().unwrap())
        .collect();
    for expected in [
        "kit_status",
        "kit_diff_unstaged",
        "kit_diff_staged",
        "kit_diff",
        "kit_log",
        "kit_show",
        "kit_branch",
        "kit_cat_object",
        "kit_verify",
        "kit_verify_attest",
        "kit_prove",
        "kit_verify_proof",
        "kit_closure_verify",
        "kit_add",
        "kit_unstage",
        "kit_commit",
        "kit_create_branch",
        "kit_checkout",
        "kit_init",
        "kit_keygen",
        "kit_attest",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    for t in tools {
        assert_eq!(t.pointer("/annotations/openWorldHint"), Some(&json!(false)));
    }
}

/// Shared setup for the per-behavior tests below (split
/// from the former `full_workflow_init_to_log` mega-test, which chained
/// ~11 behaviors into one `#[test]` — a failure partway through gave no
/// signal about which later behavior would have passed). Establishes
/// init → keygen → add `hello.txt` → status → commit "via mcp", with the
/// same assertions the mega-test made along the way, then hands back the
/// live client plus repo path so each dependent test continues from a
/// known-good state. Returns the repo tempdir too — it must outlive the
/// client for tests that write more files into the worktree.
fn init_keygen_committed() -> (tempfile::TempDir, McpClient, String) {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    let pubkey = ok(
        &mut client,
        "kit_keygen",
        &json!({ "repo_path": repo, "print_pubkey": true }),
    );
    assert!(pubkey.contains("ed25519:"), "keygen output: {pubkey}");

    std::fs::write(root.path().join("hello.txt"), "hello mcp\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["hello.txt"] }),
    );

    let status = ok(&mut client, "kit_status", &json!({ "repo_path": repo }));
    assert!(status.contains("hello.txt"), "status: {status}");

    let commit = ok(
        &mut client,
        "kit_commit",
        &json!({ "repo_path": repo, "message": "via mcp" }),
    );
    // git-shaped summary: `[<branch> <hash>] <subject>`.
    assert!(
        commit.contains("[main ") && commit.contains("via mcp"),
        "commit: {commit}"
    );

    (root, client, repo)
}

#[test]
fn mcp_workflow_init_keygen_add_status_commit() {
    // All the assertions for this behavior live in `init_keygen_committed`
    // itself; this test exists so the setup chain (init/keygen/add/status/
    // commit) has its own localizable name distinct from the tests below
    // that build on top of it.
    let (_root, _client, _repo) = init_keygen_committed();
}

#[test]
fn mcp_workflow_log_shows_committed_message() {
    let (_root, mut client, repo) = init_keygen_committed();
    let log = ok(&mut client, "kit_log", &json!({ "repo_path": repo }));
    assert!(log.contains("via mcp"), "log: {log}");
}

#[test]
fn mcp_workflow_verify_reports_ok() {
    let (_root, mut client, repo) = init_keygen_committed();
    let verify = ok(
        &mut client,
        "kit_verify",
        &json!({ "repo_path": repo, "revision": "HEAD" }),
    );
    assert!(verify.contains("ok"), "verify: {verify}");
}

#[test]
fn mcp_workflow_branch_create_and_checkout_round_trip() {
    let (_root, mut client, repo) = init_keygen_committed();
    ok(
        &mut client,
        "kit_create_branch",
        &json!({ "repo_path": repo, "branch_name": "feature" }),
    );
    ok(
        &mut client,
        "kit_checkout",
        &json!({ "repo_path": repo, "branch_name": "feature" }),
    );
    let branches = ok(&mut client, "kit_branch", &json!({ "repo_path": repo }));
    assert!(branches.contains("feature"), "branch: {branches}");
}

#[test]
fn mcp_workflow_unstage_clears_staged_changes() {
    let (root, mut client, repo) = init_keygen_committed();
    std::fs::write(root.path().join("two.txt"), "two\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["two.txt"] }),
    );
    ok(&mut client, "kit_unstage", &json!({ "repo_path": repo }));
    let status = ok(&mut client, "kit_status", &json!({ "repo_path": repo }));
    assert!(
        !status.contains("A "),
        "after unstage, nothing staged: {status}"
    );
}

#[test]
fn mcp_workflow_attest_then_show_reports_commit() {
    let (_root, mut client, repo) = init_keygen_committed();

    // Attestation: produce one, then inspect the commit object.
    // `kit attest` prints `attested <64-hex att-id> → <path> (<n>
    // signature(s))` to stderr (surfaced as the tool text since stdout is
    // empty) — pin that shape instead of a substring-or-length guess.
    let att = ok(&mut client, "kit_attest", &json!({ "repo_path": repo }));
    assert!(
        att.starts_with("attested ") && att.contains(" signature(s))"),
        "attest: unexpected output shape: {att}"
    );
    let att_id = att
        .strip_prefix("attested ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default();
    assert_eq!(
        att_id.len(),
        64,
        "att-id should be a 64-char hex hash: {att}"
    );
    assert!(
        att_id.chars().all(|c| c.is_ascii_hexdigit()),
        "att-id should be hex: {att}"
    );
    let shown = ok(
        &mut client,
        "kit_show",
        &json!({ "repo_path": repo, "revision": "HEAD" }),
    );
    assert!(shown.contains("via mcp"), "show: {shown}");
}

#[test]
fn commit_without_key_errors_with_guidance() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );

    let text = err(
        &mut client,
        "kit_commit",
        &json!({ "repo_path": repo, "message": "x" }),
    );
    assert!(
        text.contains("keygen"),
        "error should point at keygen: {text}"
    );
    assert!(
        text.contains("exited"),
        "error carries the exit code: {text}"
    );
}

#[test]
fn keygen_refuses_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    ok(&mut client, "kit_keygen", &json!({ "repo_path": repo }));
    // Second keygen must fail — the server never passes --force.
    err(&mut client, "kit_keygen", &json!({ "repo_path": repo }));
}

#[test]
fn scope_confines_repo_path() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(allowed.path()));

    let text = err(
        &mut client,
        "kit_status",
        &json!({ "repo_path": outside.path().to_str().unwrap() }),
    );
    assert!(
        text.contains("outside the allowed repository"),
        "scope error: {text}"
    );
}

#[test]
fn flag_injection_rejected_end_to_end() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));

    let text = err(
        &mut client,
        "kit_diff",
        &json!({ "repo_path": repo, "target": "-R" }),
    );
    assert!(text.contains("must not start with '-'"), "{text}");
    let text = err(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["-A"] }),
    );
    assert!(text.contains("must not start with '-'"), "{text}");
}

#[test]
fn unknown_tool_is_a_protocol_error() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));
    let resp = client.request(
        "tools/call",
        &json!({ "name": "kit_push", "arguments": { "repo_path": "." } }),
    );
    assert_eq!(
        resp.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602)
    );
    let msg = resp
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap();
    assert!(msg.contains("unknown tool"), "{msg}");
}

#[test]
// Under `mcp-v2`, `resources/list` no longer comes back `-32601`: rmcp's
// `ServerHandler` has a generic default implementation for every method it
// recognizes as part of the spec (including `resources/list`), answering
// with an empty result rather than method-not-found even when the server
// never advertised the `resources` capability. That's rmcp's own considered
// default, not a bug in the shared tool catalog this server wraps — see
// `mcp_v2.rs`'s module doc. `ping` still round-trips fine either way.
#[cfg(not(feature = "mcp-v2"))]
fn unknown_method_and_ping() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));

    let resp = client.request("ping", &json!({}));
    assert!(resp.get("result").is_some());

    let resp = client.request("resources/list", &json!({}));
    assert_eq!(
        resp.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601)
    );
}

// --- Helpers for the attestation security tests -----------------------------

/// Decode an even-length lowercase-hex string into bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The `blake3:<hex>` keyid the repo-key signer reports for `default.key`,
/// derived from the public key the same way the CLI does.
fn repo_keyid(pubkey_hex: &str) -> String {
    let pk = hex_decode(pubkey_hex);
    format!(
        "blake3:{}",
        kit_core::hash::to_hex(&kit_core::hash::hash(&pk))
    )
}

/// Pull the `<hex>` out of a `keygen --print-pubkey` "...ed25519:<hex>..." line.
fn pubkey_hex_from(keygen_output: &str) -> String {
    let idx = keygen_output
        .find("ed25519:")
        .expect("keygen prints ed25519:<hex>");
    keygen_output[idx + "ed25519:".len()..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect()
}

#[test]
fn verify_attest_succeeds_with_external_trust_roots() {
    // The most security-sensitive differentiator path, end-to-end through
    // JSON-RPC: attest a commit, then verify it against a trust-roots file
    // OUTSIDE the repo (the only kind the MCP accepts).
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    let keygen = ok(
        &mut client,
        "kit_keygen",
        &json!({ "repo_path": repo, "print_pubkey": true }),
    );
    let pubkey_hex = pubkey_hex_from(&keygen);

    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );
    ok(
        &mut client,
        "kit_commit",
        &json!({ "repo_path": repo, "message": "c" }),
    );
    ok(&mut client, "kit_attest", &json!({ "repo_path": repo }));

    // Trust-roots pinned to our repo key, written OUTSIDE the repo.
    let roots_dir = tempfile::tempdir().unwrap();
    let roots = roots_dir.path().join("trust-roots.toml");
    std::fs::write(
        &roots,
        format!(
            "[[trust_root]]\nkeyid = \"{}\"\nkind = \"ed25519\"\npubkey_hex = \"{}\"\n",
            repo_keyid(&pubkey_hex),
            pubkey_hex
        ),
    )
    .unwrap();

    // Explicit "HEAD" must work (regression for the hex-only --commit trap).
    let out = ok(
        &mut client,
        "kit_verify_attest",
        &json!({ "repo_path": repo, "commit": "HEAD", "trust_roots": roots.to_str().unwrap() }),
    );
    assert!(
        out.to_lowercase().contains("verif") || out.contains("ok"),
        "verify-attest: {out}"
    );
}

#[test]
fn verify_attest_rejects_in_repo_trust_roots() {
    // Hostile-clone defense: a repo-local trust-roots can never be selected
    // through the MCP, even though the CLI would honor an explicit path.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    // Plant an attacker trust-roots inside the repo.
    std::fs::write(root.path().join(".kit/attest-trust-roots.toml"), "x").unwrap();

    let text = err(
        &mut client,
        "kit_verify_attest",
        &json!({ "repo_path": repo, "trust_roots": ".kit/attest-trust-roots.toml" }),
    );
    assert!(text.contains("inside the repository"), "{text}");
}

#[test]
fn verify_trusted_succeeds_with_external_trust_roots() {
    // `kit_verify`'s `trusted`/`trust_roots` args, end-to-end
    // through JSON-RPC: commit, then cross-check the commit's signer
    // against a trust-roots file OUTSIDE the repo.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    let keygen = ok(
        &mut client,
        "kit_keygen",
        &json!({ "repo_path": repo, "print_pubkey": true }),
    );
    let pubkey_hex = pubkey_hex_from(&keygen);

    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );
    ok(
        &mut client,
        "kit_commit",
        &json!({ "repo_path": repo, "message": "c" }),
    );

    let roots_dir = tempfile::tempdir().unwrap();
    let roots = roots_dir.path().join("trust-roots.toml");
    std::fs::write(
        &roots,
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{pubkey_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{pubkey_hex}\"\n"
        ),
    )
    .unwrap();

    let out = ok(
        &mut client,
        "kit_verify",
        &json!({ "repo_path": repo, "revision": "HEAD", "trust_roots": roots.to_str().unwrap() }),
    );
    assert!(out.contains("trusted"), "verify: {out}");
}

#[test]
fn verify_trusted_fails_closed_for_unregistered_signer_via_mcp() {
    let (_root, mut client, repo) = init_keygen_committed();

    let roots_dir = tempfile::tempdir().unwrap();
    let roots = roots_dir.path().join("trust-roots.toml");
    let other_hex = "77".repeat(32);
    std::fs::write(
        &roots,
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{other_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{other_hex}\"\n"
        ),
    )
    .unwrap();

    let text = err(
        &mut client,
        "kit_verify",
        &json!({ "repo_path": repo, "revision": "HEAD", "trust_roots": roots.to_str().unwrap() }),
    );
    assert!(
        text.contains("not in the trust-roots registry") || text.to_lowercase().contains("untrust"),
        "{text}"
    );
}

#[test]
fn verify_rejects_in_repo_trust_roots() {
    // Same hostile-clone defense as verify-attest: a repo-local
    // trust-roots path can never be selected through the MCP for
    // `kit_verify` either.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    std::fs::write(root.path().join(".kit/trust-roots.toml"), "x").unwrap();

    let text = err(
        &mut client,
        "kit_verify",
        &json!({ "repo_path": repo, "revision": "HEAD", "trust_roots": ".kit/trust-roots.toml" }),
    );
    assert!(text.contains("inside the repository"), "{text}");
}

#[test]
fn attest_rejects_predicate_file_outside_repo() {
    // Scope escape: a scoped MCP must not read an outside file into a
    // signed attestation, even though --repository only confines repo_path.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "kit_init", &json!({ "repo_path": repo }));
    ok(&mut client, "kit_keygen", &json!({ "repo_path": repo }));
    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "kit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );
    ok(
        &mut client,
        "kit_commit",
        &json!({ "repo_path": repo, "message": "c" }),
    );

    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("outside.json");
    std::fs::write(&secret, "{}").unwrap();

    let text = err(
        &mut client,
        "kit_attest",
        &json!({ "repo_path": repo, "predicate_file": secret.to_str().unwrap() }),
    );
    assert!(text.contains("outside the repository"), "{text}");
}

#[test]
// MCP forbids JSON-RPC batching. The hand-rolled server answers an array with
// an invalid-request error. rmcp has its own framing, so this check does not
// apply to the `mcp-v2` build.
#[cfg(not(feature = "mcp-v2"))]
fn batch_requests_are_rejected() {
    let repo = tempfile::tempdir().unwrap();
    let mut child = Command::new(kit_bin())
        .args(["mcp", "--repository", repo.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kit mcp");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        r#"[{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}]"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).expect("error response is JSON");
    assert_eq!(resp.pointer("/error/code").and_then(Value::as_i64), Some(-32600));
    assert!(resp.get("result").is_none());

    drop(stdin);
    let _ = child.wait();
}
