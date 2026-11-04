// SPDX-License-Identifier: MIT OR Apache-2.0
// Smoke test for the generated kit-wasm bindings. It runs under Node.
// Usage: node scripts/wasm-smoke.js <path to the wasm-bindgen nodejs output>
"use strict";
const assert = require("node:assert/strict");
const path = require("node:path");

const kit = require(path.resolve(process.argv[2]));
const text = (s) => new TextEncoder().encode(s);

// BLAKE3 of the empty input is a fixed, published value.
assert.equal(
  kit.blake3_hex(new Uint8Array(0)),
  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
);

// A blob round trip: the id is the BLAKE3 of the canonical bytes.
const blob = kit.blob_encode(text("hello kit"));
assert.equal(blob.hash_hex, kit.blake3_hex(blob.bytes));

// A signed commit verifies, and a flipped byte does not.
const seed = "07".repeat(32);
const tree = kit.blob_encode(text("tree stand-in")).hash_hex;
const commit = kit.commit_encode_and_sign(tree, "", "smoke", 1700000000n, seed);
assert.equal(kit.commit_verify(commit.bytes), true);
const bad = Uint8Array.from(commit.bytes);
bad[bad.length - 1] ^= 1;
assert.equal(kit.commit_verify(bad), false);

// The raw signing path agrees with the derived public key.
const pub = kit.keypair_from_seed(seed).pubkey_hex;
const sig = kit.sign_bytes_commit_domain(seed, text("msg"));
assert.equal(kit.verify_bytes_commit_domain(pub, text("msg"), sig), true);
assert.equal(kit.verify_bytes_commit_domain(pub, text("other"), sig), false);

console.log("kit-wasm smoke test passed");
