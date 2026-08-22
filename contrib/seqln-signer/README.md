# seqln-signer: the SeqLN device signer

A Rust reimplementation of Core Lightning's signer (the crypto kernel of `libhsmd` plus the hsmd
wire subset a running node exercises), built so that a **thin wallet can hold the keys while a
host runs the node**. The device (native binary, or a browser via the WASM build) holds the
`hsm_secret` mnemonic and serves signing requests; the hosted `lightningd` never sees a key, and
in enforce mode the device refuses to sign theft-shaped transactions.

This is one half of SeqLN's signer split; the other half lives in the node tree:

```
lightningd --subdaemon=hsmd:/path/to/lightning_hsmd_proxy
    |
    v
hsmd-proxy  (hsmd/hsmd_proxy.c: all fd multiplexing, NO secret)
    |  framed requests (hsmd/signer_frame.h; u32-LE length prefix)
    v
the signer, one of:
  a) lightning_signerd        (hsmd/signerd.c, C, links real libhsmd: the reference/oracle)
  b) seqln-signer, fd mode    (this crate, local fork+socketpair, drop-in for signerd)
  c) seqln-signer, TCP mode   (this crate, remote device, BOLT-8 Noise_XK secured)
  d) browser WASM signer      (wasm/, over a WebSocket relay, same Noise_XK)
```

The proxy is selected with CLN's stock `--subdaemon=hsmd:PATH` option, so the node build is
otherwise unchanged; `SEQLN_SIGNERD` overrides which signer binary the proxy fork/execs in local
mode. Either way the `hsm_secret` (mnemonic format) is loaded from the signer's working
directory.

## Verified properties

- **Byte-exact against libhsmd.** The `conformance` harness drives the reference
  `lightning_signerd` (the oracle) and `seqln-signer` with the same `hsm_secret` and the same
  framed requests, and compares reply bytes exactly; `wasm/test/conformance.mjs` repeats the
  comparison for the WASM build against captured oracle replies. The `shadow` binary is a
  `signerd` drop-in that byte-compares live channel traffic and captures a replay corpus.
- **Validating signer (enforce mode).** With `SEQLN_SIGNER_POLICY=enforce`, before signing a
  commitment the device reconstructs every legitimate output script from the channel keys and the
  request's per-commitment point (`src/policy.rs`), and refuses if any output pays elsewhere or
  value is created. `tests/tamper.rs` proves a redirected-output commitment is rejected in
  enforce mode and signed in permissive mode (i.e. the policy, not a parse error, blocks it).
  The default is `permissive` (sign any well-formed request, mirroring libhsmd's stub validator).
- **Fail-closed remote transport.** The TCP modes run BOLT-8 Noise_XK (`src/noise.rs`, pure state
  machine, WASM-ready): encryption, integrity, and mutual authentication against pinned static
  keys. Listen mode refuses to start without its own private key and the pinned peer key; an
  unauthenticated connector is served zero frames. There is no raw-TCP fallback.
- **Seed never leaves the device.** The host holds no key material, so losing or rebuilding the
  hosted node does not endanger funds; recovery uses the device's mnemonic with CLN's standard
  recovery flow.

## Scope

Implements hsmd wire versions 4-6 and the message subset a running SeqLN node exercises:
derivation (BIP39/32/86, basepoints, per-commitment points, shachain), ECDH, commitment and HTLC
signing, withdrawal/funding signing for both Elements/Sequentia (explicit, unblinded outputs) and
Bitcoin (BIP-143 segwit v0 and BIP-86 taproot key-path wallet inputs), and BOLT11 invoice
signing. Messages outside the subset return an error sentinel rather than a wrong answer.
Enforce-mode validation currently covers commitment signs; HTLC-transaction and sweep signs are
signed as requested (a VLS-parity follow-up), and there is no rate limiting.

## Layout

| Path | What |
| --- | --- |
| `src/kernel.rs` | I/O-free crypto kernel (BIP39/32/86, HKDF, shachain, ECDH, tx sighash/sign). WASM-ready. |
| `src/wire.rs` | Big-endian hsmd wire codec for the subset. |
| `src/frame.rs` | Little-endian signer-split transport framing (`hsmd/signer_frame.h`). |
| `src/noise.rs` | BOLT-8 Noise_XK transport state machine (no sockets). |
| `src/policy.rs` | Enforce-mode commitment validation. |
| `src/dispatch.rs` | Request -> reply dispatch; channel-state tracking for the policy. |
| `src/hsm_secret.rs` | On-disk mnemonic `hsm_secret` parsing. |
| `src/bin/seqln-signer.rs` | The device signer binary (fd / `--listen` / `--connect` modes, `--genkey`). |
| `src/bin/conformance.rs` | Byte-exact conformance harness vs the libhsmd oracle. |
| `src/bin/shadow.rs` | Live shadow comparator + corpus capture. |
| `src/bin/ecdh_latency.rs` | ECDH hot-path latency probe (in-process vs transport round-trip). |
| `src/bin/emit_elements_vector.rs` | Emits an Elements v2 PSET `sign_withdrawal` vector for the conformance harness's `SEQLN_WITHDRAWAL_VECTOR` mode. |
| `tests/tamper.rs` | Enforce-mode theft-rejection test (skips without a captured corpus). |
| `tests/chstore.rs` | Channel-store persistence contract (`export_channels`/`import_channels` round-trip, MAC refusal, merge semantics). |
| `wasm/` | `wasm-bindgen` build of the same library for browsers/Node, plus SDK, relay, tests, demo page. |
| `wasm/test/enforce.mjs` | WASM enforce-mode proof: corpus replay byte-exact, tampered commitment refused. |
| `wasm/test/ws_device.mjs` | The browser-shaped device path over a real WebSocket, driven by the wallet SDK. |
| `wasm/test/reconnect_stress.sh` | Isolated regtest harness: N device disconnect/reconnect cycles and a relay restart without wedging the hosted node. |

## Build and test

Standalone crate (kept out of the seqln root workspace):

```bash
cd contrib/seqln-signer
cargo build --release           # target/release/seqln-signer, conformance, shadow, ecdh_latency
cargo test                      # unit tests + tamper.rs (skips if no captured corpus present)
```

Conformance against the reference signer (build the node first so
`lightningd/lightning_signerd` exists; see the top-level README):

```bash
./target/release/conformance /path/to/seqln/lightningd/lightning_signerd \
                             ./target/release/seqln-signer
```

## Running the split

Local (signer on the same machine, trusted socketpair; useful to validate the seam):

```bash
SEQLN_SIGNERD=/path/to/seqln-signer \
lightningd --network=sequentia-testnet \
  --subdaemon=hsmd:/path/to/seqln/lightningd/lightning_hsmd_proxy ...
```

Remote device (keys on the device, node on the host). Generate and pin transport static keys
out-of-band first (`seqln-signer --genkey` prints a keypair):

- Device listens, host connects out:
  device `seqln-signer --listen <host:port>` with `SEQLN_SIGNER_PRIVKEY[_FILE]` +
  `SEQLN_HOST_PEER_PUBKEY`; host proxy with `SEQLN_SIGNER_ADDR=<host:port>` +
  `SEQLN_HOST_PRIVKEY[_FILE]` + `SEQLN_SIGNER_PEER_PUBKEY`.
- Device connects out (browser topology; also `seqln-signer --connect` for native testing):
  host proxy with `SEQLN_SIGNER_LISTEN=<bind:port>` (reconnect-tolerant), same key pinning.

Other environment knobs: `SEQLN_SIGNER_POLICY=enforce|permissive` (default permissive),
`SEQLN_SIGNER_TRACE` (per-request trace logging), `SEQLN_SIGNER_CONNECT` (the env form of
`--connect`), and `SEQLN_SIGNER_NETWORK=bitcoin|elements`, which selects the sighash family when one
binary serves both a Bitcoin and a Sequentia node (unset: sniffed from the request's witness UTXO,
defaulting to Elements; `src/wire.rs`). On the proxy side: `SEQLN_SIGNER_HS_TIMEOUT_MS` (Noise
handshake timeout, `hsmd/signer_noise.c`), `SEQLN_SIGNER_OP_TIMEOUT_MS` (per-request timeout,
default 120000) and `SEQLN_SIGNER_TCP_{USER_TIMEOUT_MS,KEEPIDLE_S,KEEPINTVL_S,KEEPCNT}` (TCP
keepalive; `hsmd/hsmd_proxy.c`). `SEQLN_HSM_SECRET` is read only by the conformance harness.

## Browser / WASM

`wasm/` wraps the same library with `wasm-bindgen`: `Signer` (feed one framed request, get the
reply, byte-identical to native) and `NoiseSession` (the Noise_XK initiator; the page injects
entropy from `crypto.getRandomValues`). Because a browser cannot open TCP,
`wasm/relay/seqln-ws-relay.mjs` is a dumb, keyless WebSocket-to-TCP byte pipe in front of the
proxy's listen socket; Noise runs end-to-end browser-to-proxy, so the relay never sees plaintext
and holds no key. `wasm/sdk/seqln-signer-sdk.js` is the wallet-facing class (mnemonic in, live
non-custodial signer out; no npm dependencies), and `wasm/web/` is a minimal demo page.

```bash
cd contrib/seqln-signer/wasm
wasm-pack build --target nodejs --out-dir pkg        # for the node test scripts
wasm-pack build --target web    --out-dir web/pkg    # for the SDK / demo page
node test/conformance.mjs <corpus.bin> <hsm_secret> <oracle_replies.bin>
node test/device_link.mjs <host:port> <hsm_secret> <host_pub_hex> <device_priv_hex> [--enforce]
```

## Status

Testnet software, like everything Sequentia. The split, the Noise transport, enforce-mode theft
rejection, and browser-driven signing have all been exercised end-to-end against a hosted SeqLN
node, but the code is young: treat it as a working proof of the architecture, not a hardened
production signer (see the deferred validations under "Scope").
