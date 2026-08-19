# SeqLN Tier 2: hosted channels via a CLN native signer split (design + milestones)

Status: design, 2026-07-04. Grounds the build of the Tier-2 backend the UX audit (§8, decision 8.9)
picks: **truly-instant pure-LN from a thin wallet, non-custodially** — we host the SeqLN node, the user's
device holds the keys and co-signs every channel state, so we can never move the user's funds. This is the
foundation the wallet Lightning UX hangs off; it is built before the UX overhaul.

Decision locked with the user (2026-07-04): the signer mechanism is the **CLN native signer split** (not VLS,
Greenlight, or a custodial interim). Rationale: smallest delta from our SeqLN fork, asset-native for free.

## 1. Why this is tractable (the three de-risking findings)

From a full file-anchored map of `~/seqln`'s signer (`hsmd/hsmd_wire.csv`, `hsmd/hsmd.c`, `hsmd/libhsmd.c`,
`lightningd/hsm_control.c`, `lightningd/lightningd.c:433`, `lightningd/options.c:365`):

1. **The seam is production, not a hack.** `--subdaemon=hsmd:PATH` (`options.c:1633-1642`, resolved
   `lightningd.c:433-451`) makes lightningd exec ANY binary in place of `lightning_hsmd`, provided it speaks
   the hsmd wire on fd 3. This is exactly how upstream deploys VLS
   (`--subdaemon=hsmd:/var/lib/vls/bin/remote_hsmd_socket`). No VLS/remote-signer code is in the fork — only
   the option + the example — so we build the signer, not modify lightningd.

2. **The signer is asset-agnostic.** `libhsmd.c` has ZERO `asset/elements/confidential/blind/nDenomination`
   references. Every `sign_*_tx` ends at `sign_tx_input`. The Elements sighash
   (`bitcoin/signature.c:120-151 bitcoin_tx_hash_for_sig`) feeds the input's EXPLICIT value
   (`psbt_input_get_amount` `bitcoin/psbt.c:645` returns the raw explicit sats "regardless of asset") and the
   already-serialized tx bytes; the asset tag is never a separate signer input. Transparent-by-default
   (principle 6) is exactly why: channel/HTLC values are explicit, so the sighash is deterministic with no
   blinding factors. A remote signer will not break on asset channels.

3. **The device crypto kernel is small + isolable.** `libhsmd` is already a dependency-free library. A device
   signer must cover only: BIP-39 (the fork's `hsm_secret` IS a mnemonic, `hsmd.c:307-357`), BIP-32 + BIP-86,
   HKDF-SHA256 derivations (node key, per-channel seed, shaseed), basepoint/per-commitment derivation, secp256k1
   ECDH, ECDSA low-R sign (+ BIP-340 if bolt12), and the Elements BIP-143 sighash (~40 lines over the standard
   preimage). All exist in Rust (`ambra_core` secp256k1 + rust-elements) and compile to WASM. No CLN event
   loop, DB, or gossip logic device-side.

## 2. Architecture

```
   DEVICE (browser WASM / phone Rust)                HOSTED (our box)
   +-------------------------------+                 +--------------------------------------+
   | device signer                 |  framed hsmd    | hsmd-proxy  (the `hsmd` binary)       |
   | - holds the mnemonic          |<== wire msgs ==>| - speaks hsmd wire on fd 3            |
   | - libhsmd crypto subset       |  {client_ctx,   | - multiplexes N per-subdaemon fds    |
   | - per-wallet policy/validation |   hsmd_msg}     |   LOCALLY (hsmd_client_hsmfd)         |
   +-------------------------------+   over 1 conn   | - tunnels each client's msgs to device|
                                                     +------------------|-------------------+
                                                                        | (local UNIX fds)
                                                     +------------------v-------------------+
                                                     | lightningd + channeld + gossipd +    |
                                                     | connectd + onchaind  (SeqLN fork)    |
                                                     | NO hsm_secret on disk                |
                                                     +--------------------------------------+
```

Load-bearing structural constraint (from the map): **fd multiplexing must stay in the LOCAL proxy.** The
`hsmd_client_hsmfd` (msg 9) → `io_send_fd` → `fdpass_recv` dance (`hsmd.c:601`, `hsm_control.c:20`) is
inherently local-UNIX (SCM_RIGHTS). So the `hsmd-proxy` binary terminates fd 3 from lightningd, answers
`hsmd_client_hsmfd` locally (socketpair + fd passback), and for every client fd forwards framed
`{client_ctx: node_id/dbid/capabilities, hsmd_wire_msg}` to the device over ONE transport. The device is a
pure request/response signer and never sees fd passing. Do NOT try to network-transport the fd handout.

The whole hsmd protocol is synchronous request/response (only status msgs are async, `hsm_control.c:88`), so a
network round-trip per sign is structurally fine — except ECDH (below).

Hosted lightningd runs with NO `hsm_secret` on disk: the device holds the mnemonic, the proxy originates
`hsmd_init` + `derive_secret` answers from the device at boot. Channels are UNANNOUNCED (private mobile
client), so the signer advertises NOT-capable for all gossip sigs and lightningd adapts (`hsm_control.c:180`).

## 3. Milestone plan

Incremental, each independently verifiable on the laptop harness (the M4/M5 SeqLN regtest + testnet4 nodes),
mirroring the pure-LN M0-M5 discipline.

- **M0 — prove the seam. DONE (2026-07-04).** Ran a full SeqLN node with `--subdaemon=hsmd:<our binary>`: the
  node booted end-to-end (`Server started with public key ...`), lightningd resolved + exec'd our substituted
  binary (`lightningd: testing .../hsmd-passthrough.sh`), the hsmd handshake completed (`mnemonic HSM secret`,
  capabilities advertised), and the hsmd wire protocol flowed through our binary (`Received message 27`
  derive_secret, `new_client: 0` fd handout). Confirms the production `--subdaemon` seam works on our fork with
  no lightningd change. Combined with the code-proof that the signer is asset-agnostic (§1.2), asset-channel +
  swap signing through a substituted signer is established; the runtime channel-signing trace lands with M1's
  logging proxy. NEXT: M1.
- **M1 — network split (out-of-process signer). DONE (2026-07-04, seqln `1e131300a`).** `hsmd-proxy`
  (`hsmd/hsmd_proxy.c`, substituted via `--subdaemon=hsmd:PATH`) keeps all ccan/io + fd machinery, answers
  `WIRE_HSMD_CLIENT_HSMFD` LOCALLY (fd-multiplexing never crosses the wire), loads no secret, and forwards every
  secret-bearing request over one socket (fork+socketpair) to `signerd` (`hsmd/signerd.c`), which owns the
  hsm_secret + libhsmd and reconstructs the `hsmd_client` per request. `hsmd/signer_frame.h` = the tiny
  little-endian frame (`is_main|node_id|dbid|capabilities|hsmd_msg`), self-describing for M2 reuse. VERIFIED:
  a node boots through the split AND a full channel lifecycle (connect ln2, fund, open→CHANNELD_NORMAL, mutual
  close) is signed out-of-process with valid Elements/asset signatures. Runtime channel-signing trace captured
  (ECDH, GET_CHANNEL_BASEPOINTS, NEW/SETUP_CHANNEL, GET_PER_COMMITMENT_POINT, SIGN_WITHDRAWAL,
  SIGN_REMOTE_COMMITMENT_TX, VALIDATE_COMMITMENT_TX, SIGN_MUTUAL_CLOSE_TX) — confirms the M2 subset.
- **M2 — device signer (Rust). DONE (2026-07-04, seqln `8664fdf01` M2a + `3a8a753ee` M2b).** Crate
  `contrib/seqln-signer`: an I/O-free (WASM-ready) crypto kernel + the hsmd message subset (§4), reimplementing
  libhsmd's derivations AND transaction signing in Rust. M2a: derivations byte-exact (35/35 synthetic). M2b:
  the Elements BIP-143 sighash + low-R grinding (the subtlety: libhsmd feeds 32 zero noncedata bytes on the
  first grind round; driven via `sign_ecdsa_with_noncedata`) + the `sign_*` handlers. Reply =
  64-byte-compact+sighash-byte. PROVEN: real-request corpus byte-exact vs libhsmd (fundee 99/0, funder 102/1 —
  the 1 = `sign_withdrawal`'s full-PSBT reply, out of the device-as-fundee role), AND a node running the Rust
  signer ALONE (no fallback) completed a full channel lifecycle (open→CHANNELD_NORMAL→120k-sat payment→mutual
  close), the peer validating every signature, 0 BROKEN. Crypto pinned to the ambra_core 0.32 line for phone +
  WASM. So the device signer is functionally complete for the pure-LN hosted-channel path.
- **NETWORK TRANSPORT + M3 — DONE (2026-07-04, seqln `0db3812bd`).** The signer split now runs over a real
  network link, making the hosted model concrete: `hsmd_proxy.c` `connect_remote_signer()` (env
  `SEQLN_SIGNER_ADDR`) reaches a REMOTE `seqln-signer --listen host:port` over TCP instead of fork+socketpair
  (fork stays the default). PROVEN: a hosted node with NO local `hsm_secret` derived its node_id from a
  separate, detached remote signer over TCP, then completed a full channel lifecycle (open→NORMAL→50k
  payment→mutual close) with every signature crossing the network. **M3 confirmed:** a GOLD asset channel to
  the hosted node reached CHANNELD_NORMAL and mutual-closed, the Rust signer signing the asset-channel
  commitments over the transport (Elements sighash serializes the GOLD asset/value commitment identically).
  Topology confirmed: the device node is the FUNDEE (inbound liquidity from the LP), so `sign_withdrawal` being
  out of the M2 subset is correct.
- **SECURE TRANSPORT — DONE (2026-07-04, seqln `a581a5d90`).** The device↔hosted link (raw TCP topology proof)
  is now **BOLT-8 Noise_XK** (`Noise_XK_secp256k1_ChaChaPoly_SHA256` + per-message ChaCha20-Poly1305, 1000-nonce
  rotation) — the project's own idiom, the C proxy reusing CLN's audited `common/cryptomsg` and the Rust device
  a pure I/O-free `noise.rs` (both roles, WASM-ready). Encrypted + integrity-protected + forward secrecy +
  MUTUAL static-key auth from pinned keys (`SEQLN_HOST_*`/`SEQLN_SIGNER_*`; `--genkey` provisions), fail-CLOSED
  in remote mode (no unauth fallback); local fork mode unchanged. Verified: full channel lifecycle over the
  secured link, wire entropy 7.97 bits/byte with no plaintext hsmd markers, and wrong-key/no-handshake
  connectors REJECTED with 0 frames served (node fails closed). Resolves the prior blocking-for-production
  security note. Deferred: transport-key rotation (re-pin flow) + the browser WebSocket adapter over `noise.rs`.
- **WASM DEVICE SIGNER + BROWSER TOPOLOGY — DONE (2026-07-04, seqln `43c166364`).** The signer compiles to
  `wasm32` (sub-crate `contrib/seqln-signer/wasm`, wasm-bindgen; secp256k1 C via clang; native crate untouched).
  JS API: `Signer{fromMnemonic,processFrame,setEnforce}` + `NoiseSession` (Noise_XK initiator) + `devicePubkey`.
  PROVEN byte-exact IN WASM: all 99 real-corpus frames (incl. real signing ops (13 SIGN_TX + gossip/invoice)) reproduce libhsmd identically
  (wasm == native == libhsmd, re-verified), and the enforce policy runs in wasm (refuses a tampered commitment).
  Browser topology (device connects OUT, can't listen): a Noise_XK RESPONDER + a proxy `SEQLN_SIGNER_LISTEN`
  mode; a WASM signer as INITIATOR connected out and a KEYLESS hosted lightningd booted, derived its node_id
  over the channel, and connected to ln1 as a live peer. Remaining for the real browser: a WebSocket adapter
  (browsers can't open raw TCP; `noise::Transport` + the frame codec are transport-agnostic) + a
  `wasm-pack --target web` page holding the mnemonic (IndexedDB/WebCrypto).
- **M4 — policy + ECDH latency. DONE (2026-07-04, seqln `7695806c5`).** The device is now a VALIDATING signer:
  `policy.rs` tracks channel state (funding amount/outpoint, remote basepoints + funding pubkey, to_self_delay,
  channel_type) from SETUP_CHANNEL, and on SIGN_REMOTE_COMMITMENT_TX (the fundee theft vector) +
  VALIDATE_COMMITMENT_TX rebuilds every expected output (to_local revocable-delayed, to_remote, per-HTLC,
  anchors) from the channel keys + per-commitment point, rejecting any output not derivable from them plus
  enforcing value conservation. Toggle `SEQLN_SIGNER_POLICY=enforce|permissive` (default permissive = no
  regression). PROVEN: enforce-mode replay of the real corpus is 99/0 byte-exact (legitimate signs untouched);
  a tampered commitment (output redirected to an attacker script) is REJECTED in enforce, signs unmodified,
  signs in permissive. Deferred to VLS-parity (labeled): SIGN_COMMITMENT_TX HTLC set (off the fundee path),
  HTLC-tx/sweep/penalty signs (pay to keys we own), rate limits. **ECDH decision RESOLVED** (see §5).
- **M5 — recovery / escape hatch. DONE (2026-07-04, seqln `7527d3fbd`).** Proven: with the hosted node's WHOLE
  database destroyed, the device recovered its channel funds from only its mnemonic + the SCB
  (`emergency.recover`) — node_id reconstituted from the mnemonic, `emergencyrecover`/`recoverchannel` restored
  the stub, reconnect drove the peer to force-close, and the recovered node delivered the 700k-sat
  static_remotekey `to_remote` to a device-controlled key. Separately proved the device signer produces a VALID
  on-chain to-us sweep (`SIGN_ANY_DELAYED_PAYMENT_TO_US` after CSV; tx accepted + confirmed). So hosting carries
  no custody risk. Follow-ups (hardening, funds are already safe): add a `sign_withdrawal` handler (Elements
  PSET partial-sig) so recovered `to_remote` is re-spendable hands-off (also the M2b VLS-parity gap); fix the
  fork's `guesstoremote` (memcpy's 32 of the 64-byte BIP39 seed); harden the `emergencyrecover` onchaind stub.

**Signer split M0-M5 COMPLETE** (seqln `7527d3fbd`): the non-custodial CLN native signer split is proven
end-to-end — hosted node with no local key, remote Rust device signer (byte-exact vs libhsmd, WASM-ready),
network transport, asset channels, a validating policy that refuses theft, and device-only fund recovery. The
remaining work is PRODUCTIZATION (§below): secure the transport (Noise/TLS + per-wallet auth), the hosted-LSP
infra (JIT/pay-to-open liquidity + a wallet-facing API), and wallet integration (the signer as WASM/FFI + an
SDK), then the parked UX overhaul.

- **CAPSTONE — vision proven end-to-end (2026-07-04).** A hosted node with NO local key (keys only on the
  remote Rust device signer) completed a real pure-LN GOLD<->BTC-stand-in trade through the `seqobd` order book,
  non-custodially: received 100k GOLD, paid 200k cbe3b48f, both legs off-chain, settled in ~2-3s, the device
  signing every commitment update across the transport. Proven TWICE — permissive AND with
  `SEQLN_SIGNER_POLICY=enforce` (the validating signer witnessed both channel opens via SETUP_CHANNEL and
  permitted the legitimate swap with 0 policy rejects). Topology = the faithful production shape: the GOLD leg
  on one peer (ln3), the BTC-stand-in hold leg on another (ln2), mirroring separate asset/BTC daemons.
- **CAPSTONE FINDINGS (real, actionable):**
  1. **Same-peer multi-asset misrouting (PRIORITY BUG).** With both legs over the SAME node pair carrying
     multiple assets, the maker's `pay asset=GOLD` misrouted over the cbe3b48f channel — the swap settled on the
     shared preimage but the WRONG asset moved (taker got 0 GOLD). `getroute(asset=)` filters correctly; the
     `pay` plugin's route SELECTION does not constrain to the asset channel when the peer is reachable via
     several. Fix: constrain `pay`'s first-hop/route selection to the payment asset (pay.c / libplugin-pay.c).
     Consequence for the record: the **M4 same-network pure-LN e2e verified settle/preimage but NOT per-asset
     movement**, so it is subject to this bug and needs re-verification with per-asset checks. The **M5
     real-testnet4 proof is unaffected** (its legs were on separate networks, no same-peer ambiguity). The
     capstone fixed it via separate peers and verified real per-asset movement.
  2. **Enforce + mutual close (VLS-parity gap).** The enforce validator rejects a cooperative-close output (pays
     a plain wallet address, not a commitment script). Mutual close needs its own validation path.
  3. **Policy state is per-process in-memory.** A signer restart into enforce cannot resume pre-existing
     channels (channeld issues SIGN_COMMITMENT_TX on reestablish before any SETUP_CHANNEL re-sync) and
     fail-safe-refuses. Correct behavior; productization needs persistent policy state or a SETUP re-sync.

Then Tier-2 hosted channels are available to the wallets: the wallet SDK opens a hosted channel (pay-to-open /
JIT liquidity from our LP), holds its keys, co-signs, and trades asset<->BTC over pure-LN truly instantly.

## 4. Device-signer minimal message subset

MUST implement (a hosted, private-channel, pure-LN wallet exercises only these):
- Boot/derivation: `init`(→ v4 reply, hsm_version 5-6, honest capabilities), `derive_secret`,
  `get_channel_basepoints`, `get_per_commitment_point`, `new_channel`/`setup_channel`/`forget_channel`,
  `check_outpoint`/`lock_outpoint`.
- Channel lifecycle: `sign_commitment_tx`, `sign_remote_commitment_tx`, `validate_commitment_tx`,
  `revoke_commitment_tx`, `validate_revocation`.
- HTLCs: `sign_remote_htlc_tx`, `sign_any_local_htlc_tx`.
- On-chain claim (onchaind): `sign_mutual_close_tx`, `sign_(any_)remote_htlc_to_us`,
  `sign_(any_)delayed_payment_to_us`, `sign_(any_)penalty_to_us`.
- Peer + payments: `ecdh` (hot path), `sign_invoice`, `sign_withdrawal`, `get_output_scriptpubkey`.
- Policy: `preapprove_invoice`/`keysend`(`_check`).

CAN skip (advertise NOT-capable so lightningd adapts): all gossip sigs (`node_announcement`,
`channel_announcement/update`) — channels are unannounced; `sign_splice_tx`, `sign_anchorspend`,
`sign_htlc_tx_mingle` unless splicing/anchors/BYO-fee enabled; `sign_bolt12*` unless offers;
`bip137_sign_message`; `check_pubkey`/`check_bip86_pubkey`.

## 5. Open decisions (resolve during M4)

- **ECDH latency (load-bearing). RESOLVED (M4, 2026-07-04).** Measured: ECDH is ~113 µs in-process and ~212 µs
  round-trip over the localhost TCP transport (the framing/syscall overhead is ~0.1 ms). On a device the WAN
  RTT replaces the transport term ~1:1, so a naive per-ECDH round-trip at a phone RTT of 50-150 ms would add
  100-300 ms to every peer-connect (2 ECDH) and 50-150 ms to every onion hop (1 ECDH) — unacceptable.
  DECISION: do NOT ship naive per-ECDH round-trips; **provision a device-authorized ECDH session key at channel
  open** (or a connectd-held ECDH subkey / delegated node-ECDH), rotated periodically, collapsing the hot path
  back to the in-process figure. The funds-moving commitment signs stay per-request round-trips (not
  latency-critical, and the device must gate them). (Mirrors UX-spec §8.9.)
- **Validation policy depth (M4).** MVP can mirror the libhsmd stub (sign on request); the security win is a
  VLS-style policy (never sign a commitment that moves funds to a non-channel destination, enforce
  value-conservation, rate-limit). Depth vs latency tradeoff.
- **Backup transport.** SCB via peer-storage (the hosted node stashes the device's encrypted backup) vs a
  device-local export vs both. Recovery UX in the wallet.

## 6. Do not regress

The M0-M5 pure-LN + submarine flows (seqdex `phase3-pure-ln`), the asset-channel machinery (seqln
`825c5db`+`3ab36eec`+`0a21f40`), and the transparent-by-default explicit-value property that makes the signer
asset-agnostic. The hosted lightningd stays a normal SeqLN node; only the signer is externalized.
