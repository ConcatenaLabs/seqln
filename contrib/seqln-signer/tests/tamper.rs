//! M4 positive security test: the validating signer REJECTS a theft-shaped
//! commitment (an output redirected to a script not derivable from the channel
//! keys) in enforce mode, while the unmodified request signs — and the SAME
//! tamper is happily signed in permissive mode, proving it is the POLICY, not a
//! parse error, that blocks the theft.
//!
//! It replays the real captured M2b corpus (the legitimate channel) to build up
//! channel state in order, then attacks the first `SIGN_REMOTE_COMMITMENT_TX`.
//!
//! Data (override via env, defaults are this job's captures):
//!   SEQLN_HSM_SECRET   the captured node's hsm_secret (mnemonic)
//!   SEQLN_TAMPER_CORPUS the frame corpus
//! If either file is absent the test SKIPS (so a clean checkout still passes).

use std::io::Cursor;

use seqln_signer::dispatch::{Outcome, Signer};
use seqln_signer::policy::Policy;
use seqln_signer::wire::{self, msg};
use seqln_signer::{frame, hsm_secret};

const DEFAULT_SECRET: &str =
    "/home/aejkohl/.claude/jobs/e30a9b5a/tmp/t2m2b/liquid-regtest/hsm_secret";
const DEFAULT_CORPUS: &str = "/home/aejkohl/.claude/jobs/e30a9b5a/tmp/t2m2b-corpus.bin";

fn is_reply(o: &Outcome) -> bool {
    matches!(o, Outcome::Reply(_))
}
fn is_reject(o: &Outcome) -> bool {
    matches!(o, Outcome::Reject(_))
}

/// The scriptPubKey bytes of the largest-value non-fee output (the to_local /
/// to_remote holding the bulk of the channel funds — the juicy theft target).
fn biggest_output_script(hsmd_msg: &[u8]) -> Vec<u8> {
    let mut r = wire::Reader::new(hsmd_msg);
    r.u16().unwrap();
    let bt = wire::read_bitcoin_tx(&mut r).expect("parse bitcoin_tx");
    let mut best: (u64, Vec<u8>) = (0, Vec::new());
    for o in &bt.tx.outputs {
        if o.script.is_empty() {
            continue;
        }
        let v = if o.value.len() == 9 && o.value[0] == 0x01 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&o.value[1..9]);
            u64::from_be_bytes(b)
        } else {
            0
        };
        if v >= best.0 {
            best = (v, o.script.clone());
        }
    }
    assert!(!best.1.is_empty(), "no spendable output found");
    best.1
}

/// Redirect one commitment output to an attacker: find the victim script inside
/// the raw hsmd message and flip its hash bytes IN PLACE (length preserved, so
/// the tx still parses), yielding a script NOT derivable from the channel keys.
fn tamper_output(hsmd_msg: &[u8], victim: &[u8]) -> Vec<u8> {
    let pos = hsmd_msg
        .windows(victim.len())
        .position(|w| w == victim)
        .expect("victim script present in raw message");
    let mut out = hsmd_msg.to_vec();
    // Flip the trailing 4 bytes of the witness-program hash -> attacker script.
    let end = pos + victim.len();
    for b in out[end - 4..end].iter_mut() {
        *b ^= 0xff;
    }
    out
}

#[test]
fn enforce_rejects_theft_shaped_commitment() {
    let secret_path =
        std::env::var("SEQLN_HSM_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string());
    let corpus_path =
        std::env::var("SEQLN_TAMPER_CORPUS").unwrap_or_else(|_| DEFAULT_CORPUS.to_string());

    let (secret_bytes, corpus) = match (std::fs::read(&secret_path), std::fs::read(&corpus_path)) {
        (Ok(s), Ok(c)) => (s, c),
        _ => {
            eprintln!(
                "SKIP tamper test: need {secret_path} + {corpus_path} (set SEQLN_HSM_SECRET / SEQLN_TAMPER_CORPUS)"
            );
            return;
        }
    };

    let mk = || {
        let s = hsm_secret::parse(&secret_bytes).expect("parse hsm_secret");
        s
    };
    let mut enforce = Signer::with_policy(mk(), Policy::Enforce);
    let mut permissive = Signer::with_policy(mk(), Policy::Permissive);

    let mut cur = Cursor::new(&corpus);
    let mut attacked = false;
    while let Some(req) = frame::read_request(&mut cur).expect("read frame") {
        let t = wire::peektype(&req.hsmd_msg).unwrap_or(0);

        if t == msg::HSMD_SIGN_REMOTE_COMMITMENT_TX && !attacked {
            attacked = true;

            // 1. The genuine request signs in enforce mode (no false reject).
            let genuine = enforce.handle(&req);
            assert!(
                is_reply(&genuine),
                "legitimate remote commitment should sign in enforce mode, got {}",
                describe(&genuine)
            );

            // 2. Redirect the biggest output to an attacker script.
            let victim = biggest_output_script(&req.hsmd_msg);
            let tampered_msg = tamper_output(&req.hsmd_msg, &victim);
            let tampered = frame::Request {
                is_main: req.is_main,
                node_id: req.node_id,
                dbid: req.dbid,
                capabilities: req.capabilities,
                hsmd_msg: tampered_msg,
            };

            // 3. Control: permissive mode SIGNS the theft-shaped tx (the tamper
            //    is well-formed; only the policy stands between it and a stolen
            //    signature).
            let permissive_out = permissive.handle(&tampered);
            assert!(
                is_reply(&permissive_out),
                "permissive mode should still sign the tampered tx (control), got {}",
                describe(&permissive_out)
            );

            // 4. The security payoff: enforce mode REFUSES the theft.
            let enforce_out = enforce.handle(&tampered);
            assert!(
                is_reject(&enforce_out),
                "enforce mode must REJECT the theft-shaped commitment, got {}",
                describe(&enforce_out)
            );
            if let Outcome::Reject(reason) = &enforce_out {
                eprintln!("tamper correctly rejected: {reason}");
            }
            break;
        }

        // Build up state (INIT, setup_channel, basepoints, earlier signs, ...).
        let _ = enforce.handle(&req);
        let _ = permissive.handle(&req);
    }

    assert!(attacked, "corpus contained no SIGN_REMOTE_COMMITMENT_TX to attack");
}

fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Reply(b) => format!("Reply({} bytes)", b.len()),
        Outcome::Sentinel => "Sentinel".to_string(),
        Outcome::Reject(r) => format!("Reject({r})"),
        Outcome::Fatal(m) => format!("Fatal({m})"),
    }
}
