//! Emit a real-shaped Elements v2 PSET `WIRE_HSMD_SIGN_WITHDRAWAL` (type 7) for
//! the canonical BIP39 test mnemonic, so it can be replayed through BOTH the
//! reference libhsmd oracle (`lightning_signerd`) and `seqln-signer` and the
//! resulting signatures byte-compared (the `SEQLN_WITHDRAWAL_VECTOR` mode of the
//! `conformance` binary). This anchors the Elements-asset funding-withdrawal
//! reconstruction against the real libwally `wally_psbt_sign`.
//!
//! It builds a 1-input / 3-output asset funding PSET (funding P2WSH + P2WPKH
//! change + explicit-fee output) exactly as lightningd would hand it to the
//! signer: a v2 PSET (PSBT_GLOBAL_VERSION = 2, magic `pset\xff`) with NO global
//! unsigned tx, the tx spread across the input/output maps. The single wallet
//! input is a native P2WPKH on the mnemonic's BIP-86 key `keyindex`, so both
//! signers derive the key and sign it.
//!
//! Usage: emit_elements_vector [keyindex] [in_amount]  -> prints the msg hex.

use seqln_signer::kernel::{self, Kernel, BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC};
use seqln_signer::wire::{msg, Writer};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// compact-size for small lengths (<0xfd) used throughout PSET maps here.
fn c(n: usize) -> Vec<u8> {
    assert!(n < 0xfd);
    vec![n as u8]
}

/// One PSET record: keylen || key || vallen || val.
fn rec(key: &[u8], val: &[u8]) -> Vec<u8> {
    let mut r = c(key.len());
    r.extend_from_slice(key);
    r.extend_from_slice(&c(val.len()));
    r.extend_from_slice(val);
    r
}

/// 7-byte PSET proprietary key `fc 04 "pset" <t>`.
fn pkey(t: u8) -> Vec<u8> {
    vec![0xfc, 0x04, 0x70, 0x73, 0x65, 0x74, t]
}

/// Elements explicit witness_utxo: asset(0x01||32)||value(0x01||u64_be)||null||varbuff(spk).
fn elements_wu(asset: &[u8; 32], sats: u64, spk: &[u8]) -> Vec<u8> {
    let mut v = vec![0x01u8];
    v.extend_from_slice(asset);
    v.push(0x01);
    v.extend_from_slice(&sats.to_be_bytes());
    v.push(0x00);
    v.extend_from_slice(&c(spk.len()));
    v.extend_from_slice(spk);
    v
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let keyindex: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let in_amount: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(500_000);

    let seed = kernel::bip39_seed(MNEMONIC, "").to_vec();
    let k = Kernel::new(seed, BIP32_VER_TEST_PUBLIC, BIP32_VER_TEST_PRIVATE);
    let pubkey = k.bip86_child_pubkey(keyindex);
    let keyhash = kernel::hash160(&pubkey);
    let in_spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain(keyhash).collect();

    let asset_id: [u8; 32] = [0x3au8; 32]; // a stand-in Sequentia asset id
    let fee_asset: [u8; 32] = [0x77u8; 32]; // the policy/fee asset (tSEQ)
    let txid = [0x33u8; 32];
    let seq = 0xffff_fffdu32;

    // ---- v2 PSET ----
    let mut p = Vec::new();
    p.extend_from_slice(b"pset\xff");
    // global: GLOBAL_VERSION(0xfb)=2, TX_VERSION(0x02)=2, FALLBACK_LOCKTIME(0x03)=0,
    // INPUT_COUNT(0x04)=1, OUTPUT_COUNT(0x05)=3.
    p.extend_from_slice(&rec(&[0xfb], &2u32.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x02], &2u32.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x03], &0u32.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x04], &[0x01]));
    p.extend_from_slice(&rec(&[0x05], &[0x03]));
    p.push(0x00);
    // input 0
    let wu = elements_wu(&asset_id, in_amount, &in_spk);
    p.extend_from_slice(&rec(&[0x01], &wu)); // WITNESS_UTXO
    p.extend_from_slice(&rec(&[0x0e], &txid)); // PREVIOUS_TXID
    p.extend_from_slice(&rec(&[0x0f], &0u32.to_le_bytes())); // OUTPUT_INDEX
    p.extend_from_slice(&rec(&[0x10], &seq.to_le_bytes())); // SEQUENCE
    p.push(0x00);
    // output 0: funding P2WSH
    let fund_spk: Vec<u8> = [0x00u8, 0x20].iter().copied().chain([0xabu8; 32]).collect();
    p.extend_from_slice(&rec(&pkey(0x02), &asset_id));
    p.extend_from_slice(&rec(&[0x03], &300_000u64.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x04], &fund_spk));
    p.push(0x00);
    // output 1: P2WPKH change
    let change_spk: Vec<u8> = [0x00u8, 0x14].iter().copied().chain([0xcdu8; 20]).collect();
    p.extend_from_slice(&rec(&pkey(0x02), &asset_id));
    p.extend_from_slice(&rec(&[0x03], &199_000u64.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x04], &change_spk));
    p.push(0x00);
    // output 2: explicit fee, empty script
    p.extend_from_slice(&rec(&pkey(0x02), &fee_asset));
    p.extend_from_slice(&rec(&[0x03], &1_000u64.to_le_bytes()));
    p.extend_from_slice(&rec(&[0x04], &[]));
    p.push(0x00);
    let psbt = p;

    // ---- SIGN_WITHDRAWAL message ----
    let mut w = Writer::new(msg::HSMD_SIGN_WITHDRAWAL);
    w.u16(1);
    w.bytes(&txid);
    w.u32(0);
    w.u64(in_amount);
    w.u32(keyindex);
    w.bool(false); // legacy is_p2sh
    w.u16(in_spk.len() as u16);
    w.bytes(&in_spk);
    w.bool(false); // is_unilateral_close
    w.bool(false); // legacy is_in_coinbase
    w.u32(psbt.len() as u32);
    w.bytes(&psbt);
    println!("{}", hexs(&w.into_vec()));
    eprintln!("keyindex={keyindex} in_amount={in_amount} wallet_pubkey={}", hexs(&pubkey));

    // Debug: print seqln-signer's own reconstructed-tx sighash for input 0, so it
    // can be compared against libwally's wally_psbt_get_input_signature_hash.
    if std::env::var("SEQLN_DEBUG_SIGHASH").is_ok() {
        let tx = seqln_signer::wire::reconstruct_elements_tx_from_pset(&psbt).unwrap();
        let mut scriptcode = vec![0x76u8, 0xa9, 0x14];
        scriptcode.extend_from_slice(&keyhash);
        scriptcode.extend_from_slice(&[0x88, 0xac]);
        let mut v9 = [0u8; 9];
        v9[0] = 0x01;
        v9[1..].copy_from_slice(&in_amount.to_be_bytes());
        let sh = kernel::elements_sighash_sw_v0(&tx, 0, &scriptcode, &v9, 0x01);
        eprintln!("seqln_sighash={}", hexs(&sh));
    }
}
