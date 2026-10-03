//! Payment approval and velocity limits (enforce mode; I/O-free, WASM-ready).
//!
//! A hosted node's device approves payments in two places:
//!
//!  * `PREAPPROVE_INVOICE` / `PREAPPROVE_KEYSEND`, which `pay` and `keysend`
//!    send before they offer an HTLC. The device records the payment hash as
//!    approved and answers no when the payment cannot fit in what the limit
//!    leaves for the period. The request does not name the asset, so the
//!    amount (with a routing-fee allowance) must fit in the smallest
//!    allowance left among the assets of the device's channels.
//!  * Every commitment the device signs or validates. An HTLC we offer that a
//!    commitment lists for the first time must carry an approved payment hash,
//!    and its amount is charged to the channel asset's allowance. Value that
//!    leaves our side without a listed HTLC (an HTLC trimmed as dust has no
//!    output, so the commitment request does not list it) is charged too, once
//!    the commitments show it gone. A commitment that would take the asset
//!    over its limit is refused.
//!
//! The limit is an amount per asset, in the asset's own atoms, over a sliding
//! period; Bitcoin is an asset like any other. An offered HTLC is charged when
//! it is first committed, whether the payment then succeeds or fails, so a
//! failed attempt still counts until the period has passed.

use std::collections::BTreeMap;

/// The asset an amount is in: an issued asset by its 32-byte id as a
/// transaction serializes it (the reverse of the display order), or Bitcoin
/// on a Bitcoin channel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum AssetKey {
    Btc,
    Asset([u8; 32]),
}

impl AssetKey {
    /// 33 bytes: 0x00 and zeros for Bitcoin, 0x01 and the id for an asset.
    pub fn encode(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if let AssetKey::Asset(id) = self {
            out[0] = 0x01;
            out[1..].copy_from_slice(id);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<AssetKey, String> {
        match b.first() {
            Some(0x00) if b.len() == 33 && b[1..].iter().all(|&x| x == 0) => Ok(AssetKey::Btc),
            Some(0x01) if b.len() == 33 => Ok(AssetKey::Asset(b[1..].try_into().unwrap())),
            _ => Err("bad asset key in channel-store blob".to_string()),
        }
    }

    /// `btc`, or the asset id in display order (as the node's RPC shows it).
    pub fn display(&self) -> String {
        match self {
            AssetKey::Btc => "btc".to_string(),
            AssetKey::Asset(id) => id.iter().rev().map(|b| format!("{b:02x}")).collect(),
        }
    }

    /// Parse `btc` or a display-order asset id.
    pub fn parse(s: &str) -> Result<AssetKey, String> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("btc") {
            return Ok(AssetKey::Btc);
        }
        if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("asset {s:?} is neither `btc` nor a 64-hex asset id"));
        }
        let mut id = [0u8; 32];
        for i in 0..32 {
            id[31 - i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        Ok(AssetKey::Asset(id))
    }
}

/// The default limit, in atoms of each asset per period: the largest channel
/// the hosted service sells (`INBOUND_MAX_SAT`, 10,000,000 units), so a day's
/// payments can never move more than one such channel holds.
pub const DEFAULT_LIMIT_ATOMS: u64 = 10_000_000;
/// The default period: a day.
pub const DEFAULT_PERIOD_SECS: u64 = 86_400;
/// At most this many approved payment hashes are kept (the oldest go).
pub const MAX_APPROVALS: usize = 256;
/// At most this many charges are kept; beyond it the two oldest merge into one
/// that expires with the later of them, which can only overstate what was spent.
pub const MAX_SPENDS: usize = 512;

/// The allowance for routing fees on top of a payment's amount when checking
/// it against the limit at approval: `pay`'s default fee budget, half a
/// percent and at least 5,000 msat.
pub fn fee_allowance_msat(amount_msat: u64) -> u64 {
    (amount_msat / 200).max(5_000)
}

/// The configured limits: a default for every asset, overrides per asset
/// (`None` = no limit) and the period they apply over.
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    pub default_atoms: Option<u64>,
    pub per_asset: BTreeMap<AssetKey, Option<u64>>,
    pub period_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            default_atoms: Some(DEFAULT_LIMIT_ATOMS),
            per_asset: BTreeMap::new(),
            period_secs: DEFAULT_PERIOD_SECS,
        }
    }
}

fn parse_atoms(v: &str) -> Result<Option<u64>, String> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    v.parse::<u64>()
        .map(Some)
        .map_err(|_| format!("limit {v:?} is neither a number of atoms nor `none`"))
}

impl Limits {
    /// The limit for `asset`, in msat; `None` when it has none.
    pub fn limit_msat(&self, asset: &AssetKey) -> Option<u64> {
        self.per_asset
            .get(asset)
            .copied()
            .unwrap_or(self.default_atoms)
            .map(|a| a.saturating_mul(1000))
    }

    /// Read `SEQLN_SIGNER_PAY_LIMIT` (atoms per period for every asset, or
    /// `none`), `SEQLN_SIGNER_PAY_LIMITS` (`<asset>=<atoms|none>,...`, the
    /// asset `btc` or a display-order id) and `SEQLN_SIGNER_PAY_PERIOD`
    /// (seconds). Unset variables keep the defaults; a malformed one is an
    /// error, so a typo never leaves the device without the limit it was meant
    /// to have.
    pub fn from_env() -> Result<Limits, String> {
        let mut l = Limits::default();
        if let Ok(v) = std::env::var("SEQLN_SIGNER_PAY_LIMIT") {
            l.default_atoms = parse_atoms(&v)?;
        }
        if let Ok(v) = std::env::var("SEQLN_SIGNER_PAY_LIMITS") {
            for item in v.split(',').filter(|s| !s.trim().is_empty()) {
                let (a, n) = item
                    .split_once('=')
                    .ok_or_else(|| format!("SEQLN_SIGNER_PAY_LIMITS item {item:?} is not <asset>=<atoms>"))?;
                l.per_asset.insert(AssetKey::parse(a)?, parse_atoms(n)?);
            }
        }
        if let Ok(v) = std::env::var("SEQLN_SIGNER_PAY_PERIOD") {
            l.period_secs = v
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| format!("SEQLN_SIGNER_PAY_PERIOD {v:?} is not a positive number of seconds"))?;
        }
        Ok(l)
    }
}

/// An amount charged to an asset's allowance, and when.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Spend {
    pub asset: AssetKey,
    pub at: u64,
    pub msat: u64,
}

/// An approved payment hash, and when it was approved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Approval {
    pub hash: [u8; 32],
    pub at: u64,
}

/// What the device has approved and charged, across every channel. Persisted
/// with the channel store, so a restart neither forgets an approval nor
/// refills an allowance.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct Ledger {
    pub approvals: Vec<Approval>,
    pub spends: Vec<Spend>,
}

fn within(at: u64, now: u64, period: u64) -> bool {
    // A time ahead of the clock (the clock went back) still counts.
    now.saturating_sub(at) < period
}

impl Ledger {
    /// Drop approvals and charges older than the period.
    pub fn prune(&mut self, now: u64, period: u64) {
        self.approvals.retain(|a| within(a.at, now, period));
        self.spends.retain(|s| within(s.at, now, period));
    }

    pub fn spent_msat(&self, asset: &AssetKey, now: u64, period: u64) -> u64 {
        self.spends
            .iter()
            .filter(|s| s.asset == *asset && within(s.at, now, period))
            .fold(0u64, |t, s| t.saturating_add(s.msat))
    }

    /// What is left of `asset`'s allowance this period; `None` = unlimited.
    pub fn remaining_msat(&self, limits: &Limits, asset: &AssetKey, now: u64) -> Option<u64> {
        limits
            .limit_msat(asset)
            .map(|l| l.saturating_sub(self.spent_msat(asset, now, limits.period_secs)))
    }

    pub fn is_approved(&self, hash: &[u8; 32], now: u64, period: u64) -> bool {
        self.approvals.iter().any(|a| a.hash == *hash && within(a.at, now, period))
    }

    pub fn approve(&mut self, hash: [u8; 32], now: u64) {
        self.approvals.retain(|a| a.hash != hash);
        self.approvals.push(Approval { hash, at: now });
        while self.approvals.len() > MAX_APPROVALS {
            self.approvals.remove(0);
        }
    }

    /// Whether `msat` more of `asset` fits in its allowance this period.
    pub fn check_spend(&self, limits: &Limits, asset: &AssetKey, msat: u64, now: u64) -> Result<(), String> {
        if msat == 0 {
            return Ok(());
        }
        match limits.limit_msat(asset) {
            None => Ok(()),
            Some(limit) => {
                let spent = self.spent_msat(asset, now, limits.period_secs);
                if spent.saturating_add(msat) > limit {
                    Err(format!(
                        "paying {} more msat of asset {} would pass its limit of {} msat per \
                         {} s ({} msat already spent)",
                        msat,
                        asset.display(),
                        limit,
                        limits.period_secs,
                        spent
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn charge(&mut self, asset: AssetKey, msat: u64, now: u64) {
        if msat == 0 {
            return;
        }
        self.spends.push(Spend { asset, at: now, msat });
        self.spends.sort_by_key(|s| s.at);
        while self.spends.len() > MAX_SPENDS {
            // Fold the oldest charge into the next one of the same asset,
            // which expires later: the total is kept and can only outlast
            // what it was. (With no other charge of its asset, nothing is
            // dropped.)
            let first = self.spends[0];
            match self.spends[1..].iter().position(|s| s.asset == first.asset) {
                Some(p) => {
                    self.spends[p + 1].msat = self.spends[p + 1].msat.saturating_add(first.msat);
                    self.spends.remove(0);
                }
                None => break,
            }
        }
    }

    /// Fold in a persisted ledger (a blob import): keep every approval and
    /// every charge either side knows of.
    pub fn merge_from(&mut self, other: &Ledger) {
        for a in &other.approvals {
            match self.approvals.iter_mut().find(|x| x.hash == a.hash) {
                Some(x) => x.at = x.at.max(a.at),
                None => self.approvals.push(*a),
            }
        }
        for s in &other.spends {
            if !self.spends.contains(s) {
                self.spends.push(*s);
            }
        }
        self.approvals.sort_by_key(|a| a.at);
        while self.approvals.len() > MAX_APPROVALS {
            self.approvals.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// BOLT 11: the payment hash and amount of an invoice string.
// ---------------------------------------------------------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The amount a BOLT 11 human-readable part states, in msat: `ln`, the
/// network's letters, then an optional amount (digits and a multiplier).
fn hrp_amount_msat(hrp: &str) -> Result<Option<u64>, String> {
    let rest = hrp.strip_prefix("ln").ok_or("invoice prefix is not `ln`")?;
    let start = match rest.find(|c: char| c.is_ascii_digit()) {
        Some(i) => i,
        None => return Ok(None),
    };
    let amt = &rest[start..];
    let (digits, mult) = match amt.chars().last() {
        Some(c) if "munp".contains(c) => (&amt[..amt.len() - 1], Some(c)),
        _ => (amt, None),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("invoice amount {amt:?} is malformed"));
    }
    let n: u128 = digits.parse().map_err(|_| format!("invoice amount {amt:?} is malformed"))?;
    // msat per unit of the multiplier; a whole unit is 10^11 msat.
    let msat = match mult {
        None => n * 100_000_000_000,
        Some('m') => n * 100_000_000,
        Some('u') => n * 100_000,
        Some('n') => n * 100,
        Some('p') => {
            if n % 10 != 0 {
                return Err(format!("invoice amount {amt:?} is not a whole msat"));
            }
            n / 10
        }
        _ => unreachable!(),
    };
    u64::try_from(msat).map(Some).map_err(|_| format!("invoice amount {amt:?} is too large"))
}

/// Decode a BOLT 11 invoice far enough for approval: its payment hash and
/// the amount it states (msat), checking the bech32 checksum. The signature is
/// not checked: approval binds the hash, whoever made the invoice.
pub fn decode_bolt11(invoice: &str) -> Result<([u8; 32], Option<u64>), String> {
    let s = invoice.trim().to_ascii_lowercase();
    let s = s.strip_prefix("lightning:").unwrap_or(&s);
    let sep = s.rfind('1').ok_or("invoice has no bech32 separator")?;
    let (hrp, data) = (&s[..sep], &s[sep + 1..]);
    if hrp.is_empty() || data.len() < 7 + 104 + 6 {
        return Err("invoice is too short".to_string());
    }
    let words: Vec<u8> = data
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or("invoice has a character outside bech32")?;
    let mut chk: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    chk.push(0);
    chk.extend(hrp.bytes().map(|c| c & 31));
    chk.extend_from_slice(&words);
    if polymod(&chk) != 1 {
        return Err("invoice checksum does not verify".to_string());
    }
    let amount = hrp_amount_msat(hrp)?;
    // timestamp (7 words), tagged fields, signature (104 words), checksum (6).
    let fields = &words[7..words.len() - 104 - 6];
    let mut i = 0;
    while i + 3 <= fields.len() {
        let tag = fields[i];
        let len = fields[i + 1] as usize * 32 + fields[i + 2] as usize;
        let body = fields.get(i + 3..i + 3 + len).ok_or("invoice field runs past its end")?;
        if tag == 1 && len == 52 {
            let mut acc: u32 = 0;
            let mut bits = 0;
            let mut out = Vec::with_capacity(33);
            for &w in body {
                acc = (acc << 5) | w as u32;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                    acc &= (1 << bits) - 1;
                }
            }
            let hash: [u8; 32] = out[..32].try_into().unwrap();
            return Ok((hash, amount));
        }
        i += 3 + len;
    }
    Err("invoice carries no payment hash".to_string())
}

// ---------------------------------------------------------------------------
// What a channel's commitments pay away.
// ---------------------------------------------------------------------------

/// An HTLC we offered, as a commitment request lists it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Offered {
    pub amount_msat: u64,
    pub hash: [u8; 32],
    pub cltv: u32,
}

/// The latest commitment on one side of a channel, as far as payments go.
#[derive(Clone, PartialEq, Debug)]
pub struct SideTrack {
    /// Its commitment number.
    pub n: u64,
    /// What it leaves this side, in atoms: our main output and the HTLCs we
    /// offered, plus the fee and anchors when we opened the channel (those
    /// are ours too, and are paid by us).
    pub value: u64,
    /// The HTLCs we offered that it lists.
    pub offered: Vec<Offered>,
    /// The value, in atoms, that has left this side over this chain of
    /// commitments without a listed HTLC to account for it.
    pub lost: u64,
}

/// Per-channel payment tracking: the channel's asset, the latest commitment
/// on each side, and how much of the unlisted loss has been charged.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct PayTrack {
    pub asset: Option<AssetKey>,
    pub local: Option<SideTrack>,
    pub remote: Option<SideTrack>,
    /// The larger of the two sides' `lost`, as already charged.
    pub charged_lost: u64,
}

/// At most this many offered HTLCs are kept per side (BOLT 2 caps a side at
/// 483 in flight).
pub const MAX_OFFERED: usize = 966;

/// Count of `x` in a sorted multiset.
fn count(set: &[Offered], x: &Offered) -> usize {
    set.iter().filter(|y| *y == x).count()
}

/// The elements of `a` beyond the multiplicity `b` gives them.
fn minus(a: &[Offered], b: &[Offered]) -> Vec<Offered> {
    let mut out = Vec::new();
    let mut seen: Vec<Offered> = Vec::new();
    for x in a {
        seen.push(*x);
        if count(&seen, x) > count(b, x) {
            out.push(*x);
        }
    }
    out
}

/// Each element at the larger of its two multiplicities.
fn max_union(a: &[Offered], b: &[Offered]) -> Vec<Offered> {
    let mut out = a.to_vec();
    out.extend(minus(b, a));
    out
}

/// What a commitment means for payments, before it is signed: the HTLCs it
/// newly offers (each must carry an approved hash), the amount to charge, and
/// the channel's tracking once it is signed.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub asset: AssetKey,
    pub new_offered: Vec<Offered>,
    pub charge_msat: u64,
    pub track: PayTrack,
}

impl PayTrack {
    /// Plan a commitment of `local` (ours) or the peer's side, number `n`,
    /// that leaves this side `value` atoms and lists our offered HTLCs
    /// `offered`. With no record of either side (a channel this device has
    /// tracked only since before it kept one), the commitment is the
    /// baseline: what it carries is taken as already approved and charged.
    pub fn plan(&self, local: bool, n: u64, asset: AssetKey, value: u64, mut offered: Vec<Offered>) -> Plan {
        offered.sort();
        offered.truncate(MAX_OFFERED);
        let (this, other) = if local { (&self.local, &self.remote) } else { (&self.remote, &self.local) };
        let baseline = self.local.is_none() && self.remote.is_none();
        let known = max_union(
            this.as_ref().map_or(&[][..], |t| &t.offered),
            other.as_ref().map_or(&[][..], |t| &t.offered),
        );
        let new_offered = if baseline { Vec::new() } else { minus(&offered, &known) };
        let new_msat = new_offered.iter().fold(0u64, |t, h| t.saturating_add(h.amount_msat));
        let mut track = self.clone();
        track.asset = Some(asset);
        match this {
            // An older commitment than the latest on this side (a re-send):
            // its new HTLCs are checked and charged, the record stays.
            Some(t) if n < t.n => {
                return Plan { asset, new_offered, charge_msat: new_msat, track };
            }
            _ => {}
        }
        let lost = match this {
            None => 0,
            Some(t) => {
                let removed = minus(&t.offered, &offered);
                let removed_atoms = removed.iter().fold(0u64, |s, h| s.saturating_add(h.amount_msat / 1000));
                // Rounding each amount down to whole atoms moves a value by
                // at most an atom per HTLC added or removed.
                let tolerance = 1 + new_offered.len() as u64 + removed.len() as u64;
                let step = t.value.saturating_sub(value).saturating_sub(removed_atoms).saturating_sub(tolerance);
                t.lost.saturating_add(step)
            }
        };
        let side = SideTrack { n, value, offered, lost };
        let other_lost = other.as_ref().map_or(0, |t| t.lost);
        let max_lost = lost.max(other_lost);
        let lost_charge = max_lost.saturating_sub(self.charged_lost);
        track.charged_lost = self.charged_lost.max(max_lost);
        if local {
            track.local = Some(side);
        } else {
            track.remote = Some(side);
        }
        Plan {
            asset,
            new_offered,
            charge_msat: new_msat.saturating_add(lost_charge.saturating_mul(1000)),
            track,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_seqln_invoice() {
        // A sequentia-regtest invoice for 300m (0.3 units), from a test run;
        // its hash decoded independently.
        let inv = "lnsqrt300m1p4vqc54sp55mylrq4dfn3cjs7zxjg0urxrpxxnzxhkdx7rdwefsf2m57elkk9qpp5z63d3a3qx6qs73qvuth2pvmz9khh3jy6um87fy9hueuxse8mlw8sdq9da6hgxqyjw5qcqz959qxpqysgqhk7a8uc3wl6vu0mgxc4d59q0y3qkfjpxqe3t06w5ks5caha8xsp8rrt3fqvj7favpmpge79amfserdywnsy8g3jkqe43a7jjx7wj6esq387l4s";
        let (hash, amount) = decode_bolt11(inv).unwrap();
        assert_eq!(amount, Some(30_000_000_000));
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "16a2d8f62036810f440ce2eea0b3622daf78c89ae6cfe490b7e6786864fbfb8f");
        // A flipped character fails the checksum.
        let mut bad = inv.to_string();
        bad.replace_range(40..41, if &inv[40..41] == "q" { "p" } else { "q" });
        assert!(decode_bolt11(&bad).unwrap_err().contains("checksum"));
        assert!(decode_bolt11("lnsqrt1qqqq").is_err());
    }

    #[test]
    fn hrp_amounts() {
        assert_eq!(hrp_amount_msat("lnsqrt").unwrap(), None);
        assert_eq!(hrp_amount_msat("lnbcrt2500u").unwrap(), Some(250_000_000));
        assert_eq!(hrp_amount_msat("lntb1").unwrap(), Some(100_000_000_000));
        assert_eq!(hrp_amount_msat("lnbc10p").unwrap(), Some(1));
        assert!(hrp_amount_msat("lnbc15p").is_err());
        assert!(hrp_amount_msat("bc10").is_err());
    }

    #[test]
    fn asset_keys_round_trip() {
        let a = AssetKey::parse(&"ab".repeat(31).chars().chain("01".chars()).collect::<String>()).unwrap();
        assert_eq!(AssetKey::decode(&a.encode()).unwrap(), a);
        assert_eq!(AssetKey::decode(&AssetKey::Btc.encode()).unwrap(), AssetKey::Btc);
        assert!(a.display().ends_with("01"));
        assert!(AssetKey::parse("xyz").is_err());
    }

    fn h(n: u8, amount_msat: u64) -> Offered {
        Offered { amount_msat, hash: [n; 32], cltv: 100 }
    }

    #[test]
    fn ledger_window_and_limits() {
        let mut limits = Limits::default();
        let gold = AssetKey::Asset([7; 32]);
        limits.per_asset.insert(AssetKey::Btc, None);
        let mut l = Ledger::default();
        assert_eq!(l.remaining_msat(&limits, &gold, 0), Some(DEFAULT_LIMIT_ATOMS * 1000));
        l.charge(gold, 9_000_000_000, 10);
        assert!(l.check_spend(&limits, &gold, 1_000_000_000, 20).is_ok());
        let e = l.check_spend(&limits, &gold, 1_000_000_001, 20).unwrap_err();
        assert!(e.contains("would pass its limit"), "{e}");
        assert!(l.check_spend(&limits, &AssetKey::Btc, u64::MAX, 20).is_ok());
        // A period later the charge has expired.
        assert!(l.check_spend(&limits, &gold, 10_000_000_000, 10 + DEFAULT_PERIOD_SECS).is_ok());
        // Approvals expire with the period too.
        l.approve([1; 32], 5);
        assert!(l.is_approved(&[1; 32], 5 + DEFAULT_PERIOD_SECS - 1, DEFAULT_PERIOD_SECS));
        assert!(!l.is_approved(&[1; 32], 5 + DEFAULT_PERIOD_SECS, DEFAULT_PERIOD_SECS));
        // Merging keeps the total and never shrinks it.
        for i in 0..(MAX_SPENDS as u64 + 10) {
            l.charge(gold, 1, 100 + i);
        }
        assert!(l.spends.len() <= MAX_SPENDS);
        assert_eq!(l.spent_msat(&gold, 700, DEFAULT_PERIOD_SECS), 9_000_000_000 + MAX_SPENDS as u64 + 10);
    }

    #[test]
    fn plan_charges_new_htlcs_once_and_unlisted_loss() {
        let a = AssetKey::Asset([7; 32]);
        let t = PayTrack::default();
        // Commitment 0, ours, as the baseline.
        let p = t.plan(true, 0, a, 600_000, vec![]);
        assert_eq!((p.new_offered.len(), p.charge_msat), (0, 0));
        let t = p.track;
        let p = t.plan(false, 0, a, 600_000, vec![]);
        let t = p.track;
        // We offer 100,000 atoms: on the peer's commitment first, then ours.
        let p = t.plan(false, 1, a, 600_000, vec![h(1, 100_000_000)]);
        assert_eq!((p.new_offered.len(), p.charge_msat), (1, 100_000_000));
        let t = p.track;
        let p = t.plan(true, 1, a, 600_000, vec![h(1, 100_000_000)]);
        assert_eq!((p.new_offered.len(), p.charge_msat), (0, 0));
        let t = p.track;
        // It is fulfilled: gone from both, our value down by it; no charge.
        let p = t.plan(true, 2, a, 500_000, vec![]);
        assert_eq!(p.charge_msat, 0);
        let t = p.track;
        let p = t.plan(false, 2, a, 500_000, vec![]);
        assert_eq!(p.charge_msat, 0);
        let t = p.track;
        // 5,000 atoms leave with no listed HTLC (a trimmed one): charged
        // once, though both sides show it.
        let p = t.plan(true, 3, a, 495_000, vec![]);
        assert_eq!(p.charge_msat, (5_000 - 1) * 1000);
        let t = p.track;
        let p = t.plan(false, 3, a, 495_000, vec![]);
        assert_eq!(p.charge_msat, 0);
        let t = p.track;
        // An HTLC offered again after it resolved is a new one.
        let p = t.plan(false, 4, a, 495_000, vec![h(1, 100_000_000)]);
        assert_eq!(p.new_offered.len(), 1);
        // An older commitment does not move the record.
        let p2 = p.track.plan(false, 2, a, 1, vec![]);
        assert_eq!(p2.track.remote.as_ref().unwrap().n, 4);
    }
}
