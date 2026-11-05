# The device's broadcast signature: given only to close

A keyless node's commitment of ours becomes broadcastable only with the device's
signature on it (`SIGN_COMMITMENT_TX`). This note says when the device gives that
signature and why.

## The problem

A penalty channel is safe for this side only while no commitment of ours that the
device has revoked can reach the chain: the peer holds the revocation secret and
takes the whole channel from it. Revoking is routine, since every payment revokes the
commitment before it.

So whoever holds a fully signed commitment of ours, after the device revoked it, can
hand the channel to the peer. The host holds every commitment the device signed for
broadcast. When one operator runs both the host and the channel's peer (the hosted
model: the hub is the peer), a signed commitment that is later revoked is a theft the
operator can carry out alone.

A tower slot used to do exactly this. At every commitment step lightningd had the
device sign the new commitment for broadcast and stored it, so that a tower could
force-close if the device dropped in the middle of a round. A step later the device
revoked it, and the host kept a fully signed revoked commitment for every state of the
channel.

## Two designs

**A. A separate request, with the signature encrypted to an independent tower.** At
every step the device answers a distinct request with its broadcast signature
encrypted to a tower key pinned on the device. The tower is run by someone other than
the operator. The host stores only ciphertext. The device keeps a record of the
commitments it signed in plain and refuses to revoke them.

**B. The broadcast signature only to close.** The device gives the broadcast signature
of a commitment of ours only when the node closes the channel. It records the lowest
commitment it signed so, and from then on never reveals that commitment's secret, nor
any later one's. No commitment slot exists.

## Which is stronger: B

- **B removes the exposure; A moves it.** Under B no commitment the host was given
  fully signed can ever be revoked, so no single operator can steal through an old
  state, even one who runs the host, the peer and any tower. Under A the theft is still
  possible for an operator who also runs the tower, or who colludes with it. The tower
  holds every state's ciphertext and can decrypt any of them.
- **A cannot protect itself even with an honest tower.** The host decides what the
  tower receives. A host that withholds the newer ciphertexts and then arms the tower
  gets an honest tower to broadcast a commitment the device has since revoked, and the
  peer takes the channel. To stop that, the device would have to refuse every
  revocation until the tower acknowledged the next state under its pinned key. That
  puts a second operator's round trip into every payment and stops the channel
  whenever that tower is unreachable.
- **What B gives up protects nothing in the hosted model.** The tower slot let the host
  force-close while the device was away in the middle of a round. Where host and peer
  are one operator, that protection is the operator's own word. Where they differ, the
  peer cannot steal anyway:
  - a revoked commitment of the peer's is answered by the tower's pre-signed penalty
    set;
  - a current one pays this side's outputs, which the pre-signed sweeps (`to_remote`,
    and the HTLC sweeps off the peer's commitment) collect.
- **What stays as it is.** An HTLC this side fulfilled whose peer neither settles nor
  closes waits for the device. The device then closes and claims it, as a node that was
  offline would. BOLT 2 already asks this of every node: sign a commitment only when
  about to broadcast it.
- **B needs no new key, message or third party.** The two-operator tower arrangement
  (each Arca operator the other's tower) would make an independent tower available, but
  A would still be weaker than B for the reasons above, so the arrangement is not used
  here.

## What is built

- **The device** (`contrib/seqln-signer`) records, per channel, the lowest commitment
  of ours it signed for broadcast (`broadcast_from`, store version 16). It refuses
  `REVOKE_COMMITMENT_TX` for that commitment and every later one: "commitment n of ours
  was signed for broadcast, a close: its secret and every later one's stay on this
  device, so the commitment the host holds fully signed is never a revoked one". A
  revocation it already gave is still given again. A channel whose commitment was
  signed for broadcast cannot step any further; it closes. It still signs a commitment
  only if it validated it and has not revoked it.
- **lightningd** no longer asks for a broadcast signature at each step. It asks only
  when it drops a channel to chain, and at a mutual close's re-sign, which is a close
  and records nothing. The watchtower store keeps no commitment of ours: it writes the
  slot empty, and drops one an earlier build stored at the channel's next step. The
  `setpreemptarmed` command is gone, and speculad broadcasts no commitment of ours.
- **Channels from before.** Their earlier commitments were signed for the slot and then
  revoked, and no device rule can take back a signature already given. A channel stops
  being exposed only when it closes, and a channel opened afterwards is never exposed.
