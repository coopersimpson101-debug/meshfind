# meshfind threat model

Scope: protocol v1 as specified in [PROTOCOL.md](PROTOCOL.md), with the
reference implementations in this repository. Unless a property is marked as
verified on host, the security argument here is design-level. None of it has
been audited.

## Assets

1. **Owner location history**: where the tag (and so the owner's things) has
   been.
2. **Relay operator privacy**: which tags a relay saw, and when.
3. **Bystander privacy**: people near relays must not become trackable.
4. **Safety of non-owners**: a meshfind tag must not become a covert stalking
   tool.
5. **Availability**: the owner can still find the tag.

## Adversaries and what they get

| Adversary | Capability | Gets | Does not get |
|---|---|---|---|
| **Passive BLE observer** | records all advertisements anywhere | an unlinkable key (and address) per 15-minute epoch; can link across rotations only heuristically, by timing and RSSI continuity (the same signal the anti-stalking detector uses, §Stalking) | the owner's identity, past or future keys |
| **Malicious relay** | runs modified firmware, sees advertisements and every mesh frame | what a passive observer gets, plus the ciphertexts it forwards | plaintext of any report (needs `d_i`); it cannot tell which relay originated a frame, because `msg_id` is derived from the content and frames carry no source address |
| **Malicious gateway / server** | stores and serves everything, sees query patterns | report counts and timing per key hash; **which hashes one owner queries together**, which links that owner's epochs | locations; it cannot re-point a report to another hash (the AAD binds `H`) |
| **Network attacker** (between gateway and server, or owner and server) | reads and modifies HTTP | the same as the server | with TLS, nothing more. Without TLS it sees query sets. |
| **Thief with the tag** | physical access, can dump flash | the *current* chain values, and therefore future keys; can impersonate the tag from now on | past keys: the ratchet is one-way and old values are overwritten. **Caveat:** see "Provisioning secrets". |
| **Stalker** | owns a meshfind tag and plants it on a victim | the victim's location through the network, until the victim's scanner flags it | an unnoticed long-term track: the victim gets an alert after about 45 minutes of moving together (rotating mode) or 15 minutes (separated mode), with no tag cooperation needed |
| **Mesh DoS attacker** | transmits ESP-NOW and BLE | can flood, spoof beacons, forge reports for keys it hears | an unbounded amplification: TTL, dedup, token buckets and queue bounds cap the cost |

## Properties

### Confidentiality of reports

ECIES (X25519, HKDF-SHA256, ChaCha20-Poly1305) to the epoch key. Each report
uses a fresh ephemeral key, so reports from one relay cannot be linked to
each other through their ciphertexts. Verified on host: round-trips, rejection
of single-bit tampering at every byte position in both Python and C, wrong-key
rejection, low-order point rejection, and C/Python byte equality.

### Unlinkability of tags

The key and the address rotate together every 900 s. The Python tests check
that keys and addresses are unique over 430 epochs, that byte positions vary,
that consecutive keys have a Hamming distance of about 50 %, and that the bits
are balanced. **Limits:**

- A continuously observing adversary can stitch rotations by timing and RSSI.
  This is inherent to any rotating-identifier beacon, and anti-stalking
  depends on it.
- The rotation phase is per tag (`epoch0`), which helps stitching. A
  network-wide synchronised phase would reduce stitchability at the cost of
  weaker anti-stalking. We chose to favour the victim.
- Separated mode deliberately reduces unlinkability: one key a day.

### Forward secrecy of the tag

The tag holds only `X_i`. Each step `X_{i+1} = HKDF(X_i)` overwrites NVS. The
ratchet is one-way: tested on host in Python and C, including that the stored
state matches no earlier value.

### Integrity and replay

- The report AAD covers the version, flags, key hash and ephemeral key. Any
  modification is detected.
- **Replay** of an envelope is idempotent: the server deduplicates on
  `SHA-256(envelope)[:16]` and the owner deduplicates on the report id. A
  relay or mesh replay yields the same report, not a new location.
- **Re-recording old advertisements** (a replay of the tag's broadcast in
  another place) creates *new, genuine-looking* reports for an old key. The
  owner flags reports whose synced timestamp falls more than 30 minutes
  outside the key's epoch. Within an epoch, a real-time relay attack (one
  that tunnels the advertisement elsewhere) cannot be detected. This is the
  same as Apple's system, and UWB distance bounding is the long-term answer.

### Report authenticity: an explicit limit

**Anyone who hears an advertisement can create a valid report with any
position.** Relays are anonymous by design, so the owner cannot authenticate
them. Consequences and mitigations:

- An attacker in radio range can inject false positions for the current
  epoch. The owner's estimator uses the median RSSI per node and
  maximum-likelihood fitting, and the CLI shows every report. Outliers are
  visible but not automatically rejected.
- Mitigations available today:
  1. In a **fixed-node deployment** (your own building) the owner knows the
     legitimate node ids and positions and can whitelist them. The plaintext
     carries `node_id` and position, which only the owner sees. Not yet
     automated; on the roadmap.
  2. Consistency checks: reports for one epoch must be physically consistent.
- Roadmap: *private relay attestation*. Each relay holds an Ed25519 key, and
  its signature over `(H, E)` is placed **inside** the ciphertext, so only the
  owner can verify it and other relays still learn nothing. That breaks
  relay anonymity toward the owner only, and is opt-in per site.

### Mesh time

Beacons carry the gateway's time **unauthenticated**. A spoofer can skew
relay clocks, which produces reports with implausible timestamps that the
owner ignores. It cannot forge locations this way. Tag time, by contrast, is
re-synchronised only from **authenticated** owner-presence tokens. Roadmap:
signed beacons with a gateway key pinned in relay firmware.

### Query privacy

The server learns which set of hashes a client asks for together, which links
a tag's epochs (and so reveals report volume and timing for that tag, though
not locations). Mitigations: `--decoys N` adds random hashes, queries can go
through Tor or a VPN, and windows can be queried in separate sessions.
Roadmap: bucketised queries (a hash-prefix scheme in which the server returns
a superset) or PIR.

### Provisioning secrets

`tag provision` emits chain **seeds** (not `MS`) as sdkconfig values. They
are compiled into the firmware image, so **anyone who dumps the flash of a
tag provisioned this way can recompute every key from `SK_0`**, which defeats
forward secrecy. Until serial or BLE provisioning lands (roadmap), do one of
the following:

1. enable ESP32-C3 flash encryption and secure boot, or
2. after first boot (the seeds are now in NVS), reflash an image built with
   empty seed strings. The NVS state survives an app reflash.

### Stalking: design decisions

- **Separated mode.** A tag that has not seen a valid owner-presence token
  for 8 hours switches to a daily key, sets a visible flag bit, and
  advertises twice as often. Scanners can then alert within about 15 minutes
  of moving together.
- **Detection without cooperation.** The detector in `antistalk.py` also
  stitches rotating keys. In simulation (200 victim days with a rotating
  stalker tag, ambient tags at home, a cafe and an office, and a stranger
  walking alongside for 20 minutes) it detected the stalker on 200/200 days
  and raised a spurious alert on 9/200 days without a stalker. All
  simulation, no field data.
- **Limits.** A stalker can build tags that never enter separated mode
  (custom firmware) or that rotate on a random schedule. Detection then rests
  on the duration and movement heuristics only, and can be evaded by a
  sufficiently erratic transmitter. That is a limit of every open tracking
  network, Apple's and Google's included. Firmware-level guarantees need
  attested hardware, which a DIY project cannot provide. Standards work to
  follow: the IETF DULT ("Detecting Unwanted Location Trackers") drafts, and
  AirGuard (Heinrich et al., WiSec 2022) for prior art on scanner-side
  detection.
- **Anyone can scan.** Separated tags advertise the flag. A future
  "play sound / identify" function should be available to *non-owners* who
  are physically near a separated tag.

### Availability

There are bounded queues, token buckets and TTLs. The server enforces body
and list limits and per-hash result caps, and an optional upload token blocks
anonymous spam. **Not mitigated:** ESP-NOW jamming, or flooding the server
with junk envelopes for random hashes when no token is set (storage
exhaustion until retention expires).

## Out of scope

Side channels on the MCUs (the reference X25519 has no secret-dependent
branches or table lookups, but it has not been evaluated with power or EM
measurements), compromise of the owner's laptop or `tag.json`, and
regulatory compliance of radio settings.
