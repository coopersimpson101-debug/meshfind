# meshfind protocol, version 1

This is the normative description of the protocol. The Python package
(`meshfind/`) is the reference implementation, and the portable C core
(`firmware/common/`) has to match it byte for byte. Both are checked against
`vectors/meshfind_vectors.json`. All multi-byte integers are little-endian
unless a section says otherwise.

meshfind takes its ideas from Apple's offline finding system as it was
reverse-engineered and documented publicly in *"Who Can Find My Devices?
Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking
System"* (Heinrich, Stute, Kornhuber, Hollick, PoPETs 2021) and implemented
in the open-source **OpenHaystack** project. It is **not** compatible with
Apple's network and does not reuse its formats. The cryptographic suite, key
schedule, report format, transport and anti-stalking design described here
are its own.

## 1. Roles

| Role | Hardware | Knows | Does |
|---|---|---|---|
| **Tag** | ESP32-C3 (any BLE 4.x+ SoC) | current chain values only | rotates keys, advertises the public key |
| **Relay** | ESP32 mesh node, fixed position | its own position | hears tags, seals encrypted reports, forwards mesh frames |
| **Gateway** | relay + USB/serial (or IP) uplink | the same as a relay | delivers reports to the server, provides mesh time |
| **Server** | anything that runs Python | opaque envelopes | stores reports by key hash and returns them on request |
| **Owner** | laptop or phone (CLI today) | the tag's master secret | derives hashes, queries, decrypts, locates |
| **Scanner** | any BLE device (victim side) | nothing | flags unknown trackers that travel with it |

## 2. Cryptographic suite

| Purpose | Primitive |
|---|---|
| Tag keys, report key agreement | X25519 (RFC 7748) |
| All derivations | HKDF-SHA256 (RFC 5869) |
| Report encryption | ChaCha20-Poly1305 (RFC 8439), 12-byte nonce, 16-byte tag |
| Server index, message ids | SHA-256 |
| Presence tokens | HMAC-SHA256, truncated to 16 bytes |

**Why X25519 rather than P-224.** Apple uses P-224 because its 28-byte
x-coordinate fits in an advertisement. X25519 needs 32 bytes, but those
32 bytes still fit exactly in one *legacy* advertisement (§4), and the curve
brings the following:

- constant-time implementations are simple and widely audited (TweetNaCl,
  libsodium, mbedTLS);
- there is no point validation to get wrong: every 32-byte string is a valid
  input, the curve is twist-secure, and the one check needed is rejecting an
  all-zero shared secret;
- there are no patent or parameter-provenance questions;
- the same code base serves both the ratchet and the ECIES.

**Why ChaCha20-Poly1305 rather than AES-GCM.** ChaCha20-Poly1305 is fast and
constant-time in plain software on any MCU, including the classic ESP32 when
the AES block is busy or not exposed to a given stack. It is also harder to
misuse: no GHASH table side channels. Its nonces are derived and keys are
never reused, so nonce misuse is impossible by construction (§5).

**Why HKDF everywhere.** A single, standard KDF covers the ratchet, the epoch
keys, the presence key, the ECIES and the UWB STS keys. Each use gets its own
`info` label (`meshfind/v1/...`) for domain separation.

## 3. Key schedule

Pairing creates a 32-byte master secret `MS` (CSPRNG) and a provisioning time
`epoch0`, stored in the owner's `tag.json`. The tag never receives `MS`.

```
SK_0        = HKDF(ikm=MS,   salt="", info="meshfind/v1/chain-init",     32)
SEP_0       = HKDF(ikm=MS,   salt="", info="meshfind/v1/sep-chain-init", 32)
PK_presence = HKDF(ikm=MS,   salt="", info="meshfind/v1/presence",       32)
X_{i+1}     = HKDF(ikm=X_i,  salt="", info="meshfind/v1/chain-step",     32)   (both chains)
d_i         = clamp(HKDF(ikm=X_i, salt="", info="meshfind/v1/epoch-priv", 32))
P_i         = X25519(d_i, 9)
H_i         = SHA-256(P_i)                       -- server index ("key hash")
```

An empty salt means 32 zero bytes, as RFC 5869 specifies.

- **Near-owner chain** (`SK_i`): `i = floor((t - epoch0) / 900)`, so the key
  rotates every **15 minutes**.
- **Separated chain** (`SEP_j`): `j = floor((t - epoch0) / 86400)`, so the key
  rotates **daily**. The tag uses it when it has not seen its owner for
  `CONFIG_MESHFIND_TAG_SEPARATED_AFTER_MIN` (480 minutes by default). See §10.
- **Forward secrecy for the tag.** The tag keeps only the current `X_i`. Each
  step overwrites the old value in NVS, and the step function is one-way, so
  a seized tag does not reveal past keys and therefore not past reports.
- **The owner** keeps `MS` and derives any `i`. The reference implementation
  caches a checkpoint every 96 epochs, so deriving a year of keys costs about
  35,000 HKDF calls.
- **Clock drift.** The owner queries `[i - 2, i + 2]` around each target
  epoch, and accepts report timestamps up to 30 minutes outside a key's epoch.
  When a tag hears a valid presence token for epoch `e` (§3.1) it moves its
  clock into `e`: an *authenticated* time source.

### 3.1 Owner-presence token

```
token_e = HMAC-SHA256(PK_presence, "presence" || u32le(e))[:16]
```

The owner's device advertises (raw AD, 21 bytes):

| off | len | value |
|---|---|---|
| 0 | 1 | `0x14` (AD length 20) |
| 1 | 1 | `0xFF` (Manufacturer Specific Data) |
| 2 | 2 | `0xFFFF` company id |
| 4 | 1 | `0x50` marker. Its low three bits are 0, so it never parses as a tag advertisement. |
| 5 | 16 | `token_e` |

The tag scans for 300 ms every 60 s and accepts tokens for `e` within ±4
epochs of its own clock. `python -m meshfind tag presence tag.json` prints
the payloads. No owner app ships yet; this is on the roadmap.

## 4. Tag advertisement

The advertisement is a legacy, non-connectable, undirected advertisement
(`ADV_NONCONN_IND`) sent from a **static random address that is derived from
the key**.

```
addr[0]    = P[0] | 0xC0          (MSB first, as printed; the top two bits 11
                                   mark a static random address)
addr[1..5] = P[1..5]
```

Advertising data, exactly 31 bytes:

| off | len | field |
|---|---|---|
| 0 | 1 | `0x1E` AD length (30) |
| 1 | 1 | `0xFF` Manufacturer Specific Data |
| 2 | 2 | `0xFFFF` company id (the Bluetooth SIG "reserved for testing" value; a real deployment would register its own) |
| 4 | 1 | status: b7..6 = `P[0] >> 6` (the two bits the address marker overwrote) · b5..4 battery (0 full, 1 medium, 2 low, 3 critical) · b3 separated flag · b2..0 protocol version = 1 |
| 5 | 26 | `P[6..31]` |

All 256 bits of the key are recovered:
`P[0] = (addr[0] & 0x3F) | (status & 0xC0)`.

**Why legacy rather than BLE 5 extended advertising.** The relays are classic
ESP32s, which support BLE 4.2 and cannot receive extended advertisements.
Legacy advertisements also reach every phone ever made, which matters for
anti-stalking scanners. Primary-channel legacy PDUs are also the most robust
and lowest-power option for a coin-cell tag. BLE 5 extended advertising
(e.g. adding a coded-PHY long-range copy) is on the roadmap as an *additional*
advertisement, not a replacement.

**Address and key rotate together.** The address is part of the key, so
nothing static is ever on the air: no public address and no stable payload
bytes.

**Battery-aware interval** (`mf_adv_interval_ms` and `adv.adv_interval_ms`):

| battery | ≥60 % | 30–59 % | 10–29 % | <10 % |
|---|---|---|---|---|
| near-owner | 2000 ms | 2000 ms | 4000 ms | 8000 ms |
| separated | 1000 ms | 1000 ms | 2000 ms | 4000 ms |

Separated tags advertise twice as often, but never faster than 1 s, which
makes them easier to find and easier for victims to notice.

## 5. Encrypted report (ECIES)

A relay that hears `P` builds:

```
e        = clamp(32 random bytes)        -- fresh per report, wiped afterwards
E        = X25519(e, 9)
S        = X25519(e, P)                  -- abort if S == 0^32 (low-order P)
okm      = HKDF(ikm=S, salt=E || P, info="meshfind/v1/report", 44)
k, n     = okm[0:32], okm[32:44]
header   = 0x01 (version) | 0x00 (flags) | SHA-256(P) (32) | E (32)      = 66 bytes
body     = ChaCha20-Poly1305(k, n, plaintext, aad = header)               = 26 + 16 bytes
envelope = header || body                                                  = 108 bytes
```

Plaintext (26 bytes):

| off | type | field |
|---|---|---|
| 0 | u8 | plaintext version = 1 |
| 1 | u8 | flags: b0 time-synced, b1 local frame |
| 2 | u32 | `seen_ts` unix seconds (uptime seconds if b0 is not set) |
| 6 | u32 | relay node id |
| 10 | i32 | x: cm in the site-local frame, or latitude × 1e7 |
| 14 | i32 | y: cm, or longitude × 1e7 |
| 18 | i32 | z: cm |
| 22 | u16 | position accuracy, cm |
| 24 | i8 | RSSI, dBm (median over the aggregation window) |
| 25 | u8 | tag status bits (battery, separated, version) |

- The **AAD covers the key hash**, so a server or gateway cannot move a report
  to another index without detection.
- **Nonce uniqueness:** `(k, n)` is derived from a fresh `e`, so each key
  encrypts exactly one message.
- **Owner side:** check `header[2:34] == SHA-256(P_i)`, compute
  `S = X25519(d_i, E)`, derive, then decrypt. Any failure means the report is
  dropped silently.

## 6. Relay behaviour

1. Passive scan only: the relay never sends scan requests. Scan interval
   100 ms, window 50 ms, which leaves airtime for Wi-Fi/ESP-NOW coexistence.
2. Keep only advertisements that decode under §4 and come from a *random*
   address.
3. Aggregate per public key for `CONFIG_MESHFIND_AGGREGATE_MS` (10 s), then
   seal **one** report carrying the median RSSI, and wipe the key from memory.
4. Limit origination to one report per tag key per relay every 300 s, so
   1–3 reports per key per relay.
5. Timestamp from mesh time (§7). If there is none, use uptime and clear the
   time-synced flag.

## 7. Mesh transport (ESP-NOW broadcast)

Frame (12-byte header, at most 120 bytes, under the 250-byte ESP-NOW limit):

| off | len | field |
|---|---|---|
| 0 | 1 | magic `0x4D` |
| 1 | 1 | `version(=1) << 4 \| type` with type 1 REPORT, 2 BEACON, 3 ACK |
| 2 | 1 | TTL (hops left) |
| 3 | 1 | `sender_dist`: the transmitter's hop distance to the nearest gateway, 255 = no route |
| 4 | 8 | `msg_id` |
| 12 | … | payload |

| type | msg_id | payload |
|---|---|---|
| REPORT | `SHA-256(envelope)[:8]` (derived from the content, so it never identifies the relay) | 108-byte envelope |
| BEACON | `SHA-256("bcn" \| u32 gw_id \| u32 seq)[:8]` | u32 gw_id, u32 seq, u32 unix_time (0 = unknown) |
| ACK | msg_id of the delivered report | none |

**Routing (gradient / directed flood, no addresses or neighbour tables):**

- Gateways flood a BEACON every 10 s (TTL 16). A node sets
  `dist = sender_dist + 1` from the best beacon of the newest sequence and
  uses the minimum of the last two rounds, which stops it flapping when a
  longer path happens to deliver first. A route is stale after 35 s with no
  beacon. Beacons also carry time, which relays adopt (they have no RTC, GPS
  or NTP).
- A non-duplicate REPORT is queued for forwarding only if
  `my_dist < sender_dist` (strictly closer to a gateway) and TTL > 1
  (`should_forward`, table-tested in both implementations). The forwarder
  re-stamps `sender_dist = my_dist` at transmit time and decrements TTL.
  The default TTL is 10.
- **Reliability:** the forwarder keeps the frame until it hears a closer node
  re-broadcast it (*passive ack*) or a gateway ACK. Otherwise it retries up
  to 5 times at 0.6–1.2 s intervals, and gateways re-ACK duplicates.
- **Store-and-forward:** with no route (dist 255), frames are held for up to
  1 h and sent once a beacon restores a route. A routed neighbour hearing an
  unrouted sender takes the frame over.
- **Protection:** a dedup cache (time-bounded, 600 s); a TTL; a token bucket
  covering every transmission (20 frames/s, burst 20); a bounded queue (24
  frames in C, 64 in Python, oldest dropped); per-key origination limits;
  random 0–150 ms forwarding jitter, which also blurs timing correlation.

## 8. Gateway → server

The gateway prints `MFRPT <216 hex chars>\n` for each delivered report and
accepts `MFTIME <unix>\n` from the host. `python -m meshfind gateway --serial
PORT --server URL` bridges the two: it validates lines, uploads batches and
pushes time every 60 s.

HTTP API (JSON; deploy behind TLS):

| method | path | body | response |
|---|---|---|---|
| GET | `/v1/health` | none | `{"ok": true, "reports": N}` |
| POST | `/v1/reports` | `{"reports": [hex, …]}` (≤1000), optional `Authorization: Bearer <token>` | `{"accepted", "duplicates", "rejected"}` |
| POST | `/v1/query` | `{"key_hashes": [hex32, …] (≤4096), "since": unix}` | `{"reports": {hash: [hex, …]}}` (≤500 per hash) |

The server deduplicates by `SHA-256(envelope)[:16]`, so a replayed upload has
no effect, and deletes reports after `--retention-days` (7 by default).

## 9. Owner: query, validate, locate

1. Derive keys for the window (near-owner ±2 epochs, separated ±1 day) and
   optionally add random decoy hashes (`--decoys N`), shuffled.
2. Decrypt. Drop failures and duplicates. Mark a report *implausible* if it
   claims a synced time more than 30 minutes outside its key's epoch, then
   ignore it for positioning.
3. Positioning uses the reports from the newest 15-minute window:
   - 1–2 relays: a **weighted centroid** with weights `1/d²`, where
     `d = 10^((A - RSSI) / (10 n))` and the defaults are A = −59 dBm, n = 2.2;
   - 3 or more relays: **maximum-likelihood trilateration** under log-normal
     shadowing, which minimises `Σ (rssi_i − (A − 10 n log10 |p − n_i|))²`.
     The tag's reference power `A` is solved in closed form with a Gaussian
     prior around the configured value, and the search runs over a box around
     the hearing relays. This absorbs moderate TX-power differences between
     tags.

## 10. Anti-stalking (scanner side)

Any scanner sees raw advertisements. `meshfind/antistalk.py`:

1. **Tracks** group sightings by key.
2. **Stitching:** track B continues chain A when it starts 5 s before to
   180 s after A was last seen, at an RSSI within 12 dB, in the same mode and,
   once A has rotated before, *on A's rotation phase*: `k × 900 s ± 60 s`
   after A's last rotation. A second pass re-joins fragments broken by missed
   scans, when the missed rotation provably falls inside the gap and is on
   phase.
3. **Alert** when a chain has lasted ≥ 45 minutes, covered ≥ 3 distinct
   places (250 m clusters of the scanner's own position), had ≥ 2
   phase-confirmed rotations, and the scanner moved ≥ 500 m while seeing it.
   For separated-mode tags (flag bit, one key a day) the thresholds are
   ≥ 15 minutes and ≥ 2 places, with no stitching needed.
4. The user's own tags (derivable from their keyring) are excluded.

## 11. UWB extension

See [UWB.md](UWB.md). It covers the BLE ranging request (marker `0x51`),
STS keys derived from `SK_i`, and DS-TWR.

## 12. Constants

| name | value |
|---|---|
| epoch length | 900 s (configurable at provisioning) |
| separated epoch | 86400 s |
| separated after | 480 min without the owner |
| advertisement length | 31 bytes |
| envelope length | 108 bytes |
| mesh frame length (REPORT) | 120 bytes |
| report TTL / beacon TTL | 10 / 16 |
| beacon period / stale | 10 s / 35 s |
| relay aggregation / origin limit | 10 s / 300 s per key |
| dedup lifetime | 600 s |
| owner clock slack | ±2 epochs (keys), 30 min (timestamps) |

Versioning: the advertisement, envelope, plaintext and mesh frame each carry
their own version field, and every implementation rejects versions it does
not know.
