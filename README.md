<p align="center">
  <img src="docs/assets/banner.svg" alt="meshfind: offline, end-to-end encrypted Find-My for DIY trackers over an ESP32 mesh" width="100%">
</p>

<p align="center">
  <a href="https://github.com/coopersimpson101-debug/meshfind/actions/workflows/ci.yml"><img src="https://github.com/coopersimpson101-debug/meshfind/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
[![Release](https://img.shields.io/github/v/release/coopersimpson101-debug/meshfind?color=A78BFA&label=release)](https://github.com/coopersimpson101-debug/meshfind/releases/latest)
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.12-3776AB?logo=python&logoColor=white" alt="Python 3.10 | 3.12">
  <img src="https://img.shields.io/badge/C99-portable%20core-555555" alt="C99 core">
  <img src="https://img.shields.io/badge/ESP--IDF-v5.2-E7352C?logo=espressif&logoColor=white" alt="ESP-IDF v5.2">
  <img src="https://img.shields.io/badge/crypto-X25519%20%C2%B7%20ChaCha20--Poly1305-A78BFA" alt="X25519, ChaCha20-Poly1305">
  <img src="https://img.shields.io/badge/hardware-not%20yet%20tested-lightgrey" alt="hardware: not yet tested">
</p>

**Put a €3 ESP32-C3 tag on your keys, bike or toolbox. Fixed ESP32 relays hear it, seal a location
report that only you can decrypt, and pass it hop by hop over ESP-NOW to a gateway. There is no cloud,
no phone vendor and no internet connection on the tag side.**

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#results-all-on-the-host-all-simulated">Results</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="docs/PROTOCOL.md">Protocol spec</a> ·
  <a href="docs/THREAT_MODEL.md">Threat model</a>
</p>

<p align="center">
  <img src="docs/assets/sim_map.svg" alt="Owner-side map from the simulated building: relay sightings, true tag position (+) and trilaterated estimate (x)" width="720"><br>
  <img src="docs/assets/simulate_terminal.svg" alt="Terminal output of python -m meshfind simulate --seed 3" width="720"><br>
  <sub>Real output of <code>python -m meshfind simulate --seed 3 --svg …</code>. In a simulated 50 × 30 m
  building, 24 relays hear the tag, all 24 encrypted reports cross the mesh, and the owner decrypts them and
  trilaterates to within 2.28 m. Regenerate with <a href="docs/assets/make_figures.py"><code>docs/assets/make_figures.py</code></a>.</sub>
</p>

## Highlights

- 🔑 **Its own protocol, in 31 bytes**: a 32-byte X25519 key split across the BLE static-random address and
  a legacy advertisement, rotated every 15 minutes by a one-way HKDF ratchet (forward secret).
- ✉️ **108-byte ECIES reports** (X25519 + HKDF-SHA256 + ChaCha20-Poly1305): relays, gateways and the server
  only ever see ciphertext indexed by `SHA-256(P_i)`.
- 🕸️ **Store-and-forward ESP-NOW mesh** with gradient routing, TTL, dedup, passive acks and rate limiting:
  **99.87 % / 99.61 % / 99.08 %** delivery at 10 / 20 / 30 % per-link loss (simulated, 20 topologies).
- 📍 **Indoor positioning** by maximum-likelihood trilateration on known relay positions: **1.13 m median**
  error over 100 simulated tag positions.
- 🛡️ **Anti-stalking**: a separated mode on the tag, plus a scanner-side detector that stitches rotating keys.
  It caught the stalker on **200/200** simulated days.
- 🧪 **Two implementations, one truth**: the Python reference and the portable C99 firmware core agree byte for
  byte on a shared vector file (**665 C checks**, **127 Python tests**). CI runs the C core under ASan/UBSan.
- 🔧 **ESP-IDF firmware** for the tag (ESP32-C3) and the relay/gateway (ESP32, reference or mbedTLS crypto),
  built in CI on every push.

## Quickstart

```bash
git clone https://github.com/coopersimpson101-debug/meshfind && cd meshfind
pip install -e ".[test]"
python -m pytest -q                                   # 127 tests, incl. the C core vs the Python vectors
python -m meshfind simulate --seed 3 --svg map.svg    # tag -> relays -> mesh -> server -> owner
python tools/host_test.py                             # C core on the host (uses $CC, ziglang or cc)
```

## Project status

| Area | Status |
|---|---|
| Protocol spec, Python reference, server, owner CLI | ✅ implemented and tested here (127 tests) |
| Portable C core (crypto, ratchet, advertisement, ECIES, mesh) | ✅ byte-identical to Python on 665 C checks (incl. duty-cycle helpers); ASan/UBSan with gcc and clang in CI |
| Tag firmware (ESP32-C3), relay/gateway firmware (ESP32) | ✅ builds with ESP-IDF v5.2.2 in CI (both crypto backends) · ✅ tag light-sleep + duty-cycled presence scans in firmware · ⏳ never run on hardware |
| Mesh routing, indoor positioning, anti-stalking | 🧪 simulated only, with simple radio models (see [Results](#results-all-on-the-host-all-simulated)) |
| Range, battery life, real positioning accuracy | ⏳ needs hardware (see [Hardware validation](#hardware-validation--todo-for-the-author)) |
| Owner mobile app, presence beacon sender | ⏳ not started (the CLI prints presence payloads) |
| UWB (DW3000) last-metre finding | 🧪 design, interface header and tested maths only |

---

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant T as Tag (ESP32-C3)
    participant R as Relay (ESP32, fixed x,y)
    participant M as Mesh (ESP-NOW hops)
    participant G as Gateway (ESP32 + serial)
    participant S as Server (HTTP + sqlite)
    participant O as Owner CLI
    Note over T: P_i = X25519(d_i, 9), d_i from the HKDF ratchet, new every 15 min
    T-)R: BLE legacy adv: addr = P_i[0..5], payload = status + P_i[6..31]
    Note over R: fresh e, S = X25519(e, P_i), key and nonce = HKDF(S, E + P_i)
    R->>M: REPORT frame (12 B header + 108 B envelope), TTL 10
    M->>G: forwarded only by nodes closer to a gateway (gradient)
    G--)M: passive ack / gateway ACK, beacons carry mesh time
    G->>S: upload envelope, indexed by SHA-256(P_i)
    O->>S: POST /v1/query with SHA-256(P_i) of derivable epochs + decoys
    S-->>O: matching envelopes (opaque to the server)
    Note over O: derive d_i, decrypt, trilaterate on relay positions, SVG map
```

<p align="center">
  <img src="docs/assets/byte_layout.svg" alt="Byte layout of the 6-byte BLE address, the 31-byte advertisement and the 108-byte encrypted report envelope" width="100%"><br>
  <sub>Wire formats drawn from the real bytes that <code>meshfind.adv.encode()</code> and <code>meshfind.report.seal()</code> produce for a fixed demo key.</sub>
</p>

meshfind combines protocol design, cryptography and hardware in one project:

- **its own protocol**: X25519 rotating keys from a one-way HKDF ratchet;
  a key split across the BLE address and payload so it fits in one 31-byte
  legacy advertisement; ECIES reports with ChaCha20-Poly1305; an index keyed
  by SHA-256 hashes;
- **a store-and-forward mesh routing layer**: gradient routing, TTL, a dedup
  cache, passive acks, rate limiting and partition tolerance;
- **owner-side positioning**: weighted centroid, plus maximum-likelihood
  trilateration on the known relay positions, which works indoors;
- **anti-stalking**: a separated mode on the tag, plus an unknown-tracker
  detector that stitches rotating keys on the scanner side;
- a **Python reference implementation** and **portable C firmware**, held to
  byte-for-byte agreement by a shared vector file;
- a **UWB (DW3000) extension** design for last-metre finding.

> Inspired by the public analysis of Apple's offline finding system in
> *"Who Can Find My Devices? Security and Privacy of Apple's Crowd-Sourced
> Bluetooth Location Tracking System"* (Heinrich et al., PoPETs 2021) and by
> the open-source **OpenHaystack** project. meshfind is a separate
> protocol and is not compatible with Apple's network.

### Architecture

```
   ┌──────────┐  BLE legacy adv, every 1-8 s
   │  TAG     │  addr = P_i[0..5] | 0xC0 (static random)
   │ ESP32-C3 │  payload = status | P_i[6..31]            P_i rotates every 15 min
   └────┬─────┘  (separated mode: daily key + flag)
        │ ))))
        ▼
 ┌─────────────┐   ESP-NOW broadcast mesh (gradient routing, TTL 10,
 │ RELAY  n_k  │   dedup, passive ack + retries, token bucket,
 │ ESP32, fixed│──▶ store-and-forward)  ──▶ ┌──────────┐ ──▶ ┌──────────┐
 │ position    │   ECIES(P_i, {t, node, x, y,   │ GATEWAY  │ USB │ meshfind │
 └─────────────┘   z, rssi, status})            │ ESP32    │ ser │ server   │
   … more relays …    108-byte envelope         └──────────┘ ial │ (HTTP,   │
                                                   ▲ MFTIME      │ sqlite)  │
                                                   └─ beacons ── └────┬─────┘
                                                      carry time      │ POST /v1/query
                                                                      │ {SHA-256(P_i), …}
                                              ┌───────────────────────┴──┐
                                              │ OWNER CLI: derive P_i/d_i │
                                              │ from master, decrypt,     │
                                              │ trilaterate, SVG map      │
                                              └───────────────────────────┘
 Anyone's BLE scanner ── antistalk.detect(): key groups that move with you ──▶ ALERT
```

| Path | What it is |
|---|---|
| `meshfind/` | Python reference implementation: `crypto`, `ratchet`, `adv`, `report` (ECIES), `mesh` (routing and simulator), `server` (HTTP and sqlite), `owner`, `locate`, `antistalk`, `uwb`, `plot` (SVG), `scenario`, `cli` |
| `firmware/common/` | Portable C core and ESP-IDF component: `mf_crypto_*` (reference or mbedTLS backend), `mf_proto` (ratchet, advertisement, ECIES), `mf_mesh` (routing state machine), `mf_uwb.h` (interface) |
| `firmware/tag/` | ESP-IDF app for ESP32-C3 (NimBLE broadcaster and observer) |
| `firmware/relay/` | ESP-IDF app for ESP32 (NimBLE observer and ESP-NOW). Set `MESHFIND_IS_GATEWAY` to build a gateway. |
| `vectors/meshfind_vectors.json` | Shared test vectors, generated by Python and checked by Python and C |
| `docs/` | [PROTOCOL.md](docs/PROTOCOL.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md), [UWB.md](docs/UWB.md) |

### Protocol summary

The full specification is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

- **Crypto suite**: X25519, HKDF-SHA256, ChaCha20-Poly1305 and SHA-256.
  X25519 is used instead of Apple's P-224 for its simple constant-time
  implementations, the absence of point-validation pitfalls (one zero check),
  and its availability in TweetNaCl, libsodium and mbedTLS. ChaCha20-Poly1305
  is fast and constant-time in software on any MCU, and its nonces are
  derived per ephemeral key, so they cannot be reused.
- **Ratchet**: `SK_0 = HKDF(MS, "chain-init")` and `SK_{i+1} = HKDF(SK_i,
  "chain-step")`. Each epoch's private key is `d_i = clamp(HKDF(SK_i,
  "epoch-priv"))`, with `P_i = X25519(d_i, 9)`. An epoch is 15 minutes. A
  second chain rotates daily for separated mode. The tag stores only the
  current chain value, so past keys are lost even if the tag is seized
  (forward secrecy).
- **Advertisement (31 bytes, legacy)**: the address is
  `P[0..5]` with the top bits set to `11`. The payload is
  `1E FF FF FF | status | P[6..31]`, where status carries the 2 key bits the
  address overwrote, the battery level, the separated flag and the version.
  Legacy rather than extended advertising, because ESP32 relays and every
  phone can receive it.
- **Report**: `E = X25519(e, 9)`, `S = X25519(e, P)`, then
  `HKDF(S, salt=E‖P)` gives the key and nonce. The envelope is
  `01 00 | SHA-256(P) | E | ChaCha20-Poly1305(26-byte sighting, aad=header)`,
  108 bytes in total.
- **Mesh**: a 12-byte header (magic, version and type, TTL, sender
  distance, content-derived message id). REPORT frames are 120 bytes, well
  under the ESP-NOW limit. A frame is forwarded only by nodes strictly closer
  to a gateway. Delivery is confirmed by passive ack or gateway ACK, with
  retries. Beacons build the gradient and carry the time.
- **Server**: stores envelopes indexed by `SHA-256(P_i)`. The owner asks for
  the hashes of the epochs it can derive, optionally padded with decoys.
- **Anti-stalking**: separated mode gives a daily key and a flag bit. The
  scanner-side detector stitches rotations by gap, RSSI and rotation phase,
  then alerts on long, multi-place co-travel.

### Threat model summary

The full analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

| What | Protected against | Not protected against |
|---|---|---|
| Report contents | relays, gateways, server, network | the owner's own compromised laptop |
| Tag identity over time | casual and long-term observers (15-minute rotation of key and address) | continuous observers stitching rotations by timing and RSSI (inherent; anti-stalking uses it) |
| Past locations after tag theft | yes (one-way ratchet), **if** the seeds were not left in the firmware image | an image that still contains the provisioning seeds: reflash, or enable flash encryption |
| Report authenticity | tampering and re-pointing (AEAD covers the key hash); envelope replay (dedup) | **anyone who hears the advertisement can submit false positions** for that epoch. This is a documented limit; private relay attestation is on the roadmap. |
| Mesh time | the tag clock (resynchronised only by authenticated owner tokens) | unauthenticated beacon time spoofing relay clocks (the owner ignores implausible timestamps) |
| Query privacy | contents | the server learns which hashes are queried together (decoys and Tor help; PIR is on the roadmap) |
| Stalking | rotating and separated meshfind tags carried by a victim (detected in simulation) | malicious custom firmware that never enters separated mode and rotates erratically |

## Build, run, test

<details>
<summary><b>Python, C core and firmware build commands</b></summary>

### Python (reference, server, owner CLI)

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[test]"
python -m pytest -q                                  # all tests, including the C-vs-Python check (needs a C compiler or ziglang)
```

End-to-end simulation (building, mesh, server, owner):

```bash
python -m meshfind simulate --seed 3 --svg sim.svg
# tag at (12.9, 16.1) m; 24 relays heard it; 24 reports reached the gateway over the mesh
# owner estimate (trilateration): (15.0, 15.3) m, error 2.28 m
```

Real-world flow:

```bash
python -m meshfind tag new mytag.json                # master secret: keep it private and backed up
python -m meshfind tag provision mytag.json          # sdkconfig lines for the tag firmware
python -m meshfind server --db reports.db --token "$UPLOAD_TOKEN"
python -m meshfind gateway --server http://127.0.0.1:8787 --serial /dev/ttyUSB0 --token "$UPLOAD_TOKEN"   # pip install pyserial
python -m meshfind query mytag.json --server http://127.0.0.1:8787 --hours 6 --decoys 32 --svg map.svg
python -m meshfind antistalk scans.jsonl             # JSONL: {"t","x","y","key","rssi","separated"}
```

### C core on the host

```bash
make -C firmware/common/test CC=gcc SAN=1            # ASan/UBSan, Linux/macOS
python tools/host_test.py                            # any OS: uses $CC, ziglang, or cc
```

### Firmware (ESP-IDF v5.2+)

```bash
cd firmware/tag   && idf.py set-target esp32c3 && idf.py menuconfig   # "meshfind tag": paste provision values
idf.py build flash monitor
cd firmware/relay && idf.py set-target esp32   && idf.py menuconfig   # "meshfind relay": node position, gateway?
idf.py build flash monitor
# optional mbedTLS crypto backend:
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;../sdkconfig.defaults.mbedtls" build
```

CI (`.github/workflows/ci.yml`, Ubuntu) runs the Python tests on 3.10 and
3.12, checks that the vector file is current, builds and runs the C core with
gcc and clang under ASan and UBSan, and builds the tag (esp32c3) and the
relay (esp32, both crypto backends) with `espressif/esp-idf-ci-action`
(IDF v5.2.2).

</details>

## Results (all on the host, all simulated)

| Test / experiment | Result |
|---|---|
| Python test suite (`python -m pytest -q`) | **127 passed** on Windows 10, Python 3.12 (includes building and running the C core) |
| C core vs Python vectors (`tools/host_test.py`, zig cc 0.17) | **665 checks, 0 failures**: RFC 7748, 8439 and 5869 vectors, ratchet, advertisements, presence, duty-cycle current model, ECIES seal and open (byte-identical), tamper rejection at every byte, mesh frames, forwarding table, C mesh simulation |
| Mesh: 40 random nodes, 2 gateways, unit-disc radio, 20 topologies × 38 reports | delivery **99.87 %** at 10 % per-link loss, **99.61 %** at 20 %, **99.08 %** at 30 % (no collision model); plot below |
| Indoor positioning: 50 × 30 m floor, relays on a 10 m grid, 4 dB shadowing, 100 random tag positions, through the full mesh and server path | matched TX power: median **1.13 m**, p90 2.42 m. Tag 6 dB weaker than modelled: median 2.16 m, p90 13.9 m. Tag 6 dB stronger: median 1.41 m, p90 2.91 m. |
| Anti-stalking: 200 simulated victim days | rotating stalker detected **200/200**. Spurious alerts on **9/200** days without a stalker (a stranger who walks with the victim for 20 minutes can be stitched to a café tag). |
| UWB maths | DS-TWR error under 1 cm with ±40 ppm clocks; SS-TWR off by metres |

<p align="center">
  <img src="docs/assets/mesh_delivery.png" alt="Mesh delivery ratio versus per-link loss, 40 nodes, 2 gateways, 20 random topologies" width="720"><br>
  <sub>Delivery vs per-link loss from <code>meshfind.mesh.MeshSimulator</code> (same setup as <code>tests/test_mesh.py</code>, 20 seeds).
  One topology misses 1 of 38 reports even at 0 % loss, so the band does not reach 100 %.
  Generated by <a href="docs/assets/make_figures.py"><code>docs/assets/make_figures.py</code></a>.</sub>
</p>

The radio models are simple: log-distance path loss with Gaussian shadowing
for BLE, and a unit disc with i.i.d. loss for ESP-NOW. Real buildings have
walls, multipath and body shadowing, so **expect worse numbers in the field**.

## Hardware validation / TODO for the author

> [!NOTE]
> ⏳ **Nothing below has been run on real hardware yet.** Every table is empty on purpose and is to be
> filled with real measurements only. The firmware **builds** in CI (ESP-IDF v5.2.2), but its behaviour
> on a target is untested.

<details>
<summary><b>Step-by-step bench plan with empty result tables (8 steps)</b></summary>

**1. Builds** (CI already builds all three; record the app sizes from a local build)
```bash
cd firmware/tag   && idf.py set-target esp32c3 build   # record binary size
cd firmware/relay && idf.py set-target esp32 build
cd firmware/relay && idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;../sdkconfig.defaults.mbedtls" build
```
| target | IDF version | builds? | app size |
|---|---|---|---|
| tag esp32c3 | | | |
| relay esp32 (ref crypto) | | | |
| relay esp32 (mbedTLS) | | | |

**2. On-target crypto check.** Port `firmware/common/test/test_main.c` into
an IDF unit-test app, or temporarily call the vector checks from `app_main`
with the JSON embedded via `EMBED_TXTFILES`. Record the X25519 timing.

| board | backend | vectors pass? | X25519 ms | report seal ms |
|---|---|---|---|---|
| ESP32-C3 | ref | | | |
| ESP32 | ref | | | |
| ESP32 | mbedTLS | | | |

**3. Advertisement on air.** Flash a provisioned tag, then capture with
nRF Connect or `btmon`/`bluetoothctl scan on`. Confirm that the address
equals `python -m meshfind tag keys mytag.json -n 1` and rotates at the
epoch boundary.

| check | result |
|---|---|
| address matches CLI | |
| rotates at epoch boundary (± s) | |
| interval matches battery table | |
| separated mode after timeout (set `SEPARATED_AFTER_MIN=2` for the test) | |

**4. Tag current draw** (PPK2 or similar, 3.0 V). Firmware already enables
automatic light sleep between ADV events and duty-cycled presence scans
(default 50 ms every 60 s). Leave cells empty until measured — do not fill
from `adv.adv_avg_current_ua` / simulation. Optional lower floor on boards
with a 32 kHz crystal:

```bash
cd firmware/tag
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.ext32k" build flash
```

| mode | interval | avg current | projected CR2032 / 1000 mAh LiPo life |
|---|---|---|---|
| near-owner | 2 s | | |
| separated | 1 s | | |
| with presence scan every 60 s | | | |

**5. BLE reception range** (relay RSSI and report rate vs distance):

| environment | distance | median RSSI | % of 10 s windows with a report |
|---|---|---|---|
| line of sight | 5 / 10 / 20 / 40 m | | |
| through 1 wall | | | |
| through 2 walls | | | |

**6. ESP-NOW mesh:**
```bash
python -m meshfind server --db hw.db
python -m meshfind gateway --server http://127.0.0.1:8787 --serial /dev/ttyUSB0
```
| nodes | hops to gateway | reports originated | reports at server | median latency |
|---|---|---|---|---|
| | | | | |

**7. Indoor positioning accuracy.** Place the tag at surveyed points and run
`python -m meshfind query mytag.json --server … --window 5`. Fit `--p0` and
`--n` from a calibration walk first.

| point | true (x, y) | estimate | error m | relays heard |
|---|---|---|---|---|
| | | | | |

**8. Anti-stalking field test.** Log scans from a phone or ESP32 to JSONL
while carrying a tag (and while not carrying one), then run
`python -m meshfind antistalk log.jsonl`.

| scenario | duration | alert? | time to alert |
|---|---|---|---|
| carrying a rotating tag | | | |
| carrying a separated tag | | | |
| no tag (false alarms) | | | |

</details>

## Roadmap

1. **Hardware bring-up**: everything in the section above.
2. Provisioning over serial or BLE, so seeds never live in an image; flash
   encryption guide.
3. Tag power measurements: firmware already light-sleeps between advertising
   events and duty-cycles presence scans; fill the current-draw table on
   hardware (main XTAL default, or `sdkconfig.defaults.ext32k` when present).
4. Signed gateway beacons (authenticated mesh time); opt-in private relay
   attestation (a relay signature inside the ciphertext); automatic node
   whitelisting for fixed sites.
5. An owner presence beacon on a phone or keyfob, and a phone scanner for
   anti-stalking.
6. Query privacy: hash-prefix bucketing or PIR.
7. BLE 5 coded-PHY long-range secondary advertisement (ESP32-C3/S3 relays).
8. Using the mesh from the router project as an IP backhaul (ESP-WIFI-MESH)
   instead of serial-attached gateways.
9. UWB DW3000 driver, responder and initiator ([docs/UWB.md](docs/UWB.md)).
10. Multi-floor positioning (per-floor fits, then floor selection by
    strongest-relay vote).

## Contributing, security, citation

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report weaknesses in the protocol or the implementation
privately, as described in [SECURITY.md](SECURITY.md). To cite meshfind, see [CITATION.cff](CITATION.cff).

## License

MIT. See [LICENSE](LICENSE). The X25519 field arithmetic in
`firmware/common/src/mf_crypto_ref.c` is derived from the public-domain
TweetNaCl (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers).
