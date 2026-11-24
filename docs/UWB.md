# UWB last-metre finding (DW3000): design

**Status: design only.** The protocol maths in `meshfind/uwb.py` is
implemented and unit-tested: the request MAC, the STS key and the DS-TWR
estimator. The C interface is fixed in `firmware/common/include/mf_uwb.h`.
No DW3000 driver integration exists yet.

## Why

Positions from BLE RSSI are good to a few metres at best (see the README
results). Ultra-wideband two-way ranging gives roughly 10 cm accuracy. With a
secure STS it also gives **distance bounding**: an attacker cannot make the
tag appear *closer* than it is, which addresses the relay-attack limit in the
threat model.

## Hardware

- Tag: ESP32-C3 + Qorvo DW3000 module (e.g. DWM3000) on SPI. The DW3000
  stays in DEEP_SLEEP (under 1 µA) until a ranging request arrives.
- Owner device: a second ESP32 + DW3000 (a handheld "finder"), or a UWB
  phone in the future.
- Channel 5 or 9, 6.8 Mb/s, STS mode 1 (STS after the SFD, with the PHR).

## Flow

```
owner finder                                   tag
------------                                   ---
BLE adv: RANGING_REQ(nonce, MAC)  ───────────▶ (presence-scan window hears it)
                                               verify MAC for the current epoch, check
                                               the nonce has not been seen, wake the DW3000,
                                               load the STS key
UWB POLL        ─────────────────────────────▶ rx at t2
                ◀───────────────────────────── UWB RESP  tx at t3 = t2 + Db
rx t4; Ra = t4 - t1
UWB FINAL(Ra, Da) tx t5 = t4 + Da  ──────────▶ rx at t6; Rb = t6 - t3
                ◀───────────────────────────── UWB REPORT(Rb, Db)
ToF = (Ra*Rb - Da*Db) / (Ra + Rb + Da + Db)
distance = ToF * c
repeat for about 10 Hz updates, then the tag sleeps after 30 s of silence
```

## Messages

**BLE ranging request** (29 bytes of advertising data):

| off | len | field |
|---|---|---|
| 0 | 1 | `0x1C` |
| 1 | 1 | `0xFF` Manufacturer Specific Data |
| 2 | 2 | `0xFFFF` |
| 4 | 1 | `0x51` marker |
| 5 | 8 | nonce (random, single use) |
| 13 | 16 | `HMAC-SHA256(HKDF(SK_i, "meshfind/v1/uwb-req"), u32 epoch ‖ nonce)[:16]` |

Only the owner, who knows `SK_i`, can wake the UWB radio. That prevents
battery-drain attacks and probing for the tag. The tag tracks the nonces it
has used, so a recorded request cannot be replayed.

**STS key** = `HKDF(SK_i, salt=nonce, "meshfind/v1/uwb-sts")[:16]`. The STS
IV is derived the same way with the info string `.../uwb-sts-iv`. The key is
unique per session and epoch.

**UWB frames** (802.15.4z data frames, payload as in `mf_uwb.h`): POLL `0x61`,
RESP `0x62`, FINAL `0x63` (carrying Ra and Da as 40-bit tick counts), REPORT
`0x64` (carrying Rb and Db). Each frame includes a 4-byte session id (nonce
prefix) and a sequence number. Range is accepted only if `sts_ok` is set for
every frame (the DW3000 STS quality check).

## Why DS-TWR

`tests/test_uwb.py` simulates clocks that are off by ±40 ppm. Asymmetric
DS-TWR stays under 1 cm of error, while single-sided TWR is off by metres
once the reply time is 300 µs. Crystal tolerance alone makes SS-TWR unusable
here.

## Roadmap

1. A DW3000 SPI driver shim for ESP-IDF that implements `mf_uwb_driver_t`.
2. Responder state machine on the tag, initiator on the finder.
3. Antenna-delay calibration procedure: a two-board known-distance fit,
   recorded in NVS.
4. AoA (DW3000 PDoA variant) for direction arrows.
5. Bounding check: refuse ranges whose STS quality is below threshold, and
   report the lower bound only.
