# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Tag power management: automatic light sleep between advertising events, BT modem sleep, and duty-cycled owner-presence scans (`MESHFIND_TAG_PRESENCE_SCAN_MS`)
- Analytical average-current helpers (`mf_adv_avg_current_ua` / `adv.adv_avg_current_ua`) for scheduling tests — not hardware measurements
- Optional `firmware/tag/sdkconfig.defaults.ext32k` overlay for boards with an external 32 kHz crystal

## [0.1.0] - 2026-11-25

First public release of an offline, end-to-end encrypted Find My protocol for DIY trackers over an ESP32 mesh.

### Added
- X25519 + HKDF-SHA256 + ChaCha20-Poly1305; 15-minute key ratchet with unlinkable rotating adverts
- 31-byte legacy BLE advert, 108-byte ECIES location report, ESP-NOW store-and-forward mesh routing
- Portable C core byte-identical to the Python reference (vector checks); ESP-IDF tag and relay firmware build in CI
- Simulation: 99%+ delivery at up to 30% link loss, 1.13 m median indoor positioning error, unknown-tracker detection

[0.1.0]: https://github.com/coopersimpson101-debug/meshfind/releases/tag/v0.1.0
