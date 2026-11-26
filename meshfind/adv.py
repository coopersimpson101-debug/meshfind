"""BLE legacy advertisement codec for meshfind tags.

A 32-byte X25519 public key does not fit in a 31-byte legacy advertisement
next to the AD headers, so -- like OpenHaystack does for P-224 -- the first 6
key bytes become the BLE *static random* device address and the remaining 26
bytes go in a Manufacturer Specific Data AD structure.

Device address (shown MSB first, as in ``AA:BB:CC:DD:EE:FF``)::

    addr[0] = key[0] | 0xC0      # top two bits 0b11 = static random address
    addr[1..5] = key[1..5]

Advertising payload (exactly 31 bytes, ADV_NONCONN_IND)::

    off len  field
    0   1    AD length = 0x1E (30)
    1   1    AD type   = 0xFF (Manufacturer Specific Data)
    2   2    company id 0xFFFF (LE; SIG "testing" id, see PROTOCOL.md)
    4   1    status: b7..6 = key[0] >> 6   (bits lost to the address marker)
                     b5..4 = battery level (0 full .. 3 critical)
                     b3    = separated-mode flag
                     b2..0 = protocol version (1)
    5   26   key[6..31]

Because the address is derived from the key, the address rotates together
with the key, so a passive observer sees a fresh, unlinkable identity every
epoch.
"""

from __future__ import annotations

from dataclasses import dataclass

ADV_LEN = 31
AD_LEN_BYTE = 0x1E
AD_TYPE_MSD = 0xFF
COMPANY_ID = 0xFFFF
PROTO_VERSION = 1

BATT_FULL, BATT_MEDIUM, BATT_LOW, BATT_CRITICAL = 0, 1, 2, 3


class AdvError(ValueError):
    pass


@dataclass(frozen=True)
class TagAdvert:
    public_key: bytes
    battery: int = BATT_FULL
    separated: bool = False

    @property
    def status_bits(self) -> int:
        """Status byte minus the two key bits: what relays pass to the owner."""
        return ((self.battery & 3) << 4) | (int(self.separated) << 3) | PROTO_VERSION


def encode(advert: TagAdvert) -> tuple[bytes, bytes]:
    """Returns (address[6] MSB-first, payload[31])."""
    k = advert.public_key
    if len(k) != 32:
        raise AdvError("public key must be 32 bytes")
    if not 0 <= advert.battery <= 3:
        raise AdvError("battery must be 0..3")
    addr = bytes([k[0] | 0xC0]) + k[1:6]
    status = ((k[0] >> 6) << 6) | advert.status_bits
    payload = bytes([AD_LEN_BYTE, AD_TYPE_MSD, COMPANY_ID & 0xFF, COMPANY_ID >> 8, status]) + k[6:32]
    assert len(payload) == ADV_LEN
    return addr, payload


def decode(addr: bytes, payload: bytes) -> TagAdvert:
    """Parse a received advertisement; raises AdvError if it is not ours."""
    if len(addr) != 6:
        raise AdvError("address must be 6 bytes")
    if len(payload) != ADV_LEN:
        raise AdvError("wrong advertisement length")
    if payload[0] != AD_LEN_BYTE or payload[1] != AD_TYPE_MSD:
        raise AdvError("not a manufacturer-data advertisement")
    if payload[2] | (payload[3] << 8) != COMPANY_ID:
        raise AdvError("wrong company id")
    if addr[0] & 0xC0 != 0xC0:
        raise AdvError("address is not static random")
    status = payload[4]
    if status & 0x07 != PROTO_VERSION:
        raise AdvError("unsupported protocol version")
    k0 = (addr[0] & 0x3F) | (status & 0xC0)
    key = bytes([k0]) + addr[1:6] + payload[5:31]
    return TagAdvert(public_key=key, battery=(status >> 4) & 3, separated=bool(status & 0x08))


def battery_level(percent: int) -> int:
    if percent >= 60:
        return BATT_FULL
    if percent >= 30:
        return BATT_MEDIUM
    if percent >= 10:
        return BATT_LOW
    return BATT_CRITICAL


_BASE_INTERVAL_MS = {BATT_FULL: 2000, BATT_MEDIUM: 2000, BATT_LOW: 4000, BATT_CRITICAL: 8000}


def adv_interval_ms(battery_percent: int, separated: bool) -> int:
    """Battery-aware advertising interval.

    Separated tags advertise twice as often (easier to find and easier for
    victims' anti-stalking scanners to notice) but never faster than 1 s.
    """
    base = _BASE_INTERVAL_MS[battery_level(battery_percent)]
    if separated:
        base = max(1000, base // 2)
    return base


def adv_sleep_ms(interval_ms: int, tx_ms: int = 1) -> int:
    """Idle time between advertising events in a duty-cycled schedule."""
    if interval_ms <= 0:
        return 0
    if tx_ms >= interval_ms:
        return 0
    return interval_ms - tx_ms


def adv_avg_current_ua(interval_ms: int, tx_ua: int, sleep_ua: int, tx_ms: int = 1) -> int:
    """Modelled average current for duty-cycled advertising (not a measurement).

    ``tx_ua`` is the current while the radio transmits one ADV_NONCONN_IND;
    ``sleep_ua`` is the light-sleep / modem-sleep floor between events.
    """
    if interval_ms <= 0:
        return tx_ua
    tx_ms = min(tx_ms, interval_ms)
    sleep_ms = interval_ms - tx_ms
    return (tx_ua * tx_ms + sleep_ua * sleep_ms + interval_ms // 2) // interval_ms


def presence_avg_current_ua(period_s: int, scan_ms: int, scan_ua: int, base_ua: int) -> int:
    """Modelled average current with a short presence-scan window each period."""
    if period_s <= 0:
        return base_ua
    period_ms = period_s * 1000
    scan_ms = min(scan_ms, period_ms)
    idle_ms = period_ms - scan_ms
    return (scan_ua * scan_ms + base_ua * idle_ms + period_ms // 2) // period_ms


# --------------------------------------------------------------------------
# Owner-presence beacon (owner device -> tag). Keeps the tag in near-owner
# mode and lets it re-synchronise its clock from an authenticated token.
#
#   0 0x14 | 1 0xFF | 2..3 0xFFFF | 4 0x50 marker (low 3 bits 0 = never a tag
#   advert) | 5..20 token = HMAC-SHA256(presence_key, "presence"|u32 epoch)[:16]
# --------------------------------------------------------------------------
PRESENCE_MARKER = 0x50
PRESENCE_LEN = 21


def encode_presence(token: bytes) -> bytes:
    if len(token) != 16:
        raise AdvError("presence token must be 16 bytes")
    return bytes([0x14, AD_TYPE_MSD, COMPANY_ID & 0xFF, COMPANY_ID >> 8, PRESENCE_MARKER]) + token


def decode_presence(payload: bytes) -> bytes:
    if (len(payload) != PRESENCE_LEN or payload[0] != 0x14 or payload[1] != AD_TYPE_MSD
            or payload[2:4] != b"\xff\xff" or payload[4] != PRESENCE_MARKER):
        raise AdvError("not a presence beacon")
    return payload[5:]
