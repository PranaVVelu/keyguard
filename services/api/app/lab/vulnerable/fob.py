"""A naive key-fob receiver with no rolling counter. DO NOT USE OUTSIDE THE ATTACK LAB.

What it gets right: it verifies a real ECDSA P-256 signature over the same kg-fob-v1 bytes the production
engine uses (D-010).
What it gets wrong, on purpose: it keeps no record of counters it has accepted, so any genuine press can be
replayed forever. Compare app/security/fob.py, which advances last_counter atomically.
"""

from __future__ import annotations

from app.security.protocol import FobFields, ProtocolError, encode_fob_message, load_public_key, verify_signature


class CounterlessFobReceiver:
    """In-memory, per-scenario state only."""

    def __init__(self, *, vehicle_id: str, key_id: str, spki_b64url: str) -> None:
        self.vehicle_id, self.key_id, self._spki = vehicle_id, key_id, spki_b64url
        self.lock_state = "locked"

    def press(self, *, counter: int, action: str, signature: str) -> tuple[str, str | None]:
        try:
            key, _ = load_public_key(self._spki)
            ok = verify_signature(key, encode_fob_message(FobFields(self.vehicle_id, self.key_id, counter, action)), signature)
        except ProtocolError as exc:
            return "deny", exc.code
        if not ok:
            return "deny", "SIGNATURE_INVALID"
        # BUG (intentional): no counter check, so old presses stay valid forever.
        self.lock_state = "unlocked" if action == "unlock" else "locked"
        return "allow", None
