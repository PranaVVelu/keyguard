"""Generate docs/test-vectors/kg-fob-v1.json (D-010).

Shared by the Python and TypeScript suites, like kg-auth-v1.json. Encoding vectors are deterministic; the verify
vectors use a fresh key whose private half is discarded.

    uv run python scripts/gen_fob_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.evidence.client_sim import SimulatedClientKey  # noqa: E402
from app.security.protocol import DOMAIN_TAG_FOB, FOB_PROTOCOL_VERSION, MAX_FOB_COUNTER, FobFields, encode_fob_message  # noqa: E402

OUT = Path(__file__).resolve().parents[3] / "docs" / "test-vectors" / "kg-fob-v1.json"
BASE = {"vehicle_id": "veh_AAAAAAAAAAAAAAAAAAAAAA", "key_id": "key_BBBBBBBBBBBBBBBBBBBBBB", "counter": 1, "action": "unlock"}


def main() -> None:
    cases = [
        ("unlock-counter-1", BASE),
        ("lock-counter-2", {**BASE, "counter": 2, "action": "lock"}),
        ("max-safe-counter", {**BASE, "counter": MAX_FOB_COUNTER}),
    ]
    encoding = [{"name": n, "fields": f, "message_hex": encode_fob_message(FobFields(**f)).hex()} for n, f in cases]

    key = SimulatedClientKey()
    good = encode_fob_message(FobFields(**BASE))
    replayed_as_lock = encode_fob_message(FobFields(**{**BASE, "action": "lock"}))
    sig = key.sign_p1363(good)
    verify = {
        "public_key_spki_b64url": key.spki_b64url,
        "cases": [
            {"name": "valid", "message_hex": good.hex(), "signature": sig, "expected": True},
            {"name": "action-changed", "message_hex": replayed_as_lock.hex(), "signature": sig, "expected": False},
        ],
    }
    OUT.write_text(json.dumps({
        "protocol": FOB_PROTOCOL_VERSION,
        "spec": "docs/DECISIONS.md D-010",
        "domain_tag_hex": DOMAIN_TAG_FOB.hex(),
        "encoding": encoding,
        "verify": verify,
    }, indent=2) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
