"""Strict base64url helpers and opaque identifiers (D-004)."""

from __future__ import annotations

import base64
import re
import secrets

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_ID_RE = re.compile(r"^(lab|veh|key|chl|evt)_[A-Za-z0-9_-]{22}$")


class EncodingError(ValueError):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, accepting only the canonical form.

    Rejects padding, foreign characters, impossible lengths and non-zero trailing
    bits, so every byte string has exactly one accepted text form.
    """
    if not isinstance(text, str) or not _B64URL_RE.fullmatch(text) or len(text) % 4 == 1:
        raise EncodingError("not canonical unpadded base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(data) != text:
        raise EncodingError("not canonical unpadded base64url")
    return data


def new_id(prefix: str) -> str:
    """128-bit random opaque identifier, e.g. ``veh_<22 chars>``."""
    return f"{prefix}_{b64url_encode(secrets.token_bytes(16))}"


def is_valid_id(value: object, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix + "_") and bool(_ID_RE.fullmatch(value))
