"""
TrustShield - Evidence sealing.

A forensic case is sealed with an HMAC-SHA256 signature computed with a server
secret over the case id, the SHA-256 of the original uploaded bytes, the SHA-256
of the stored dossier, and the creation timestamp. Anyone holding the server key
(only the server) can produce a valid seal, so a database edit to the dossier,
the hash, or the timestamp is detected on verification.
"""

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional

from security import IS_PRODUCTION, _load_secret

SEAL_ALGORITHM = "HMAC-SHA256"

_seal_key = (os.getenv("EVIDENCE_SIGNING_KEY", "").strip() or _load_secret("SECRET_KEY")).encode()


def canonical_json(obj: Any) -> str:
    """Stable serialisation so the same dossier always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _message(case_id: str, evidence_hash: str, dossier_json: str, created_at_iso: str) -> bytes:
    dossier_digest = sha256_hex(dossier_json.encode("utf-8"))
    return "\n".join([case_id, (evidence_hash or "").lower(), dossier_digest, created_at_iso]).encode("utf-8")


def seal(case_id: str, evidence_hash: str, dossier_json: str, created_at_iso: str) -> str:
    return hmac.new(_seal_key, _message(case_id, evidence_hash, dossier_json, created_at_iso), hashlib.sha256).hexdigest()


def verify_seal(case_id: str, evidence_hash: str, dossier_json: str, created_at_iso: str, signature: Optional[str]) -> bool:
    if not signature:
        return False
    expected = seal(case_id, evidence_hash, dossier_json, created_at_iso)
    return hmac.compare_digest(expected, signature)


def integrity_block(status: str, signature: Optional[str], sealed_at_iso: Optional[str]) -> Dict[str, Any]:
    """Structure the report generator renders verbatim (it adds no claims of its own)."""
    return {
        "status": status,
        "signature": signature,
        "sealed_at": sealed_at_iso,
        "algorithm": SEAL_ALGORITHM,
    }
