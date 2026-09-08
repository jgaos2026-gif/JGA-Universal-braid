from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL = "OASIS-BRAID-1"
ALLOWED_NODES = {"OASIS-PAVILION-01", "OASIS-THINKBOOK-01"}
ALLOWED_BRANCHES = {"control-room", "trench-city"}
ALLOWED_FAMILIES = {"INTEG", "ROUTE", "RECOV", "ROLE", "AUTH", "MEM"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


@dataclass(frozen=True)
class Identity:
    node_id: str
    identity_epoch: int
    private_key: Ed25519PrivateKey

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        return sha256(self.public_bytes)

    def sign(self, body: bytes) -> str:
        return b64(self.private_key.sign(body))

    def public_record(self) -> dict[str, Any]:
        return {
            "protocol": PROTOCOL,
            "node_id": self.node_id,
            "identity_epoch": self.identity_epoch,
            "public_key": b64(self.public_bytes),
            "fingerprint": self.fingerprint,
        }


def create_identity(root: Path, node_id: str, epoch: int = 1) -> Identity:
    if node_id not in ALLOWED_NODES:
        raise ValueError("node_id is not an admitted initial Control Room")
    root.mkdir(parents=True, exist_ok=True)
    private_path = root / "identity.pem"
    if private_path.exists():
        raise FileExistsError("identity already exists; refusing silent replacement")
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    identity = Identity(node_id, epoch, key)
    (root / "identity.json").write_text(json.dumps(identity.public_record(), indent=2) + "\n")
    return identity


def load_identity(root: Path) -> Identity:
    record = json.loads((root / "identity.json").read_text())
    key = serialization.load_pem_private_key((root / "identity.pem").read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("identity key type is not Ed25519")
    identity = Identity(record["node_id"], int(record["identity_epoch"]), key)
    if identity.fingerprint != record["fingerprint"]:
        raise ValueError("identity fingerprint mismatch")
    return identity


class EvidenceLedger:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def head(self) -> str:
        if not self.path.exists() or not self.path.stat().st_size:
            return "0" * 64
        last = self.path.read_text().splitlines()[-1]
        return json.loads(last)["entry_hash"]

    def append(self, event: str, outcome: str, details: dict[str, Any]) -> dict[str, Any]:
        record = {
            "event_id": str(uuid.uuid4()), "created_at": iso(utcnow()),
            "event": event, "outcome": outcome, "details": details,
            "previous_hash": self.head(),
        }
        record["entry_hash"] = sha256(canonical(record))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def verify(self) -> bool:
        previous = "0" * 64
        if not self.path.exists():
            return True
        for line in self.path.read_text().splitlines():
            record = json.loads(line)
            claimed = record.pop("entry_hash")
            if record["previous_hash"] != previous or sha256(canonical(record)) != claimed:
                return False
            previous = claimed
        return True


def sign_envelope(identity: Identity, destination: str, session_id: str, payload: Any,
                  branch: str = "control-room", family: str = "INTEG",
                  capability: str = "braid.exchange", ttl: int = 30,
                  message_id: str | None = None, created_at: datetime | None = None) -> dict[str, Any]:
    now = created_at or utcnow()
    body = {
        "protocol": PROTOCOL, "message_id": message_id or str(uuid.uuid4()),
        "session_id": session_id, "source_node": identity.node_id,
        "destination_node": destination, "branch": branch, "family": family,
        "capability": capability, "identity_epoch": identity.identity_epoch,
        "revision": 1, "created_at": iso(now), "expires_at": iso(now + timedelta(seconds=ttl)),
        "nonce": secrets.token_hex(16), "previous_hash": "0" * 64,
        "payload_hash": sha256(canonical(payload)), "payload": payload, "evidence_refs": [],
        "signer_fingerprint": identity.fingerprint,
    }
    body["signature"] = identity.sign(canonical(body))
    return body


class Verifier:
    def __init__(self, local_node: str, peer_record: dict[str, Any], ledger: EvidenceLedger):
        self.local_node = local_node
        self.peer = peer_record
        self.ledger = ledger
        self.seen: set[str] = set()

    def verify(self, envelope: dict[str, Any], now: datetime | None = None) -> bool:
        reason = "accepted"
        try:
            unsigned = dict(envelope)
            signature = unb64(unsigned.pop("signature"))
            if unsigned.get("protocol") != PROTOCOL: raise ValueError("wrong_protocol")
            if unsigned.get("destination_node") != self.local_node: raise ValueError("wrong_destination")
            if unsigned.get("source_node") != self.peer["node_id"]: raise ValueError("wrong_source")
            if unsigned.get("signer_fingerprint") != self.peer["fingerprint"]: raise ValueError("wrong_fingerprint")
            if unsigned.get("branch") not in ALLOWED_BRANCHES: raise ValueError("wrong_scope")
            if unsigned.get("family") not in ALLOWED_FAMILIES: raise ValueError("wrong_family")
            if sha256(canonical(unsigned.get("payload"))) != unsigned.get("payload_hash"): raise ValueError("altered_payload")
            check_time = now or utcnow()
            if parse_iso(unsigned["created_at"]) > check_time + timedelta(seconds=5): raise ValueError("future_message")
            if parse_iso(unsigned["expires_at"]) < check_time: raise ValueError("expired")
            if unsigned["message_id"] in self.seen: raise ValueError("replay")
            pub = Ed25519PublicKey.from_public_bytes(unb64(self.peer["public_key"]))
            pub.verify(signature, canonical(unsigned))
            self.seen.add(unsigned["message_id"])
            self.ledger.append("envelope.verify", "PASS", {"message_id": unsigned["message_id"]})
            return True
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            self.ledger.append("envelope.verify", "FAIL", {"message_id": envelope.get("message_id"), "reason": reason})
            return False


def sign_challenge(identity: Identity, nonce: str) -> dict[str, str]:
    body = canonical({"protocol": PROTOCOL, "node_id": identity.node_id, "nonce": nonce})
    return {"node_id": identity.node_id, "nonce": nonce, "fingerprint": identity.fingerprint,
            "signature": identity.sign(body)}


def verify_challenge(peer: dict[str, Any], proof: dict[str, str], nonce: str) -> bool:
    if proof.get("nonce") != nonce or proof.get("node_id") != peer["node_id"]:
        return False
    body = canonical({"protocol": PROTOCOL, "node_id": peer["node_id"], "nonce": nonce})
    try:
        Ed25519PublicKey.from_public_bytes(unb64(peer["public_key"])).verify(unb64(proof["signature"]), body)
        return True
    except Exception:
        return False


def seal_checkpoint(identity: Identity, ledger: EvidenceLedger, state: dict[str, Any], path: Path) -> dict[str, Any]:
    body = {"protocol": PROTOCOL, "node_id": identity.node_id, "created_at": iso(utcnow()),
            "ledger_head": ledger.head(), "state_hash": sha256(canonical(state)), "state": state,
            "certification": "PENDING_INDEPENDENT_TRIAD"}
    body["signature"] = identity.sign(canonical(body))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n")
    ledger.append("checkpoint.seal", "PASS", {"state_hash": body["state_hash"], "certification": body["certification"]})
    return body
