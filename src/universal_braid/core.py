from __future__ import annotations

import base64
from contextlib import contextmanager
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
MAX_HANDSHAKE_TTL_SECONDS = 300


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


def validate_public_identity(record: dict[str, Any]) -> dict[str, Any]:
    """Validate the public identity and its self-signature."""
    if not isinstance(record, dict) or record.get("protocol") != PROTOCOL:
        raise ValueError("wrong identity protocol")
    if record.get("node_id") not in ALLOWED_NODES:
        raise ValueError("unadmitted node identity")
    epoch = record.get("identity_epoch")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise ValueError("invalid identity epoch")
    public_key = unb64(record["public_key"])
    if len(public_key) != 32:
        raise ValueError("invalid Ed25519 public key")
    fingerprint = sha256(public_key)
    if fingerprint != record.get("fingerprint"):
        raise ValueError("identity fingerprint mismatch")
    normalized = {
        "protocol": PROTOCOL,
        "node_id": record["node_id"],
        "identity_epoch": epoch,
        "public_key": record["public_key"],
        "fingerprint": fingerprint,
    }
    signature = unb64(record["identity_signature"])
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical(normalized))
    return {**normalized, "identity_signature": record["identity_signature"]}
def import_peer(root: Path, identity: Identity, source: Path) -> dict[str, Any]:
    peer = validate_public_identity(json.loads(source.read_text(encoding="utf-8")))
    if peer["node_id"] == identity.node_id:
        raise ValueError("refusing to import local identity as a peer")
    path = root / "peers" / f'{peer["node_id"]}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = validate_public_identity(json.loads(path.read_text(encoding="utf-8")))
        if existing != peer:
            raise FileExistsError("peer identity changed; explicit rotation is required")
        return peer
    path.write_text(json.dumps(peer, indent=2) + "\n", encoding="utf-8")
    return peer


def load_peer(root: Path, node_id: str) -> dict[str, Any]:
    return validate_public_identity(json.loads(
        (root / "peers" / f"{node_id}.json").read_text(encoding="utf-8")
    ))


def create_handshake_challenge(identity: Identity, peer: dict[str, Any], ttl: int = MAX_HANDSHAKE_TTL_SECONDS) -> dict[str, Any]:
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= MAX_HANDSHAKE_TTL_SECONDS:
        raise ValueError("handshake TTL must be an integer from 1 to 300 seconds")
    peer = validate_public_identity(peer)
    if peer["node_id"] == identity.node_id:
        raise ValueError("refusing a handshake with the local identity")
    now = utcnow()
    body = {
        "protocol": PROTOCOL,
        "kind": "HANDSHAKE_CHALLENGE",
        "session_id": str(uuid.uuid4()),
        "source_node": identity.node_id,
        "destination_node": peer["node_id"],
        "identity_epoch": identity.identity_epoch,
        "nonce": secrets.token_hex(32),
        "created_at": iso(now),
        "expires_at": iso(now + timedelta(seconds=ttl)),
        "signer_fingerprint": identity.fingerprint,
    }
    body["signature"] = identity.sign(canonical(body))
    return body


def _verify_signed_handshake(record: dict[str, Any], peer: dict[str, Any], local_node: str,
                             expected_kind: str, now: datetime | None = None) -> None:
    unsigned = dict(record)
    signature = unb64(unsigned.pop("signature"))
    if unsigned.get("protocol") != PROTOCOL or unsigned.get("kind") != expected_kind:
        raise ValueError("wrong handshake protocol or kind")
    if unsigned.get("source_node") != peer["node_id"]:
        raise ValueError("wrong handshake source")
    if unsigned.get("destination_node") != local_node:
        raise ValueError("wrong handshake destination")
    if unsigned.get("signer_fingerprint") != peer["fingerprint"]:
        raise ValueError("wrong handshake fingerprint")
    if unsigned.get("identity_epoch") != peer["identity_epoch"]:
        raise ValueError("wrong handshake identity epoch")
    check_time = now or utcnow()
    created = parse_iso(unsigned["created_at"])
    expires = parse_iso(unsigned["expires_at"])
    if created > check_time + timedelta(seconds=5):
        raise ValueError("future handshake")
    if expires <= check_time:
        raise ValueError("expired handshake")
    lifetime = (expires - created).total_seconds()
    if lifetime <= 0 or lifetime > MAX_HANDSHAKE_TTL_SECONDS:
        raise ValueError("handshake validity window exceeds policy")
    if not isinstance(unsigned.get("session_id"), str) or not unsigned["session_id"]:
        raise ValueError("missing handshake session id")
    if not isinstance(unsigned.get("nonce"), str) or len(unsigned["nonce"]) != 64:
        raise ValueError("invalid handshake nonce")
    Ed25519PublicKey.from_public_bytes(unb64(peer["public_key"])).verify(signature, canonical(unsigned))


def respond_to_handshake(identity: Identity, peer: dict[str, Any], challenge: dict[str, Any]) -> dict[str, Any]:
    _verify_signed_handshake(challenge, peer, identity.node_id, "HANDSHAKE_CHALLENGE")
    body = {
        "protocol": PROTOCOL,
        "kind": "HANDSHAKE_RESPONSE",
        "session_id": challenge["session_id"],
        "source_node": identity.node_id,
        "destination_node": peer["node_id"],
        "identity_epoch": identity.identity_epoch,
        "nonce": challenge["nonce"],
        "challenge_hash": sha256(canonical(challenge)),
        "created_at": iso(utcnow()),
        "expires_at": challenge["expires_at"],
        "signer_fingerprint": identity.fingerprint,
    }
    body["signature"] = identity.sign(canonical(body))
    return body


def verify_handshake_response(root: Path, identity: Identity, peer: dict[str, Any],
                              challenge: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    peer = validate_public_identity(peer)
    if challenge.get("source_node") != identity.node_id:
        raise ValueError("challenge was not issued by this node")
    if challenge.get("destination_node") != peer["node_id"]:
        raise ValueError("challenge destination mismatch")
    _verify_signed_handshake(challenge, identity.public_record(), peer["node_id"], "HANDSHAKE_CHALLENGE")
    ledger = EvidenceLedger(root / "evidence.jsonl")
    session_id = response.get("session_id")
    _verify_signed_handshake(response, peer, identity.node_id, "HANDSHAKE_RESPONSE")
    if response.get("session_id") != challenge.get("session_id"):
        raise ValueError("handshake session mismatch")
    if response.get("nonce") != challenge.get("nonce"):
        raise ValueError("handshake nonce mismatch")
    if response.get("challenge_hash") != sha256(canonical(challenge)):
        raise ValueError("handshake challenge mismatch")
    result = {
        "protocol": PROTOCOL, "peer_node": peer["node_id"],
        "peer_fingerprint": peer["fingerprint"], "session_id": session_id,
        "verified_at": iso(utcnow()), "authentication": "MUTUALLY_VERIFIED",
        "connection": "OFFLINE", "certification": "NOT_GRANTED",
        "reason": "PENDING_INDEPENDENT_TRIAD",
    }
    accepted = ledger.append_once(
        "handshake.response.verify",
        {"session_id": session_id, "peer_node": peer["node_id"]},
        {"session_id": session_id, "peer_node": peer["node_id"],
         "peer_fingerprint": peer["fingerprint"]}
    )
    if not accepted:
        raise ValueError("handshake replay refused")
    path = root / "verifications" / f'{peer["node_id"]}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + "." + str(uuid.uuid4()) + ".tmp")
    with temp_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)
    return result

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
        body = {
            "protocol": PROTOCOL,
            "node_id": self.node_id,
            "identity_epoch": self.identity_epoch,
            "public_key": b64(self.public_bytes),
            "fingerprint": self.fingerprint,
        }
        return {**body, "identity_signature": self.sign(canonical(body))}


def create_identity(root: Path, node_id: str, epoch: int = 1) -> Identity:
    if node_id not in ALLOWED_NODES:
        raise ValueError("node_id is not an admitted initial Control Room")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise ValueError("identity epoch must be a positive integer")
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
    record = validate_public_identity(json.loads((root / "identity.json").read_text(encoding="utf-8")))
    key = serialization.load_pem_private_key((root / "identity.pem").read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("identity key type is not Ed25519")
    identity = Identity(record["node_id"], record["identity_epoch"], key)
    if identity.public_record() != record:
        raise ValueError("local identity record does not match private key")
    return identity

class EvidenceLedger:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = path.with_suffix(path.suffix + ".lock")

    @contextmanager
    def _locked(self):
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            yield
        finally:
            if locked:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_verified_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        previous = "0" * 64
        records: list[dict[str, Any]] = []
        try:
            raw = self.path.read_text(encoding="utf-8")
            if raw and not raw.endswith("\n"):
                raise ValueError("incomplete final record")
            for line in raw.splitlines():
                if not line.strip():
                    raise ValueError("blank ledger line")
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("ledger entry is not an object")
                claimed = record.get("entry_hash")
                unsigned = {key: value for key, value in record.items() if key != "entry_hash"}
                if not isinstance(claimed, str) or unsigned.get("previous_hash") != previous:
                    raise ValueError("ledger chain link mismatch")
                if sha256(canonical(unsigned)) != claimed:
                    raise ValueError("ledger entry hash mismatch")
                previous = claimed
                records.append(record)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("EVIDENCE_LEDGER_CORRUPT: " + str(exc)) from exc
        return records

    def records(self) -> list[dict[str, Any]]:
        with self._locked():
            return self._read_verified_unlocked()

    def head(self) -> str:
        with self._locked():
            records = self._read_verified_unlocked()
            return records[-1]["entry_hash"] if records else "0" * 64

    def _append_unlocked(self, event: str, outcome: str, details: dict[str, Any]) -> dict[str, Any]:
        records = self._read_verified_unlocked()
        record = {
            "event_id": str(uuid.uuid4()), "created_at": iso(utcnow()),
            "event": event, "outcome": outcome, "details": details,
            "previous_hash": records[-1]["entry_hash"] if records else "0" * 64,
        }
        record["entry_hash"] = sha256(canonical(record))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def append(self, event: str, outcome: str, details: dict[str, Any]) -> dict[str, Any]:
        with self._locked():
            return self._append_unlocked(event, outcome, details)

    def append_once(self, event: str, unique_fields: dict[str, Any],
                    details: dict[str, Any]) -> bool:
        """Atomically persist one accepted event for a unique identity tuple."""
        with self._locked():
            records = self._read_verified_unlocked()
            replay = any(
                record.get("event") == event
                and record.get("outcome") == "PASS"
                and all(record.get("details", {}).get(key) == value
                        for key, value in unique_fields.items())
                for record in records
            )
            if replay:
                self._append_unlocked(event, "FAIL", {
                    **details, "reason": "replay", "replayed_fields": unique_fields
                })
                return False
            self._append_unlocked(event, "PASS", details)
            return True

    def verify(self) -> bool:
        try:
            with self._locked():
                self._read_verified_unlocked()
            return True
        except (OSError, ValueError):
            return False
def sign_envelope(identity: Identity, destination: str, session_id: str, payload: Any,
                  branch: str = "control-room", family: str = "INTEG",
                  capability: str = "braid.exchange", ttl: int = 30,
                  message_id: str | None = None, created_at: datetime | None = None) -> dict[str, Any]:
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= MAX_HANDSHAKE_TTL_SECONDS:
        raise ValueError("message TTL must be an integer from 1 to 300 seconds")
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
        self.peer = validate_public_identity(peer_record)
        self.ledger = ledger
        records = ledger.records()
        self.seen: set[str] = {
            str(record.get("details", {}).get("message_id"))
            for record in records
            if record.get("event") == "envelope.verify" and record.get("outcome") == "PASS"
        }
        self.seen_nonces: set[str] = {
            str(record.get("details", {}).get("nonce"))
            for record in records
            if record.get("event") == "envelope.verify" and record.get("outcome") == "PASS"
        }

    def verify(self, envelope: dict[str, Any], now: datetime | None = None) -> bool:
        try:
            unsigned = dict(envelope)
            signature = unb64(unsigned.pop("signature"))
            if unsigned.get("protocol") != PROTOCOL: raise ValueError("wrong_protocol")
            if unsigned.get("destination_node") != self.local_node: raise ValueError("wrong_destination")
            if unsigned.get("source_node") != self.peer["node_id"]: raise ValueError("wrong_source")
            if unsigned.get("signer_fingerprint") != self.peer["fingerprint"]: raise ValueError("wrong_fingerprint")
            if unsigned.get("identity_epoch") != self.peer["identity_epoch"]: raise ValueError("wrong_identity_epoch")
            if unsigned.get("branch") not in ALLOWED_BRANCHES: raise ValueError("wrong_scope")
            if unsigned.get("family") not in ALLOWED_FAMILIES: raise ValueError("wrong_family")
            if sha256(canonical(unsigned.get("payload"))) != unsigned.get("payload_hash"): raise ValueError("altered_payload")
            check_time = now or utcnow()
            if parse_iso(unsigned["created_at"]) > check_time + timedelta(seconds=5): raise ValueError("future_message")
            expires = parse_iso(unsigned["expires_at"])
            created = parse_iso(unsigned["created_at"])
            if expires <= check_time: raise ValueError("expired")
            lifetime = (expires - created).total_seconds()
            if lifetime <= 0 or lifetime > MAX_HANDSHAKE_TTL_SECONDS: raise ValueError("invalid_message_ttl")
            if not isinstance(unsigned.get("capability"), str) or not unsigned["capability"].strip() or len(unsigned["capability"]) > 128:
                raise ValueError("invalid_capability")
            message_id = unsigned.get("message_id")
            nonce = unsigned.get("nonce")
            if not isinstance(message_id, str) or not message_id: raise ValueError("missing_message_id")
            if not isinstance(nonce, str) or not nonce: raise ValueError("missing_nonce")
            if message_id in self.seen or nonce in self.seen_nonces: raise ValueError("replay")
            pub = Ed25519PublicKey.from_public_bytes(unb64(self.peer["public_key"]))
            pub.verify(signature, canonical(unsigned))
            accepted = self.ledger.append_once(
                "envelope.verify",
                {"message_id": message_id, "nonce": nonce},
                {"message_id": message_id, "nonce": nonce}
            )
            if not accepted:
                raise ValueError("replay")
            self.seen.add(message_id)
            self.seen_nonces.add(nonce)
            return True
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            try:
                self.ledger.append("envelope.verify", "FAIL", {
                    "message_id": envelope.get("message_id"), "reason": reason
                })
            except (OSError, ValueError):
                pass
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
