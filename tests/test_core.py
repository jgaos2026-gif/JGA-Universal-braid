import copy
from datetime import timedelta

from universal_braid.core import (
    EvidenceLedger, Verifier, create_handshake_challenge, create_identity,
    import_peer, respond_to_handshake, sign_challenge, sign_envelope, utcnow,
    verify_challenge, verify_handshake_response,
)


def pair(tmp_path):
    a = create_identity(tmp_path / "a", "OASIS-PAVILION-01")
    b = create_identity(tmp_path / "b", "OASIS-THINKBOOK-01")
    ledger = EvidenceLedger(tmp_path / "b" / "evidence.jsonl")
    return a, b, ledger, Verifier(b.node_id, a.public_record(), ledger)


def test_distinct_identity_and_challenge(tmp_path):
    a, b, _, _ = pair(tmp_path)
    assert a.fingerprint != b.fingerprint
    proof = sign_challenge(a, "fresh-nonce")
    assert verify_challenge(a.public_record(), proof, "fresh-nonce")
    assert not verify_challenge(a.public_record(), proof, "other-nonce")


def test_authorized_envelope_and_replay_visible(tmp_path):
    a, b, ledger, verifier = pair(tmp_path)
    message = sign_envelope(a, b.node_id, "session", {"kind": "heartbeat"})
    assert verifier.verify(message)
    assert not verifier.verify(message)
    assert ledger.verify()
    text = ledger.path.read_text()
    assert '"outcome": "PASS"' in text and '"outcome": "FAIL"' in text and "replay" in text


def test_altered_expired_and_wrong_scope_fail(tmp_path):
    a, b, ledger, verifier = pair(tmp_path)
    altered = sign_envelope(a, b.node_id, "s1", {"value": 1})
    altered["payload"]["value"] = 2
    assert not verifier.verify(altered)
    expired = sign_envelope(a, b.node_id, "s2", {}, ttl=1, created_at=utcnow() - timedelta(minutes=1))
    assert not verifier.verify(expired)
    wrong = sign_envelope(a, b.node_id, "s3", {})
    wrong["branch"] = "owner-root"
    assert not verifier.verify(wrong)
    assert ledger.verify()


def test_tampered_ledger_fails(tmp_path):
    _, _, ledger, verifier = pair(tmp_path)
    ledger.append("negative.test", "FAIL", {"visible": True})
    assert ledger.verify()
    ledger.path.write_text(ledger.path.read_text().replace("negative.test", "erased.test"))
    assert not ledger.verify()


def test_offline_mutual_handshake_is_verified_but_not_certified(tmp_path):
    a_root, b_root = tmp_path / "a", tmp_path / "b"
    a = create_identity(a_root, "OASIS-PAVILION-01")
    b = create_identity(b_root, "OASIS-THINKBOOK-01")
    a_peer = import_peer(a_root, a, b_root / "identity.json")
    b_peer = import_peer(b_root, b, a_root / "identity.json")
    challenge = create_handshake_challenge(a, a_peer)
    response = respond_to_handshake(b, b_peer, challenge)
    result = verify_handshake_response(a_root, a, a_peer, challenge, response)
    assert result["authentication"] == "MUTUALLY_VERIFIED"
    assert result["connection"] == "OFFLINE"
    assert result["certification"] == "NOT_GRANTED"
    assert result["reason"] == "PENDING_INDEPENDENT_TRIAD"


def test_tampered_handshake_response_fails(tmp_path):
    a_root, b_root = tmp_path / "a", tmp_path / "b"
    a = create_identity(a_root, "OASIS-PAVILION-01")
    b = create_identity(b_root, "OASIS-THINKBOOK-01")
    a_peer = import_peer(a_root, a, b_root / "identity.json")
    b_peer = import_peer(b_root, b, a_root / "identity.json")
    challenge = create_handshake_challenge(a, a_peer)
    response = respond_to_handshake(b, b_peer, challenge)
    response["nonce"] = "altered"
    try:
        verify_handshake_response(a_root, a, a_peer, challenge, response)
    except Exception:
        pass
    else:
        raise AssertionError("tampered handshake response was accepted")
