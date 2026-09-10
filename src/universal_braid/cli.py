from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import (
    EvidenceLedger, create_handshake_challenge, create_identity, import_peer,
    load_identity, load_peer, respond_to_handshake, seal_checkpoint,
    verify_handshake_response,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="oasis-braid")
    parser.add_argument("--root", type=Path, default=Path(".oasis-braid"))
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init")
    init.add_argument("--node", required=True)
    subs.add_parser("status")
    peer_import = subs.add_parser("peer-import")
    peer_import.add_argument("--identity", type=Path, required=True)
    challenge = subs.add_parser("challenge-create")
    challenge.add_argument("--peer", required=True)
    challenge.add_argument("--out", type=Path, required=True)
    respond = subs.add_parser("challenge-respond")
    respond.add_argument("--challenge", type=Path, required=True)
    respond.add_argument("--out", type=Path, required=True)
    verify = subs.add_parser("challenge-verify")
    verify.add_argument("--challenge", type=Path, required=True)
    verify.add_argument("--response", type=Path, required=True)
    seal = subs.add_parser("disconnect")
    seal.add_argument("--state", default='{"connection":"OFFLINE"}')
    args = parser.parse_args()
    if args.command == "init":
        identity = create_identity(args.root, args.node)
        EvidenceLedger(args.root / "evidence.jsonl").append("identity.create", "PASS", {"node_id": identity.node_id, "fingerprint": identity.fingerprint})
        print(json.dumps(identity.public_record(), indent=2))
    elif args.command == "status":
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        verifications = []
        for path in sorted((args.root / "verifications").glob("*.json")) if (args.root / "verifications").exists() else []:
            verifications.append(json.loads(path.read_text(encoding="utf-8")))
        print(json.dumps({"node_id": identity.node_id, "fingerprint": identity.fingerprint,
                          "ledger_valid": ledger.verify(), "ledger_head": ledger.head(),
                          "connection": "OFFLINE", "certification": "NOT_GRANTED",
                          "peer_verifications": verifications}, indent=2))
    elif args.command == "peer-import":
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        peer = import_peer(args.root, identity, args.identity)
        ledger.append("peer.import", "PASS", {"node_id": peer["node_id"], "fingerprint": peer["fingerprint"]})
        print(json.dumps(peer, indent=2))
    elif args.command == "challenge-create":
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        peer = load_peer(args.root, args.peer)
        record = create_handshake_challenge(identity, peer)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        ledger.append("handshake.challenge.create", "PASS", {"peer": peer["node_id"], "session_id": record["session_id"]})
        print(json.dumps({"out": str(args.out), "session_id": record["session_id"]}, indent=2))
    elif args.command == "challenge-respond":
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        challenge_record = json.loads(args.challenge.read_text(encoding="utf-8"))
        peer = load_peer(args.root, challenge_record["source_node"])
        response = respond_to_handshake(identity, peer, challenge_record)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(response, indent=2) + "\n", encoding="utf-8")
        ledger.append("handshake.challenge.respond", "PASS", {"peer": peer["node_id"], "session_id": response["session_id"]})
        print(json.dumps({"out": str(args.out), "session_id": response["session_id"]}, indent=2))
    elif args.command == "challenge-verify":
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        challenge_record = json.loads(args.challenge.read_text(encoding="utf-8"))
        response_record = json.loads(args.response.read_text(encoding="utf-8"))
        peer = load_peer(args.root, response_record["source_node"])
        result = verify_handshake_response(args.root, identity, peer, challenge_record, response_record)
        ledger.append("handshake.response.verify", "PASS", result)
        print(json.dumps(result, indent=2))
    else:
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        checkpoint = seal_checkpoint(identity, ledger, json.loads(args.state), args.root / "checkpoints" / "latest.json")
        print(json.dumps(checkpoint, indent=2))


if __name__ == "__main__":
    main()
