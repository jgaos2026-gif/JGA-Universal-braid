from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import EvidenceLedger, create_identity, load_identity, seal_checkpoint


def main() -> None:
    parser = argparse.ArgumentParser(prog="oasis-braid")
    parser.add_argument("--root", type=Path, default=Path(".oasis-braid"))
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init")
    init.add_argument("--node", required=True)
    subs.add_parser("status")
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
        print(json.dumps({"node_id": identity.node_id, "fingerprint": identity.fingerprint,
                          "ledger_valid": ledger.verify(), "ledger_head": ledger.head(),
                          "connection": "OFFLINE", "certification": "NOT_GRANTED"}, indent=2))
    else:
        identity = load_identity(args.root)
        ledger = EvidenceLedger(args.root / "evidence.jsonl")
        checkpoint = seal_checkpoint(identity, ledger, json.loads(args.state), args.root / "checkpoints" / "latest.json")
        print(json.dumps(checkpoint, indent=2))


if __name__ == "__main__":
    main()
