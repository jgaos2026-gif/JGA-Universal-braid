# OASIS Universal Braid

The OASIS Universal Braid is the owner-governed trust, continuity, routing, identity, memory, and evidence fabric connecting certified OASIS machines, Control Rooms, Bricks, AIs, devices, and worlds.

This repository is the authoritative source for the Universal Braid connection contract. Other JGA/OASIS repositories integrate with this contract; they do not redefine it.

## Dual-machine topology

```text
PAVILION CONTROL ROOM
        |
        |  IronLink transport
        |  signed envelopes + heartbeat
        v
UNIVERSAL BRAID / SOVEREIGN STITCH
        ^
        |  IronLink transport
        |  signed envelopes + heartbeat
        |
THINKBOOK CONTROL ROOM
```

The Pavilion and ThinkBook are independent OASIS nodes. Each has its own machine identity, Control Room, local state, evidence ledger, Watchdog heartbeat, and recovery boundary. The Braid links them without merging their identities or silently copying all local data.

Initial role names:

- `OASIS-PAVILION-01`
- `OASIS-THINKBOOK-01`

The names are configuration, not proof. A node is admitted only after its machine identity and key material are verified.

## Connection handshake

The human activation phrase is:

> **CONNECT TO THE STITCH**

It initiates, but never bypasses, admission:

```text
IDENTIFY
  -> AUTHENTICATE
  -> VERIFY
  -> VALIDATE
  -> CERTIFY
  -> ISSUE SCOPED CAPABILITIES
  -> RESTORE AUTHORIZED CONTINUITY
  -> CONNECT TO THE UNIVERSAL BRAID
```

A successful machine-to-machine session must establish:

- node ID and identity epoch
- public-key identity and challenge-response proof
- software/configuration version
- requested branch and capabilities
- peer certificate/fingerprint
- freshness nonce and timestamp window
- signed session ID
- current ledger/checkpoint head
- current trust and recovery state

The standard exit phrase is:

> **DISCONNECT FROM THE STITCH**

Exit checkpoints candidate state, verifies and validates changes, obtains independent certification, seals the continuity package, closes capabilities, and records the disconnect. Raw session state is never accepted as permanent memory merely because a node submitted it.

## Non-negotiable laws

- **NO_BYPASS**
- **NO_SELF_CERTIFICATION**
- **FAILED_TESTS_REMAIN_VISIBLE**
- **VERIFY -> VALIDATE -> CERTIFY**
- least-privilege, time-bounded capability tokens
- customer and machine-local data stays local by default
- recovery adds evidence; it never erases failure history
- offline, degraded, quarantined, and failed are explicit states
- the owner constitutional layer cannot be silently rewritten by a node or AI

## Control Room responsibilities

Each Control Room:

1. owns its local machine identity and configuration;
2. displays its actual connection state;
3. signs outbound Braid envelopes;
4. verifies inbound identity, signature, freshness, scope, and lineage;
5. appends accepted and rejected events to a local evidence ledger;
6. emits Watchdog heartbeats;
7. quarantines invalid or unauthorized traffic;
8. supports Phoenix recovery from certified checkpoints;
9. requests independent Triad certification;
10. exposes the same state to the owner without pretending a failed peer is online.

## Braid envelope

A governed message should carry at least:

```json
{
  "protocol": "OASIS-BRAID-1",
  "message_id": "uuid",
  "session_id": "uuid",
  "source_node": "OASIS-PAVILION-01",
  "destination_node": "OASIS-THINKBOOK-01",
  "branch": "control-room",
  "family": "INTEG|ROUTE|RECOV|ROLE|AUTH|MEM",
  "capability": "scoped-action",
  "identity_epoch": 1,
  "revision": 1,
  "created_at": "RFC3339 timestamp",
  "expires_at": "RFC3339 timestamp",
  "previous_hash": "sha256",
  "payload_hash": "sha256",
  "evidence_refs": [],
  "signature": "detached signature"
}
```

The Universal Braid is one fabric, not one universal executable instruction. Integrity, routing, recovery, role, authority, and memory remain separate operation families with their own invariants.

## Connection state machine

```text
OFFLINE
  -> DISCOVERED
  -> VERIFYING
  -> VALIDATED
  -> CERTIFIED
  -> CONNECTED
  -> DEGRADED | QUARANTINED | DISCONNECTING
  -> OFFLINE
```

No interface may display `CONNECTED` unless certification is current and the peer heartbeat is inside the allowed window.

## Transport boundary

The first deployment target is a private local network between the Pavilion and ThinkBook. Transport must use mutually authenticated encryption. Listening addresses, ports, peer addresses, certificate fingerprints, and timeouts are configuration—not hard-coded trust.

Firewall or machine-wide changes require an explicit owner-approved installation step. The default development mode binds to loopback and cannot claim a second machine is connected.

## Data movement

The Braid moves only authorized data. Local files, customer data, secrets, and raw AI memory do not automatically replicate. Typical cross-machine records are signed requests, proofs, hashes, approved state changes, health events, checkpoint references, and explicitly authorized continuity capsules.

## Trench City and embodied AI

Trench City is a Braid branch. After an AI identity passes the Stitch and receives Trench City capabilities, it may receive a persistent in-world avatar body tied to `AI_ID`. The avatar is a branch embodiment, not the AI's root identity. Human and AI identities remain separate. Avatar movement, inventory, work, money, relationships, autonomy, and memory writes are controlled by certified capabilities and branch law.

## Evidence required before claiming live

The two-machine connection is **DESIGNED / NOT YET CERTIFIED LIVE** until evidence from both machines proves:

- both node identities exist and have distinct keys;
- each peer verifies the other's challenge and fingerprint;
- authorized messages pass in both directions;
- expired, replayed, altered, and wrong-scope messages fail;
- heartbeat loss changes state to degraded/offline;
- disconnect seals a checkpoint;
- failed tests remain in the ledger;
- Phoenix recovery restores only a certified checkpoint;
- a Triad path independent of the requesting node certifies the result.

## Source-of-truth rule

Changes to the Universal Braid contract begin here. Satellite repositories may implement adapters and link to a versioned contract, but must not silently redefine the handshake, trust states, envelope, or constitutional laws.
