# Dual-machine activation runbook

This implementation starts **OFFLINE / CERTIFICATION NOT GRANTED**. It does not open a firewall port or claim a second machine exists.

## 1. Install separately

On the Pavilion, from an authenticated checkout:

```powershell
.\install-endpoint.ps1 -NodeId OASIS-PAVILION-01
```

On the ThinkBook:

```powershell
.\install-endpoint.ps1 -NodeId OASIS-THINKBOOK-01
```

Each machine creates a unique Ed25519 private key under `%LOCALAPPDATA%\JGA\UniversalBraid`. Never move or commit `identity.pem`.

## 2. Exchange public identity

Copy only `identity.json` from each machine to the other over an owner-controlled channel. Compare the full SHA-256 fingerprints on both screens before admitting either peer. A node name alone is not proof.

## 3. Evidence gate

The current package supplies identity, challenge-response, signed-envelope, freshness, scope, replay, tamper-evident-ledger, and checkpoint primitives. Network transport, heartbeat service, Phoenix restore, and independent Triad certification remain blocked from a live claim until they are implemented and exercised on both machines.

Required final evidence remains: bidirectional authorized traffic; altered, expired, replayed, and wrong-scope rejection; heartbeat loss; sealed disconnect; certified-only recovery; independent Triad signature. Any failure remains in each local ledger.
