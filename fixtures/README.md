# Fixture guide

All timestamps use `Z` UTC. The fixed audit issuance time is `2026-01-10T00:00:00Z`.

| Fixture | Knowledge cut | Expected result |
|---|---:|---|
| `manual/` | `2026-02-01` | `HM-1` trusted; pins a hand-computed HMAC/SHA-256 value. |
| `rotation_quorum/` | any late cut | `ROT-ONE-ISSUER`: two valid overlapping old keys but one independent issuer, hence uncertain/insufficient. `ROT-WITH-BOB`: trusted with exactly Alice + Bob in the minimum witness. |
| `quarantine/` | `2026-01-14` | Both approvals trusted before quarantine publication. |
| `quarantine/` | `2026-01-20` | Both quarantined/uncertain. |
| `quarantine/` | `2026-02-10` | `Q-CLEAR` trusted after clearance; `Q-CONFIRM` rejected by retroactive approval revocation. |
| `revocation_shared/` | `2026-01-20` | All seven approvals trusted. |
| `revocation_shared/` | `2026-02-01` | Retroactive `rev-root-retroactive` rejects `ROOT` and propagates through `SHARED` to both terminal approvals. |
| `cycle_checkpoint/` | `2026-02-01` | `RING_A/B/C` remain uncertain with stable ring evidence; frozen checkpoint for `LOCK_X` anchors `LOCK_X -> LOCK_Y`, so both are trusted. |

Useful cuts for the shared revocation diff are `K1=2026-01-20T00:00:00Z` and `K2=2026-02-01T00:00:00Z`.

Regenerate deterministic HMAC values after intentionally changing fixture content:

```bash
python tools/build_fixtures.py
```
