# R013 Predictions — implementation replay of F1 and F2 on Keycloak token exchange

Written: 2026-10-12T03:39:34Z, before any Keycloak container, realm or replay script exists.

Target: Keycloak 26.7.5 (quay.io/keycloak/keycloak:26.7.5), standard token exchange (RFC 8693, internal-to-internal), dev mode, one realm.
Setup to build:
- user `alice` (H); confidential clients `agent-a1` (A1), `agent-a2` (A2), `agent-a3` (A3); a resource client `repo-r` (R).
- A1 obtains alice's token T0 by password grant (dev-only stand-in for the authorization-code flow) for client agent-a1.
- R is a small script that validates signature, expiry and scope against the realm JWKS. In variant AUDCHECK it additionally requires aud to contain repo-r. It logs (sub, azp, act if present).

| ID | Experiment | Model analogue | Prediction |
|---|---|---|---|
| K1 | A2 exchanges T0 (aud does not include agent-a2) for a token for repo-r | F1 splice precondition (exchange by an actor that is not the subject token's audience) | **rejected** by Keycloak: standard token exchange requires the requesting client to be in the subject token's audience (implementation enforces the MAYACT-like check) |
| K2 | Same, after A1's token is configured to carry agent-a2 in aud (audience mapper) | legitimate delegation A1→A2 | **succeeds**; issued token has azp=agent-a2 |
| K3 | Inspect K2's exchanged token for an `act` claim | nested act chain | **no act claim** (Keycloak does not implement delegation semantics); the chain A1→A2 is not visible to R, only azp=agent-a2 |
| K4 | A1 presents T0 directly to R without AUDCHECK | F2 act-stripping | **accepted**; R logs sub=alice. Divergence from the model expected: T0 carries azp=agent-a1, so an R that logs azp still sees A1 |
| K5 | Same with AUDCHECK | F2 fix (AUD) | **rejected** (aud of T0 does not contain repo-r) |

Interpretation fixed in advance:
- K1 rejected ⇒ F1 is blocked in Keycloak by its audience rule (consistent with the paper: MAYACT is the fix, and this implementation has it).
- K3 no act ⇒ multi-hop attribution in Keycloak-issued tokens is limited to the last client; the paper's identity-collapse class (M1/W-c) applies to the act chain.
- K4 accepted ⇒ F2 reproduces at a resource that skips audience validation; K5 shows the fix.
Any divergence will be reported as found, not adjusted.
