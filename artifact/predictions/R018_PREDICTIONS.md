# R018 Predictions — MCP with DPoP but without XCHG (half of the M3 pair)

Written: 2026-10-23T17:34:21Z, before the variant exists.

Model: models/gen_mcp.py, new variant spec_dpop = {AUDM, SCOPECHK, DPOP} (T1 bound to the client's key; upstream token does not carry the client).

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK static | TASK dyn | W1 cross-server | W2 scope escalation | W3 identity collapse | exec |
|---|---|---|---|---|---|---|---|---|---|
| spec_dpop | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ ✓ |

Reasoning: DPoP stops a leaked T1 from being replayed by the adversary, but the upstream call still names no agent, so two agents' calls collide at R (M1) and ATTR_agent fails. Hence DPoP alone does not restore ATTR; with R007's xchg result this shows both halves of XCHG+DPOP are needed.
