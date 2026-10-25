# R017 Predictions — AIP chained mode with a human-signed capsule (fix for A2)

Written: 2026-10-23T17:34:21Z, before models/AIP.spthy has any CAPSULE or PROV variant.

Model: models/AIP.spthy (R010) extended with compile-time flags, mirroring AbsChain:
- CAPSULE: the human's task step also emits a capsule <'cap', H, tid, template> signed by H; the MCP server accepts a fixed task only with a capsule <'cap', H, tid, <'fixed', a>> for the accepted action a, and a hole task with <'cap', H, tid, <'hole', op, S>> (value unchecked).
- CAPSULE + PROV: the hole rule additionally requires <'prov', S, tid, v> signed by the S the capsule names.
The audit context stays agent-written in every variant. Steered agents, bearer call (no request binding), honest server, push:any root grant, as in R010.

| Variant | AUTH | NOESC | ATTR | TASK static | TASK dynamic | witness_context_laundering | exec static / dynamic |
|---|---|---|---|---|---|---|---|
| aip_base (= R010) | ✓ | ✓ | ✗ | ✗ | ✗ | found | ✓ / ✓ |
| aip_capsule | ✓ | ✓ | ✗ | ✓ | ✗ | none | ✓ / ✓ |
| aip_capsule_prov | ✓ | ✓ | ✗ | ✓ | ✓ | none | ✓ / ✓ |

Reasoning: the capsule pins the accepted action to the human's template, so the agent-written context can no longer accompany a different operand (A2 disappears) although the context field itself is unchanged. ATTR stays false: the call is a bearer message. TASK dynamic needs provenance from the named source, as in R012/R016.
