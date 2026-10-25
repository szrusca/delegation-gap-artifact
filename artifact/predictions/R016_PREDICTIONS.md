# R016 Predictions — Capsule + Provenance minimality on MCP (second protocol)

Written: 2026-10-10T22:04:15Z, before any R016 model or generator change exists.
Motivation: result-to-claim (thread 6cecfb5d03e2) C5 asked for Capsule+Prov minimality on a second protocol.

Base: R007 `spec` (AUDM + SCOPECHK, broad scope `push:any`, steered client, bearer T1 adversary-known).
Added knobs (generator `gen_mcp.py <dir> capsule`):
- OPENSRC: any registered source signs `<'prov', Src, tid, v>` for any task id it receives (one value per source and task); an attacker-influenced source therefore exists, as in AbsChain and R012.
- CAPSULE: at consent H signs `<'cap', H, tid, tmpl>` (`<'fixed', push, repo>` or `<'hole', push, Src>`); the MCP server M requires a capsule for the token's (H, tid) and checks the action against it.
- PROV: M requires source-signed provenance for the operand; with CAPSULE, from the source the capsule names.
Enforcement point: M (it already validates T1).

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK st | TASK dyn | W1 | W2 | W3 | Exec st / dyn |
|---|---|---|---|---|---|---|---|---|---|
| r016_base (spec + OPENSRC) | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ |
| r016_capsule | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found | ✓ / ✓ |
| r016_prov | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ |
| r016_capsule_prov | ✓ | ✓ | ✗ | ✓ | ✓ | none | none | found | ✓ / ✓ |
| mcp_allfix_cp (allfix + OPENSRC + CAPSULE + PROV) | ✓ | ✓ | ✓ | ✓ | ✓ | none | none | none | ✓ / ✓ |

Reasons:
- capsule alone: the hole is not checked, so the steered client pushes any v (TASK dyn ✗).
- prov alone: the steered client cites the attacker-influenced source (TASK dyn ✗); static tasks are unconstrained (TASK st ✗).
- capsule + prov: the capsule names the source, the source signs the value (both ✓).
- ATTR and W3 change only with XCHG + DPOP (allfix_cp), as in R007/R011.
Totals: 25 property cells, 15 witness cells, 10 executability lemmas.
