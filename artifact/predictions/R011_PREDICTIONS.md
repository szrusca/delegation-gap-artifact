# R011 predictions: minimal fixes, combined per protocol

Written 2026-10-10T02:24:29Z, before the R011 models existed. Most single fixes were already verified as variants in R006–R009; R011 adds the missing fix (WIMSE resource-side attribution), an operand-scope knob for OBO, and one all-fixes variant per protocol to check that the fixes compose and keep the protocol executable.

## New fix: WIMSE RFWD
The DS forwards the exercising DID to R (e.g., in a signed header over the DS–R channel) and R logs (H, DID) instead of (H, DS).
| Variant | CHAINAUTH | NOESC | ATTR_DS | ATTR_R | TASK st | TASK dyn | W1 | W2 | W3 |
|---|---|---|---|---|---|---|---|---|---|
| fix_rfwd (subpop_didpreauth + RFWD) | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | none | none | none |
| fix_rfwd_nopreauth (POLICY + SUBPOP + RFWD) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | none | found | none |
| wimse_allfix (SUBPOP + DIDPREAUTH + RFWD + POLICY + CAPSULE + PROV, OPENSRC) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | none | none | none |
ATTR_R with RFWD needs DIDPREAUTH for the same reason as ATTR_DS (W-b).

## MCP allfix (AUDM + SCOPECHK + OPSCOPE + XCHG + DPOP)
CONSENT_M ✓, NOESC ✓, ATTR_agent ✓, TASK st ✓, TASK dyn ✗; W1 none, W2 none, W3 none. Exec ✓ ✓.

## OBO: new knob OPSCOPE and allfix
OPSCOPE: H consents to an operand-level scope: `<'push', repo>` for a static task, `<'push', v>` for a dynamic task with v proposed by the client (as MCP opscope).
| Variant | AUTH_consent | PARTICIPATION | NOESC | ATTR_actor | TASK st | TASK dyn | W1 framing | W2 no participation |
|---|---|---|---|---|---|---|---|---|
| opscope (base + OPSCOPE) | ✓ | ✗ | ✓ | ✗ | ✓ | ✗ | found | found |
| obo_allfix (DPOPA + ACTBIND + OPSCOPE) | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | none | none |

## RFC 8693
No new run: the "all four" variant of R006 (MAYACT + DPOP + AUD + RARH) is the all-fixes variant (AUTH, NOESC, ATTR, TASK st ✓; TASK dyn ✗).

## Expected overall picture
Every protocol's own fixes repair AUTH/NOESC/ATTR and TASK-static; TASK-dynamic fails in every protocol until capsule + provenance are added (R012 / wimse_allfix).
