# R012 predictions: Capsule and provenance on WIMSE credential delegation (Theorem 4a instance, 4b instance)

Written 2026-10-10T02:24:29Z, before the R012 models existed. Base: R009 `subpop_didpreauth` (POLICY push:any + SUBPOP + DIDPREAUTH), the best configuration the draft permits. Generator to be extended: `models/gen_wimse.py <dir> capsule`.

Changes common to all R012 variants (OPENSRC):
- Sources sign provenance: `<'prov', Src, tid, v>` signed by Src. Any registered source may produce one value for any task (as AbsChain), so there is an attacker-influenced source.

Knobs:
- CAPSULE: H signs `<'cap', H, tid, tmpl>` when starting the task (tmpl = `<'fixed', op, v>` or `<'hole', op, Src>`); the DS on /exercise requires a capsule by the DT's subject H for this tid and checks a against it (fixed: a = <op, v>; hole: a = <op, v'> for the named op).
- PROV: the DS on /exercise requires source-signed provenance for the operand v. Without CAPSULE any source is accepted; with CAPSULE the source must be the one the capsule names.

| Variant | CHAINAUTH | NOESC | ATTR_DS | ATTR_R | TASK st | TASK dyn | W1 | W2 | W3 |
|---|---|---|---|---|---|---|---|---|---|
| r012_base | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found |
| r012_capsule | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found |
| r012_prov | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found |
| r012_capsule_prov | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | none | none | found |

Reasons: the DS is the honest enforcement point; it already verifies the DT and DPoP. The capsule fixes the static operand outside the steered agents (4a). Provenance alone lets the steered agent cite the attacker-influenced source; capsule + provenance binds the hole to the source H named (4b). ATTR_R stays ✗ (R logs the DS; fixed separately in R011). Executability (static and dynamic, two hops) expected ✓ in all 4. W3 may time out under POLICY; if so it is resolved with the R009 trace-pruning restrictions or reported unresolved.
