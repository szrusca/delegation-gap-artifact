# R004 predictions: AbsChain lattice at n = 3

Written 2026-10-10T02:22:24Z, before the n = 3 model existed. Model to be written: `models/AbsChain3.spthy` (H → A1 → A2 → A3 → R; all three agents steered; same evidence flags, rules and lemma shapes as `AbsChain.spthy`, with one extra intermediate delegation hop `'del'` bound to the hash of the whole prefix; R checks every hop's caveat). Only the steered adversary is run.

## Predicted verdicts (identical to R003 at n = 2)
| Evidence | AUTH | NOESC | ATTR | TASK static | TASK data-dep |
|---|---|---|---|---|---|
| Chain | ✓ | ✓ | ✗ | ✗ | ✗ |
| + ReqBind | ✓ | ✓ | ✓ | ✗ | ✗ |
| + Capsule | ✓ | ✓ | ✗ | ✓ | ✗ |
| + Prov | ✓ | ✓ | ✗ | ✗ | ✗ |
| + ReqBind + Capsule | ✓ | ✓ | ✓ | ✓ | ✗ |
| + ReqBind + Prov | ✓ | ✓ | ✓ | ✗ | ✗ |
| + Capsule + Prov | ✓ | ✓ | ✗ | ✓ | ✓ |
| + ReqBind + Capsule + Prov | ✓ | ✓ | ✓ | ✓ | ✓ |

AUTH at n = 3 means: every one of the three hops in an accepted chain was delegated by its named delegator (root by H, then A1 → A2, A2 → A3). Executability (static and dynamic, three distinct hops) expected to verify in all 8.

Reason: the lattice depends on what evidence reaches R, not on chain length; the extra hop adds a delegator who is steered but signs with an honest key, which the chain checks already cover. Risk: non-termination (plan M1). If a lemma does not terminate within 1800 s, it is reported as bounded / unresolved, not as matching.
