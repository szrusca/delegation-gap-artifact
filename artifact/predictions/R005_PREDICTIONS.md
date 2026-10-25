# R005 predictions: adversary baseline on AbsChain (n = 2)

Written 2026-10-09T21:25:30Z, before the HONEST rules or the agent-only KEYCOMP restriction existed in `models/AbsChain.spthy`.

## Question (B2)
The proposal (FINAL_PROPOSAL, "Problem anchor") says: "Under key compromise everything trivially fails; under honesty everything trivially holds." The steered agent is what yields the informative middle. R005 tests this over all 8 evidence variants of R003 rather than only the full-evidence one. That is just as cheap and shows the whole pattern.

## Adversary models
In all three, the network is Dolev-Yao and humans and data sources are honest. They differ only in what the agents do.

| Model | Agents |
|---|---|
| STEERED (R003) | honest keys; child, caveat and action chosen by the adversary |
| HONEST | A1 delegates its full caveat to a registered child; A2 requests only the action the human-signed capsule fixes (static), or the value the capsule's source signed for this task (dynamic). Agents read capsule and provenance even when R does not check them. |
| KEYCOMP | steered agents, plus `Reveal` of any agent key. A restriction keeps humans (parties that issue a root) and sources (parties that produce) unrevealed. Lemmas are unguarded. |

## Predicted tables
Rows are the evidence variants in R003 order: Chain, +R(eqBind), +C(apsule), +P(rov), +RC, +RP, +CP, +RCP.

HONEST:
| Evidence | AUTH | NOESC | ATTR | TASK static | TASK dyn |
|---|---|---|---|---|---|
| Chain | ✓ | ✓ | ✗ | ✗ | ✗ |
| +R | ✓ | ✓ | ✓ | ✓ | ✓ |
| +C | ✓ | ✓ | ✗ | ✓ | ✗ |
| +P | ✓ | ✓ | ✗ | ✗ | ✗ |
| +RC | ✓ | ✓ | ✓ | ✓ | ✓ |
| +RP | ✓ | ✓ | ✓ | ✓ | ✓ |
| +CP | ✓ | ✓ | ✗ | ✓ | ✓ |
| +RCP | ✓ | ✓ | ✓ | ✓ | ✓ |

Why: without ReqBind, R accepts a bearer chain, so the network attacker chooses the action. Honesty does not help there; only the evidence R checks does. With ReqBind, R accepts only actions the honest A2 signed, and A2 signs only task-conformant actions. So ReqBind alone makes every property hold.

KEYCOMP (agents only):
| Evidence | AUTH | NOESC | ATTR | TASK static | TASK dyn |
|---|---|---|---|---|---|
| all 8 rows | ✗ | ✓ | ✗ | ✓ iff C | ✓ iff C and P |

Why: AUTH and ATTR rest on agent signatures, which the attacker forges after a reveal. NOESC rests on the human-signed root caveat, TASK-static on the human-signed capsule, and TASK-dynamic on the capsule plus the source-signed provenance. All of those keys stay honest.

STEERED: the R003 table, unchanged (the default rules are untouched; it is rerun as a regression check).

## What this predicts for the claim
- The quoted dichotomy is **false as stated**. Honest does not give all-hold (bearer variants fail ATTR and TASK). Key compromise does not give all-fail (properties anchored in human or source signatures survive).
- The defensible claim is the contrast between the three models on the evidence that matters:
  - HONEST: ReqBind alone suffices for every property. Capsule and Prov look redundant.
  - KEYCOMP: ReqBind is useless; only human- and source-signed evidence counts, and AUTH and ATTR are unattainable.
  - STEERED: the only model in which Capsule and Prov are necessary *in addition to* ReqBind (the R003 rows +R and +RC fail TASK-dyn), while AUTH and ATTR remain attainable.
- So the steered model is the one that separates ReqBind from Capsule from Prov. If the runs confirm this, the proposal sentence must be rewritten to this form.

Executability: both lemmas (which already forbid reveals) are predicted to verify in all 16 new runs.
