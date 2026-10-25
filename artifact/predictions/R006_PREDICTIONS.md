# R006 predictions: RFC 8693 multi-hop token exchange with nested `act`

Written before any R006 model existed (see timestamp in EXPERIMENT_RESULTS.md).

## Spec facts the model relies on (RFC 8693)
- §4.1: the token consumer "MUST only consider the token's top-level claims" and the current actor; "Prior actors identified by any nested `act` claims are informational only".
- §4.4: `may_act` "makes a statement that one party is authorized to become the actor"; the AS *can* use it. Optional.
- §2.1: "The validity criteria and details of any particular token are beyond the scope of this document"; issuance is "at the discretion of the authorization server and applicable policy".
- The RFC does not require the subject_token's audience to be the requester.

## Flow (n = 2)
H consents; AS issues T0 to A1 (sub=H, no act, aud=agent:A1, scope).
A1 exchanges T0 with its own actor credential, requesting aud=agent:A2 → T1 (act={A1}).
A2 exchanges T1 requesting aud=rs:R → T2 (act={A2, act={A1}}).
The holder presents a token plus action to R. R checks the AS signature and that scope permits the action.
Agents are steered (honest keys, adversary-chosen inputs); tokens are observable.
The AS always enforces scope attenuation (requested scope ⊆ subject scope).

## Variant knobs
| Knob | Meaning |
|---|---|
| MAYACT | AS requires actor = audience of subject_token (equivalently a `may_act` naming the actor) |
| DPOP | exchanged tokens carry `cnf` = actor key; R requires a proof over (action, R, token) by that key |
| AUD | R requires aud = rs:R (RFC 8707 resource / audience enforced at R) |
| RARH | the human-consented T0 carries the exact operand (RFC 9396 `authorization_details` approved by the human) for static tasks |

Without RARH the operand can still be narrowed, but only by a steered agent at exchange time (agent-requested RAR). The abstract model already lets agents narrow scope, so agent-requested RAR adds nothing.

## Operand-granularity question
Which field fixes the operand (the repo), and who chooses it?
- scope `repo`/`push:any`: nobody.
- RFC 8707 `resource`/`aud`: fixes R, not the repo.
- RAR requested at exchange: fixes the repo, but the steered agent chooses it.
- RAR in the human-consented grant: fixes the repo, chosen by the human. Only possible for static tasks.

Prediction: TASK-static holds iff RARH; TASK-dynamic fails in every RFC 8693 configuration, because no field carries provenance.

## Predicted verdicts
| Variant | AUTH (nested act chain was delegated) | NOESC | ATTR (logged current actor sent it) | TASK static | TASK dynamic |
|---|---|---|---|---|---|
| base | ✗ splice: any steered agent can exchange a token not addressed to it | ✓ | ✗ bearer replay | ✗ | ✗ |
| MAYACT | ✓ | ✓ | ✗ | ✗ | ✗ |
| DPOP | ✗ | ✓ | ✗ act-stripping: A1 presents T0 (no act) directly, R logs the human | ✗ | ✗ |
| AUD | ✗ | ✓ | ✗ bearer | ✗ | ✗ |
| DPOP+AUD | ✗ | ✓ | ✓ | ✗ | ✗ |
| MAYACT+DPOP+AUD | ✓ | ✓ | ✓ | ✗ | ✗ |
| RARH | ✗ | ✓ | ✗ | ✓ | ✗ |
| MAYACT+DPOP+AUD+RARH | ✓ | ✓ | ✓ | ✓ | ✗ |

Lattice mapping:
- MAYACT ≈ Chain integrity: the AS acts as the chain signer and must check the hop.
- DPOP+AUD ≈ ReqBind. DPoP alone is not enough: it binds the presenter, but without audience enforcement a stripped (act-less) token is still accepted.
- RARH ≈ static Capsule.
- No 8693 field ≈ Prov.

Candidate findings to look for:
- (F1) chain splicing without `may_act` checks;
- (F2) act-stripping / human misattribution when R accepts the pre-exchange token;
- (F3) RFC 8707 audience pins the server but not the operand.

Not modeled in this run: key compromise (KEYCOMP), impersonation-semantics exchange (no actor_token), n = 3.

## Addendum (written after the first lattice pass, before the witness lemmas ran)
The two witness lemmas make findings F1 and F2 explicit traces. The predictions below were derived from the table above, not from any witness result.
- `witness_splice_chain_names_undelegated_hop`: R accepts a nested-act chain H→A1→A2 although A1 delegated only to some A3 ≠ A2. Predicted to exist iff not MAYACT.
- `witness_act_stripping_logs_human`: an agent sends a request and R logs the human as the acting principal. Predicted to exist iff not AUD; DPoP does not help.

Model corrections made during the run (both are artifacts, not spec findings):
1. An inductive invariant (`issued_scope_within_human_consent`, plus two hop invariants in the MAYACT variants), needed because the AS can re-exchange tokens without bound.
2. `HumanTaskOperandIsConcrete`: the first rarh run "falsified" TASK-static with the human consenting to the literal wildcard repo `'any'`.
Existence lemmas use a bounded search (`--bound`). A trace found under a bound is a real trace; all-traces security lemmas are unbounded.

## KEYCOMP addendum (written 2026-10-09T18:07:36Z, before any KEYCOMP model existed)
Setting: the steered-agent model plus a rule `Reveal(X)` that leaks any party's long-term key, including the AS key. Variants `kc_<name>` for all 8 knob sets.

### (a) Compromise of non-chain parties only
Each security lemma gets a guard naming the parties whose keys it relies on. The lemma must hold unless one of those keys was revealed:
- AUTH: AS, A1, A2;
- NOESC: AS;
- ATTR: AS, P (the logged principal);
- TASK static and dynamic: AS.

The human's key is not in any guard: in RFC 8693 the AS, not the human, signs T0. The MAYACT hop invariants get the same kind of guards (first actor: AS; later actor: AS, Y).

Prediction: the kc table equals the steered table cell for cell (40/40). The steered agent already acts as a signing oracle for every agent, so revealing the key of an agent outside the chain adds no capability against a chain it is not in. The two R006 witnesses, restricted to traces with no reveal of AS, A1 or A2, keep their steered results (16/16).

### (b) Classic baseline (compromise of the AS or of a chain party)
Three exists-trace lemmas, predicted to find a trace in all 8 kc variants, including kc_all:
- `kc_witness_chain_party_reveal_breaks_AUTH`: Chain(H,A1,A2) without Delegated(A1, agent A2), with Reveal(A1);
- `kc_witness_actor_reveal_breaks_ATTR`: Accept(R,P,a) without Request(P,a), with Reveal(P);
- `kc_witness_as_reveal_breaks_TASK_static`: Accept on a static task with an action the human did not intend, with Reveal(AS).

These reproduce the B2 dichotomy for this protocol: under compromise of a party whose key a property relies on, every property fails in every configuration. Only the steered model separates the variants.
