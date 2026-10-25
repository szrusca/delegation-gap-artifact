# Experiment Results

**Date**: 2026-10-08 · **Toolchain**: Tamarin 1.12.0 (official linux64 binary), Maude 3.5.1 (official build), ProVerif 2.05 (built from source, OCaml 4.14). Tamarin self-test: all tests successful.
**Models**: `models/` · **Raw logs**: `models/results/`

## M0 / M1: AbsChain lattice at n = 2 (R002, R003)

Model: `models/AbsChain.spthy`. H → A1 → A2 → R, both agents steered (honest keys, adversary-chosen child, caveat and action), Dolev-Yao network, coarse root caveat `push:any` (OAuth-scope granularity). Evidence flags: `REQBIND`, `CAPSULE`, `PROV` (8 variants via `#ifdef`). Two task kinds in one model: static (`<'fixed', push, repo>`) and data-dependent (`<'hole', push, source>`, hole bound by a unique `Produced(source, tid, v)` per source and task; a second, attacker-influenced source exists). The resource rejects wildcard operands, so witnesses push to a concrete repository.

| Evidence | AUTH | NOESC | ATTR | TASK static | TASK data-dep | Time |
|---|---|---|---|---|---|---|
| Chain | ✓ | ✓ | ✗ | ✗ | ✗ | 7.1 s |
| + ReqBind | ✓ | ✓ | ✓ | ✗ | ✗ | 9.8 s |
| + Capsule | ✓ | ✓ | ✗ | ✓ | ✗ | 11.4 s |
| + Prov | ✓ | ✓ | ✗ | ✗ | ✗ | 9.3 s |
| + ReqBind + Capsule | ✓ | ✓ | ✓ | ✓ | ✗ | 14.6 s |
| + ReqBind + Prov | ✓ | ✓ | ✓ | ✗ | ✗ | 12.4 s |
| + Capsule + Prov | ✓ | ✓ | ✗ | ✓ | ✓ | 12.8 s |
| + ReqBind + Capsule + Prov | ✓ | ✓ | ✓ | ✓ | ✓ | 16.2 s |

- All 40 cells match the lattice prediction written before the run. Both executability lemmas verify in all 8 variants (16/16), so no verdict is vacuous. No well-formedness warnings (derivation check run without timeout).
- ✗ cells are counterexample traces of 9–14 steps. TASK witness (data-dependent, chain + ReqBind): H grants `push:any`; steered A1 narrows to `push:v` for an attacker-chosen v; A2 signs the request; R accepts; no source produced v. ATTR witness: the network attacker replays the chain-bearing bearer token with its own request; R logs A2.
- Prov alone does not give TASK: without a capsule naming the source, the steered agent uses provenance from the attacker-influenced source.
- Model-design finding: an earlier draft used one message format for root and intermediate delegations; that admits a root/intermediate confusion that breaks AUTH. The model now tags `'root'` vs `'del'`. This is a candidate attack class to check in B3 (P1 nested `act`, P4 WIMSE).
- First run surfaced a degenerate witness (pushing to the operand literally named `any`); fixed by the `ConcreteOperand` restriction before the reported run.

## M1: AbsChain lattice at n = 3 (R004)
Predictions: `R004_PREDICTIONS.md`, written 2026-10-10 before the model existed (the n = 2 table, cell for cell). Model: `models/AbsChain3.spthy`, H → A1 → A2 → A3 → R, all three agents steered; the extra `'del'` hop is bound to the hash of the whole prefix and R checks every hop's caveat. Logs: `models/results/R004/`.

| Evidence | AUTH | NOESC | ATTR | TASK static | TASK data-dep | Time |
|---|---|---|---|---|---|---|
| Chain | ✓ | ✓ | ✗ | ✗ | ✗ | 171 s |
| + ReqBind | ✓ | ✓ | ✓ | ✗ | ✗ | 343 s |
| + Capsule | ✓ | ✓ | ✗ | ✓ | ✗ | 446 s |
| + Prov | ✓ | ✓ | ✗ | ✗ | ✗ | 212 s |
| + ReqBind + Capsule | ✓ | ✓ | ✓ | ✓ | ✗ | 656 s |
| + ReqBind + Prov | ✓ | ✓ | ✓ | ✗ | ✗ | 399 s |
| + Capsule + Prov | ✓ | ✓ | ✗ | ✓ | ✓ | 470 s |
| + ReqBind + Capsule + Prov | ✓ | ✓ | ✓ | ✓ | ✓ | 837 s |

- **40/40 cells match; 16/16 executability lemmas verify.** Executability requires three pairwise distinct agents on the accepted chain, so no ✓ is vacuous. The plan's termination risk did not materialize: no source lemma or oracle was needed; the largest AUTH proof is 242 steps.
- AUTH at n = 3 covers all three hops (root by H, A1 → A2, A2 → A3). The lattice is unchanged by chain length (plan ablation "chain length 2 vs 3").

## M0 go/no-go: universal Separation (R015)

Question (External Critical Review): is "Chain + ReqBind (+ Capsule) ⇏ TASK for data-dependent tasks" provable for *every* chain-view verifier, and is the proof trivial?

Model: two worlds that differ only in the tracker's answer (`repoY` vs `repoX`); the steered A2 pushes to `repoY` in both. Evidence on the wire: chain, request binding, human capsule naming the tracker. If the two worlds are observationally equivalent, every verifier that decides from public messages decides both alike; since it must accept the conformant world, it accepts the non-conformant one.

| Check | Tool | Result | Time |
|---|---|---|---|
| Equivalence, chain view | ProVerif `choice[]` | **Observational equivalence is true** | 0.11 s |
| Reachability, chain view, tracker said repoX | ProVerif | Accept(push, repoY) **reachable** (non-vacuous) | 0.09 s |
| Reachability, + Prov, tracker said repoX | ProVerif | Accept(push, repoY) **unreachable** | 0.08 s |
| Equivalence, + Prov | ProVerif | **cannot be proved; distinguishing trace found** | stopped after result |
| Equivalence, chain view | Tamarin `--diff` | aborted after ~11 min, RSS > 21 GB (state explosion) | — |
| Exists-trace lemmas, + Prov | Tamarin `--diff` | LHS conformant accept ✓; RHS non-conformant accept: no trace; equivalence falsified | 557 s |

**Verdict on depth: trivial in the abstract model.** The differing value flows only into the agent's private state and the `Produced` label; it never reaches a message, so the equivalence is a one-line non-interference argument. This confirms the reviewers' concern: the Separation cell, as stated over an abstract chain, is definitional.

**Where depth can come from (implication for B3)**: the separation is non-trivial only where a protocol's evidence binds *part* of the operand. Candidates: RFC 8707 `resource` / audience binds the resource-server identity but not the repository; RFC 9396 RAR `authorization_details` can carry the exact repository, but in agent flows it is requested by the (steered) agent, not approved by the human. The question per protocol is therefore *which part of the operand, if any, is fixed by a party outside the steered agents*. The Separation should be restated as a per-protocol operand-granularity result, with the abstract cell kept as a lemma.

## B3 / P1: RFC 8693 multi-hop token exchange with nested `act` (R006)

Predictions: `refine-logs/R006_PREDICTIONS.md`, written 2026-10-09T02:17Z before any R006 model existed. Its addendum covers the two witness lemmas and was written before they ran.
Model: `models/gen_rfc8693.py` generates 8 variants into `models/generated/rfc8693/`. Logs are in `models/results/R006/`.
Setting:
- n = 2; agents are steered, with honest keys and adversary-chosen inputs; tokens are observable.
- The AS is honest and always enforces scope attenuation.
- R accepts tokens with any `act` depth and logs the current (top-level) actor, per RFC 8693 §4.1.

| Variant | AUTH | NOESC | ATTR | TASK static | TASK dynamic | Splice witness | Act-stripping witness | Exec (2-hop, static / dynamic) | Safety time |
|---|---|---|---|---|---|---|---|---|---|
| base (bearer, no may_act, R ignores aud) | ✗ | ✓ | ✗ | ✗ | ✗ | found | found | ✓ / ✓ | 34 s |
| + MAYACT | ✓ | ✓ | ✗ | ✗ | ✗ | none exists | found | ✓ / ✓ | 32 s |
| + DPOP | ✗ | ✓ | ✗ | ✗ | ✗ | found | found | ✓ / ✓ | 88 s |
| + AUD (RFC 8707 enforced at R) | ✗ | ✓ | ✗ | ✗ | ✗ | found | none exists | ✓ / ✓ | 95 s |
| + DPOP + AUD | ✗ | ✓ | ✓ | ✗ | ✗ | found | none exists | ✓ / ✓ | 100 s |
| + MAYACT + DPOP + AUD | ✓ | ✓ | ✓ | ✗ | ✗ | none exists | none exists | ✓ / ✓ | 84 s |
| + RARH (human-consented RAR) | ✗ | ✓ | ✗ | ✓ | ✗ | found | found | ✓ / ✓ | 23 s |
| all four | ✓ | ✓ | ✓ | ✓ | ✗ | none exists | none exists | ✓ / ✓ | 46 s |

- **40/40 property cells and 16/16 witness cells match the predictions.** 16/16 executability lemmas verify; each is an honest 2-hop run H→A1→A2→R with a nested-`act` chain, so no ✓ is vacuous.
- Every existence lemma finishes in ≤ 142 s.
- The supporting invariants verify in every variant where they are used:
  - `issued_scope_within_human_consent` (induction) everywhere;
  - `first_actor_was_root_delegate` and `later_actor_was_delegated_by_previous` in the MAYACT variants.
- No well-formedness warnings except "--prove pattern absent", for the hop invariants in the non-MAYACT variants.

### Findings
**F1. Nested `act` is not delegation evidence unless the AS checks the hop.**
- Without a check that the exchanging actor is the subject token's audience (or `may_act`), a steered agent A2 can exchange a token A1 issued for A3. R then accepts a chain H→A1→A2 in which A1 never delegated to A2.
- With MAYACT, AUTH is proved and no splice trace exists.
- This is consistent with RFC 8693's own caveat: prior actors are "informational only" (§4.1), and actor validation is left to AS policy (§2.1). The contribution is the mechanized condition that turns the informational chain into authenticated delegation. It is not a spec violation.

**F2. Act-stripping: DPoP alone does not give attribution.**
- If R does not enforce its own audience, the agent that holds the human's pre-exchange token (A1) can present it directly. R logs the *human* as the acting principal and sees no agent at all. This is the motivating problem of the paper, reproduced inside the standard.
- DPoP does not help, because the stripped token is legitimately bound to A1.
- ATTR is proved only with DPOP + AUD. ReqBind therefore decomposes, in RFC 8693, into two required pieces: presenter binding (DPoP) and audience enforcement (RFC 8707), with the pre-exchange token's audience excluding R.

**F3. Operand granularity (the per-protocol Separation).**
- TASK-static holds iff the exact operand is in the human-consented grant (RARH).
- Other fields do not pin the operand: RFC 8707 `resource`/`aud` pins only the server, and agent-requested RAR/scope narrowing is chosen by the steered agent.
- TASK-dynamic fails in all 8 variants: no RFC 8693 field carries provenance.
- This is the non-trivial per-protocol form of the R015 Separation.

### Model corrections made during R006
None changes a reported verdict's meaning. Each one is logged in the predictions addendum or here.
1. **Inductive scope invariant.** The first full run diverged: the AS can re-exchange tokens without bound, and every variant hit the 6 GB cap with no lemma finished. Fixed by the scope invariant, plus two hop invariants in the MAYACT variants. Those are included only where they verify, so a false lemma is never reused.
2. **`HumanTaskOperandIsConcrete`.** The first rarh run "falsified" TASK-static with the human consenting to the literal wildcard repo `'any'`.
3. **`NoActor` tag on depth-0 acceptance.** The first act-stripping witness was satisfied by the human's own registered identity acting as an agent (depth-1 token), not by an act-less token.
4. **`Source_produces` reads a `!TaskOpen` fact instead of learning the task id from the network.** This is behaviour-equivalent for open tasks. It cut dynamic-executability search from heap exhaustion to 166–199 s in the MAYACT+DPOP+AUD variants.
5. **Lemma order.** Scope invariant, then executability, then hop invariants. Existence search was intractable with the hop invariants before it, and in the DPoP-only variants it was intractable without the scope invariant.

### KEYCOMP: steered agents plus key reveal (R006-kc)
The predictions were written at 2026-10-09T18:07:36Z, before any KEYCOMP model existed (`R006_PREDICTIONS.md`, KEYCOMP addendum). The model adds `Reveal_ltk`, which can leak any party's long-term key, AS included. Each security lemma must hold unless a key it relies on was revealed:
- AUTH: AS, A1, A2;
- NOESC, TASK: AS;
- ATTR: AS and the logged principal P.

Generator: `models/gen_rfc8693.py <dir> kc`. Logs: `models/results/R006_kc/`.

**(a) Compromise of non-chain parties: 40/40 cells equal the steered table. 16/16 honest runs verify with no reveal.**

| Variant | AUTH | NOESC | ATTR | TASK static | TASK dynamic | Splice witness (no AS/A1/A2 reveal) | Stripping witness (no AS/A1 reveal) | Safety time |
|---|---|---|---|---|---|---|---|---|
| kc_base | ✗ | ✓ | ✗ | ✗ | ✗ | found | found | 38 s |
| kc_mayact | ✓ | ✓ | ✗ | ✗ | ✗ | none | found | 88 s |
| kc_dpop | ✗ | ✓ | ✗ | ✗ | ✗ | found | found | 50 s |
| kc_aud | ✗ | ✓ | ✗ | ✗ | ✗ | found | none | 58 s |
| kc_dpop_aud | ✗ | ✓ | ✓ | ✗ | ✗ | found | none | 139 s |
| kc_mayact_dpop_aud | ✓ | ✓ | ✓ | ✗ | ✗ | none | none | 149 s |
| kc_rarh | ✗ | ✓ | ✗ | ✓ | ✗ | found | found | 29 s |
| kc_all | ✓ | ✓ | ✓ | ✓ | ✗ | none | none | 100 s |

All supporting invariants verify. The guarded scope invariant takes 51 steps; the MAYACT hop invariants verify too. Every existence check finishes within 167 s.

**(b) Classic baseline: 24/24 traces found.** Each of the 3 witnesses has a trace in every variant, including kc_all:
- `kc_witness_chain_party_reveal_breaks_AUTH`: a nested chain with an undelegated hop, using Reveal(A1);
- `kc_witness_actor_reveal_breaks_ATTR`: the logged principal never sent the request, using Reveal(P);
- `kc_witness_as_reveal_breaks_TASK_static`: an action the human did not intend is accepted on a static task, using Reveal(AS).

**Reading.** Compromising a party outside the chain changes nothing, because the steered agent is already a signing oracle for every agent. Compromising a key that a property relies on breaks that property in every configuration, including the fully fixed one. This is the B2 dichotomy (all-hold or all-fail) instantiated on RFC 8693: only the steered model separates the eight configurations.

**KEYCOMP model corrections:**
6. **Scope invariant needs an AS-reveal guard.** The first kc pass falsified `issued_scope_within_human_consent`: with the AS key revealed, the adversary forges a subject token and the honest AS exchanges it. Because the lemma is `reuse`, that whole pass was unsound. It is kept only in `results/R006_kc_void_invariant/`, and none of its verdicts are used. The guarded invariant verifies, and all reported results come from the rerun.
7. **The kc executability lemmas forbid every reveal.** Without that, an honest-run check could be satisfied with a forged token. The first rerun of those lemmas did not exclude reveals and is superseded (`results/R006_kc/exists_exec_superseded/`).

### Not modeled yet
- impersonation-semantics exchange (no `actor_token`);
- a dishonest or multi-AS setting;
- n = 3;
- the RFC 8693 `may_act` claim as a separate field: MAYACT models it as an audience equality.

## B2: adversary baseline on AbsChain (R005)
Predictions: `R005_PREDICTIONS.md`, written 2026-10-09T21:25:30Z, before the HONEST rules or the agent-only KEYCOMP restriction existed. Model: `models/AbsChain.spthy`, extended with `-D=HONEST` (A1 delegates its full caveat; A2 requests only the capsule-fixed action, or the value the capsule's source signed) and `-D=KEYCOMP` (agent keys revealable; the human and source of an accepted request are never revealed). The steered rules are unchanged and were rerun as a regression check. Logs: `models/results/R005/{steered,honest,keycomp}`.

**120/120 cells match the predictions. 48/48 executability lemmas verify. Every run takes 7–21 s.**

| Evidence | HONEST (AUTH NOESC ATTR TS TD) | STEERED (= R003) | KEYCOMP agents |
|---|---|---|---|
| Chain | ✓ ✓ ✗ ✗ ✗ | ✓ ✓ ✗ ✗ ✗ | ✗ ✓ ✗ ✗ ✗ |
| +ReqBind | ✓ ✓ ✓ ✓ ✓ | ✓ ✓ ✓ ✗ ✗ | ✗ ✓ ✗ ✗ ✗ |
| +Capsule | ✓ ✓ ✗ ✓ ✗ | ✓ ✓ ✗ ✓ ✗ | ✗ ✓ ✗ ✓ ✗ |
| +Prov | ✓ ✓ ✗ ✗ ✗ | ✓ ✓ ✗ ✗ ✗ | ✗ ✓ ✗ ✗ ✗ |
| +ReqBind+Capsule | ✓ ✓ ✓ ✓ ✓ | ✓ ✓ ✓ ✓ ✗ | ✗ ✓ ✗ ✓ ✗ |
| +ReqBind+Prov | ✓ ✓ ✓ ✓ ✓ | ✓ ✓ ✓ ✗ ✗ | ✗ ✓ ✗ ✗ ✗ |
| +Capsule+Prov | ✓ ✓ ✗ ✓ ✓ | ✓ ✓ ✗ ✓ ✓ | ✗ ✓ ✗ ✓ ✓ |
| +all three | ✓ ✓ ✓ ✓ ✓ | ✓ ✓ ✓ ✓ ✓ | ✗ ✓ ✗ ✓ ✓ |

**Reading (corrects the proposal's B2 sentence).** "Honest ⇒ all hold, key compromise ⇒ all fail" is false. Bearer variants fail under honest agents, and properties anchored in human or source signatures survive agent key compromise. The three models differ instead in which evidence they make necessary:
- HONEST: ReqBind alone gives every property.
- KEYCOMP: ReqBind is useless; AUTH and ATTR are unattainable; TASK depends only on human- and source-signed evidence.
- STEERED: the only model in which Capsule and Prov are necessary *in addition to* ReqBind, while AUTH and ATTR stay attainable.

The steered model is therefore the one that separates the three evidence types. `FINAL_PROPOSAL.md` (Problem anchor; Baselines) and `EXPERIMENT_PLAN.md` (B2 row, must-prove list, checklist) were reworded to this on 2026-10-09; the prior versions are kept as `*_20261008_*.md`.

**Model correction.** The first KEYCOMP restriction kept unrevealed only parties that actually issued a root or produced a value. The adversary revealed a human's key and forged a root that human never issued, so every property failed spuriously. That pass is void and kept in `results/R005/keycomp_void_restriction/`. The restriction now names the human of the accepted chain and the source of accepted provenance (new `ProvFrom` action). The steered and honest columns were rerun on the final file, and their verdicts are unchanged.

## B3 / P2: MCP authorization, revision 2026-07-28 (R007)
Predictions: `R007_PREDICTIONS.md`, written 2026-10-09T21:28:55Z, before any model, with the spec text quoted verbatim. Generator: `models/gen_mcp.py`; runner `run_mcp.sh`; logs `models/results/R007/`.

Model: H consents to MCP client (agent) C for server M; the MCP AS issues T1 (sub H, client C, aud, scope, task id). Separately, H authorized M once at the upstream AS, and M stores a per-user upstream token. Steered C sends a tool call; M validates T1 and calls R over TLS with H's upstream token; R logs (H, logged client). T1 is adversary-known (a steered agent can leak it); server-stored upstream tokens are not.

**All 35 property cells, all 21 witness cells and all 14 executability lemmas match the predictions. Each variant takes ≤ 31 s.**

| Variant | Knobs | CONSENT_M | NOESC | ATTR_agent | TASK static | TASK dyn | W1 cross-server | W2 scope escalation | W3 identity collapse |
|---|---|---|---|---|---|---|---|---|---|
| spec | AUDM (MUST) + SCOPECHK (SHOULD) | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found |
| spec_must | AUDM | ✓ | ✗ | ✗ | ✗ | ✗ | none | found | found |
| noaud | SCOPECHK | ✗ | ✗ | ✗ | ✗ | ✗ | found | none | found |
| noaud_noscope | — | ✗ | ✗ | ✗ | ✗ | ✗ | found | found | found |
| opscope | spec + operand-level step-up scopes | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found |
| xchg | spec + upstream token carries act = C (not in spec) | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | none |
| xchg_dpop | xchg + T1 bound to C's key (not in spec) | ✓ | ✓ | ✓ | ✗ | ✗ | none | none | none |

### Findings
- **(M1) Identity collapse is a property of the spec.** In every spec-conformant configuration, the resource cannot tell which agent caused an upstream call: two different agents' calls yield identical log entries (W3). The spec forbids passthrough and says only that the upstream token "is a separate token, issued by the upstream authorization server". No field carries the agent. This is the paper's motivating problem, mechanized against the normative text.
- **(M2) The scope check is the only barrier against escalation, and it is a SHOULD.** M holds one broad upstream token per user. With only the MUSTs (spec_must), a client H consented for a narrow scope at M can drive any upstream operation (W2, 11-step trace). The audience MUST alone stops cross-server replay (W1) but not this.
- **(M3) Attribution needs both the agent in the upstream token and sender-constraining.** Carrying the agent upstream (xchg) removes the collapse but still fails ATTR_agent: T1 is a bearer token a steered agent can leak, and the adversary then calls M directly (6-step trace). Only xchg_dpop gives ATTR_agent. This repeats R006 F2 at the MCP layer: binding plus identity are both required.
- **(M4) Operand granularity.** Operand-level step-up scopes, which the spec permits ("determined dynamically based on the specific request arguments"), give TASK-static. TASK-dynamic fails everywhere, as in R006 F3.

### R007 extensions: no-leak bound and KEYCOMP
Predictions: R007_PREDICTIONS.md addendum, written 2026-10-09T21:38:21Z, after the findings review (thread `57032c976402`, PROCEED, 7/10) asked for a bound on the token-leak assumption behind M3. Generator modes: `gen_mcp.py <dir> noleak` and `gen_mcp.py <dir> kc`. Logs: `results/R007_noleak/`, `results/R007_kc/`.

**NOLEAK: 10/10 property cells, 6/6 witnesses and 4/4 executability lemmas match.** The token reaches the agent, and the call reaches M, over private channels. The steered agent still chooses the action, the server and the token.

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK st | TASK dyn | W1 | W2 | W3 |
|---|---|---|---|---|---|---|---|---|
| spec_noleak | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found |
| xchg_noleak | ✓ | ✓ | ✓ | ✗ | ✗ | none | none | none |

Bound:
- M1 (identity collapse) holds without any token leakage.
- The bearer half of M3 needs leakage: with an unleakable token, carrying the agent upstream alone gives ATTR_agent. DPoP is required exactly when a steered agent can exfiltrate its token. The paper must state this assumption, with prompt-injection exfiltration as its justification.

**KEYCOMP: (a) 35/35 property cells and 21/21 witnesses equal the steered table, and 14/14 executability lemmas (no reveal) verify. (b) 14/14 classic-baseline traces are found:** an AS reveal breaks CONSENT_M, and a logged-client reveal breaks ATTR, in every variant, including xchg_dpop (via a forged DPoP proof). Each variant takes ≤ 78 s. The model has no reuse lemmas, so the guarded-invariant issue of R006-kc does not arise.

### Not modeled yet
Token passthrough itself; mix-up and issuer validation (RFC 9207); CIMD/DCR; refresh tokens; multiple MCP hops; the Enterprise-Managed Authorization extension; a malicious MCP server that is itself steered.

## B3 / P3: OAuth On-Behalf-Of for AI Agents, draft-02 (R008)
Predictions: `R008_PREDICTIONS.md`, written 2026-10-09T21:41:45Z, before any model, with the draft's normative text quoted. The draft is an individual, Informational draft dated 2025-08-26; it expired on 2026-02-27 and was not adopted. Generator: `models/gen_obo.py`; runner `run_mcp.sh <src> <out> <jobs> OBO`; logs `models/results/R008/`.

Model: chain H → client K (orchestrating agent) → actor A (agent named by `requested_actor`) → R.
- K requests authorization with requested_actor A. H consents to (K, A, scope). The AS binds the single-use code to (H, K, A, scope).
- The token request carries the code and A's actor_token. A hands its (reusable) actor_token to a client when it joins a flow.
- The AS checks that actor_token sub = A, consumes the code, and issues (sub H, azp K, act.sub A, scope, cnf). R logs (H, K, A).
- K and A are steered, so codes, verifiers and tokens they hold are adversary-known. There is no client authentication at the token endpoint, as in the draft.

**36/36 property cells, 12/12 witnesses and 12/12 executability lemmas match the predictions. Each variant takes ≤ 5 s.**

| Variant | AUTH_consent | PARTICIPATION | NOESC | ATTR_actor | TASK st | TASK dyn | W1 framing | W2 no participation |
|---|---|---|---|---|---|---|---|---|
| base (draft as written) | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | found | found |
| actbind | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | found | none |
| dpop_client (RFC 9449 as deployed) | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | found | found |
| dpop_client_actbind | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | found | none |
| dpop_actor | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | none | found |
| dpop_actor_actbind | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | none | none |

### Findings
- **(O1) Framing the agent with a correctly sender-constrained token.** RFC 9449 binds the token to whoever proves possession at the token endpoint. In this draft that is the code redeemer (the client K, or anyone holding the code, since there is no client authentication), not the actor named in `act.sub`.
  - W1 trace (dpop_client, 11 steps): H consents; A joins; K redeems with its own DPoP key; K sends the request; R accepts and logs actor A, who made no request.
  - Sender-constraining fixes attribution only if cnf is the actor's key (dpop_actor). The draft names the actor but never makes it hold anything.
- **(O2) The actor_token does not show participation in this delegation.** It is a reusable credential with unspecified validation, so a delegation naming A can be completed with an actor_token A handed over for a different flow (W2, 7 steps). The audit trail the draft promises ("essential information for auditing actions") is therefore not evidence that A took part. A flow-bound actor signature (actbind) restores it.
- **(O3) Consent binding works.** The code bound to (H, K, A) plus single use gives AUTH_consent and NOESC in every variant: the draft's main mechanism is sound for what it binds.
- Operand granularity: scope only, so TASK fails everywhere, as predicted (not a focus).
- Not modeled: the single-object `act` cannot express a sub-agent hop (noted only); PKCE as a separate mechanism; KEYCOMP; audience; RAR.

### R008 KEYCOMP
Predictions: R008_PREDICTIONS.md KEYCOMP addendum, written 2026-10-09T21:57:44Z. Generator mode `gen_obo.py <dir> kc`; logs `results/R008_kc/`. Guards:
- AUTH_consent, NOESC, TASK: AS;
- PARTICIPATION, ATTR_actor: AS and the actor.

The client's key is in no guard, because in dpop_client the cnf key is whatever the redeemer presents.

**(a) 36/36 property cells equal the steered table; 12/12 witnesses keep their steered results; 12/12 executability lemmas (no reveal) verify. (b) 12/12 classic-baseline traces are found:** an AS reveal breaks AUTH_consent, and an actor reveal breaks ATTR_actor, in all 6 variants (in the dpop_actor variants via a forged DPoP proof). Each variant takes ≤ 6 s.

**Model note.** An earlier run of the same models carried a misnamed witness (`..._logged_saactor`, an artifact of a variable rename); it was rerun after the fix and the verdicts are identical (`results/R008_misnamed_witness/`).

## B3 / P4: Credential Delegation for AI Agents, draft-sweeney-wimse-credential-delegation-00 (R009)
Predictions: `R009_PREDICTIONS.md`, written 2026-10-09T22:01:23Z, before any model, with the draft's normative text quoted. The draft is an individual submission to WIMSE dated 2026-07-28 (expires 2027-01-29): https://www.ietf.org/archive/id/draft-sweeney-wimse-credential-delegation-00.html. Generator: `models/gen_wimse.py`; logs `models/results/R009/` (whole-file), `models/results/R009_perlemma/` (per lemma), `models/results/R009_w3*/` (W3 attempts).

Model: H → root agent D1 → sub-agent D2 → DS → R, depth ≤ 2.
- Agents self-generate DID keys and the DS never rejects an unseen DID (§4.1), so the adversary may present a key it minted.
- The DS issues root DTs within H's policy or a CIBA approval, and child DTs with c2 ⊆ c1 and a receipt (§5.2, §5.3).
- On /exercise the DS checks the DT, the DPoP proof by the DT's DID and that a ∈ c, then calls R with H's vault credential. R logs (H, DS).
- Agents are steered. DTs they hold are adversary-known. DS, R and H are honest.

**30/30 property cells, 15/15 witnesses and 10/10 executability lemmas match the predictions.** W3 under POLICY needed trace-pruning restrictions (see Model notes). Every lemma takes ≤ 82 s.

| Variant | CHAINAUTH | NOESC | ATTR_DS | ATTR_R | TASK st | TASK dyn | W1 splice | W2 unregistered DID | W3 collapse at R |
|---|---|---|---|---|---|---|---|---|---|
| spec_min (POLICY) | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | found | found | found† |
| subpop | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | none | found | found† |
| didpreauth | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ | found | none | found† |
| subpop_didpreauth | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found† |
| exact_consent | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found (30 steps) |

### Findings
- **(W-a) The `prf` receipt records a sub-delegation hop; it does not authenticate it.**
  - spec_min CHAINAUTH trace (9 steps): the root agent's DT leaks, the adversary submits the sub-delegation request itself, and the DS issues a child DT from D1 that D1 never requested.
  - The §9.2 splice defence holds only when the DS also requires a signature by the parent DID's key on the sub-delegation request (SUBPOP). The draft does not state this.
- **(W-b) Self-generated, never-rejected DIDs make the DS audit trail name keys, not agents.**
  - subpop ATTR_DS trace (16 steps): the steered root agent signs a sub-delegation to a key the adversary minted. The adversary then signs the DPoP proof and the DS logs that DID for an operation no agent decided.
  - SUBPOP does not help (the parent's signature is genuine). The MAY-level DID pre-authorization (§4.3) is necessary and, here, sufficient for ATTR_DS, even without SUBPOP.
- **(W-c) Credential wrapping moves attribution to the DS and recreates identity collapse at R** (as MCP M1).
  - ATTR_R is falsified in all 5 variants (13–14 steps): R logs (H, DS) for every operation.
  - The two-DID witness W3 is found in all 5 variants: two registered agents act for H on two tasks and R logs (H, DS) for both.
- **(W-d) The §9.4 blast-radius claim is correct for the capability bound** (NOESC holds in all 5), but the bound is H's broad policy, chosen around the steered agent.
  - TASK-static needs H to approve the exact operand (exact_consent).
  - TASK-dynamic fails even then (14 steps): CIBA approval covers the operand the agent proposes, with no link to the source that produced it (as F3, M4, O-TASK).

### Model notes
- The whole-file `--prove` runs of the four POLICY variants hit the 1800 s cap with no output. Rerunning lemma by lemma (`models/run_perlemma.sh`, 600 s per lemma) resolved every lemma except W3.
- W3 attempts under POLICY, all timed out:
  - heuristics S, C, I, c (1200 s each);
  - a strengthened witness with two registered DIDs, two root DTs and two static tasks (1200 s; found in exact_consent in 56 steps);
  - a single-task parent-and-child form (1200 s; timed out in all 5).
  - Both strengthened forms are kept in `generated/wimse_v2`, `generated/wimse_v3`; any trace of them is a trace of W3.
- † Resolution (addendum to `R009_PREDICTIONS.md` written before the run): `gen_wimse.py <dir> w3prune` adds four restrictions used only for the W3 search: no dynamic tasks, no child DTs, concrete root capabilities, root DTs only for registered keys. Restrictions only remove traces, so the trace found is a trace of the unrestricted model. W3 is found in all four POLICY variants (32 steps, ≈ 8 s each; `results/R009_w3prune/`).
- KEYCOMP was not run for R009.

### R009 KEYCOMP
Predictions: R009_PREDICTIONS.md KEYCOMP addendum, written 2026-10-10T02:24:29Z. Generator mode `gen_wimse.py <dir> kc`; logs `results/R009_kc/`. Guards: CHAINAUTH: DS or D1; NOESC, TASK: DS; ATTR_DS, ATTR_R: DS or the owner of the logged DID. W1/W2 and executability require no reveal at all; W3 is not rerun.

**(a) 30/30 property cells equal the steered table; W1/W2 keep their steered results (10/10); 10/10 executability lemmas verify. (b) 10/10 classic-baseline traces are found:** a DS reveal breaks NOESC and a reveal of the agent owning the logged DID breaks ATTR_DS, in all 5 variants. Every lemma takes ≤ 76 s.

## B3 / P5: AIP, Biscuit chained mode (R010), reduced by the W6 gate
Predictions: `R010_PREDICTIONS.md`, written before the model. Source: S. Prakash, "AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A", arXiv:2603.24775v1, 2026-03-25. Model `models/AIP.spthy`; log `results/R010/AIP.log`.

W6 gate: P1–P4 witness every lattice cell (with R012 supplying Capsule + Prov ⇒ TASK-dynamic), so AIP is reduced to the TASK counterexample plus the cheap cells of the same model, as the proposal specifies.

Model: H signs block 0 (tool-level right `push`). Steered A1 appends a delegation block with its own key, an adversary-chosen delegatee, a narrowed right and a free-text context (non-empty, as AIP requires). Steered A2 calls the MCP server M as a bearer. M verifies all signatures, the scope subset and the tool right, and logs (A2, a, context). The paper specifies no argument constraint and no proof of possession.

| AUTH | NOESC | ATTR | TASK st | TASK dyn | Context laundering | Exec st / dyn |
|---|---|---|---|---|---|---|
| ✓ | ✓ | ✗ | ✗ | ✗ | found (12 steps) | ✓ / ✓ |

**All 5 cells, the witness and both executability lemmas match the predictions (9.8 s).**
- **(A1) AIP is the lattice's Chain row.** The richer chain (Datalog policy, mandatory context, depth and budget) changes nothing in the TASK column: the human signs authority, not the task.
- **(A2) Context laundering.** The mandatory audit `context` is written by the steered delegator. Trace: A1 writes the human's exact intended operand as the context and narrows the right to `push:x`; A2 pushes x ≠ the intended repository; M accepts and its audit log records the intended task. The audit field the paper offers for accountability is evidence of what the agent claimed, not of what the human asked.

## B4: fixes (R011)
Predictions: `R011_PREDICTIONS.md`, written 2026-10-10T02:24:29Z, before the models. Logs `results/R011_wimse/`, `results/R011_mcp/`, `results/R011_obo/`.

New fix models:
| Model | Knobs | Properties | Witnesses | Exec |
|---|---|---|---|---|
| WIMSE fix_rfwd | SUBPOP + DIDPREAUTH + RFWD (DS forwards the DID; R logs it) | CHAINAUTH ✓ NOESC ✓ ATTR_DS ✓ ATTR_R ✓ TASK st ✗ dyn ✗ | W1 none, W2 none, W3 none | ✓ ✓ |
| WIMSE fix_rfwd_nopreauth | SUBPOP + RFWD | CHAINAUTH ✓ NOESC ✓ ATTR_DS ✗ ATTR_R ✗ TASK ✗ ✗ | W1 none, W2 found, W3 none | ✓ ✓ |
| WIMSE wimse_allfix | SUBPOP + DIDPREAUTH + RFWD + CAPSULE + PROV | all six ✓ | W1, W2, W3 none | ✓ ✓ |
| MCP allfix | AUDM + SCOPECHK + OPSCOPE + XCHG + DPOP | CONSENT_M ✓ NOESC ✓ ATTR ✓ TASK st ✓ dyn ✗ | W1, W2, W3 none | ✓ ✓ |
| OBO opscope | OPSCOPE (operand-level consent) | AUTH ✓ PART ✗ NOESC ✓ ATTR ✗ TASK st ✓ dyn ✗ | W1 found, W2 found | ✓ ✓ |
| OBO obo_allfix | DPOPA + ACTBIND + OPSCOPE | AUTH ✓ PART ✓ NOESC ✓ ATTR ✓ TASK st ✓ dyn ✗ | W1, W2 none | ✓ ✓ |

**All 35 property cells (WIMSE 18, MCP 5, OBO 12), 16 witness cells and 12 executability lemmas match the predictions.** Every lemma takes ≤ 80 s.

Attack → minimal fix → verified (all fixes are in models with executability verified):
| Finding | Minimal fix | Verified in |
|---|---|---|
| F1 RFC 8693 splice | may_act at the AS | R006 +MAYACT |
| F2 RFC 8693 act-stripping | RFC 8707 audience enforced at R + DPoP | R006 +DPOP+AUD |
| M1 MCP identity collapse | agent carried in the upstream token | R007 xchg |
| M2 MCP scope escalation | scope check as MUST | R007 spec vs spec_must |
| M3 MCP misattribution | agent upstream + DPoP (or a no-leak channel) | R007 xchg_dpop, xchg_noleak |
| O1 OBO framing | cnf = the actor's key | R008 dpop_actor |
| O2 OBO participation | flow-bound actor signature | R008 actbind |
| W-a WIMSE splice | parent PoP on sub-delegation | R009 subpop |
| W-b WIMSE key-not-agent attribution | DID pre-authorization | R009 didpreauth |
| W-c WIMSE collapse at R | DS forwards the DID, R logs it (with DID pre-auth) | R011 fix_rfwd |
| A2 AIP context laundering | human-signed capsule (context written by H, not the agent) | lattice Capsule row (R003, R004); WIMSE instance R012 |
| TASK-static, all protocols | operand-level consent by H (RAR / step-up scope / CIBA exact / capsule) | R006 RARH, R007 opscope, R011 OBO opscope, R009 exact_consent, R012 capsule |
| TASK-dynamic, all protocols | capsule + source-signed provenance | R012 capsule_prov, R011 wimse_allfix, R016 capsule_prov, mcp_allfix_cp |

- **(B4-1) The fixes compose.** In each protocol, the all-fixes variant keeps every property its fixes give separately and stays executable (RFC 8693 "all four" in R006; MCP allfix; obo_allfix; wimse_allfix).
- **(B4-2) TASK-dynamic is the one cell no protocol's own mechanisms can fill.** Every all-fixes variant built only from mechanisms a protocol already describes (RFC 8693, MCP, OBO) fails TASK-dynamic; it holds only once capsule + provenance are added (wimse_allfix).
- **(B4-3) RFWD needs DID pre-authorization.** Forwarding the DID to R moves attribution to R, but without pre-authorization R logs an adversary-minted key (fix_rfwd_nopreauth: W2 found, ATTR_R ✗), the same reason as W-b.

**Model note.** Adding the OBO OPSCOPE knob and the MCP fix mode regenerates the steered OBO/MCP models with parentheses around each lemma conclusion (introduced with the KEYCOMP guards); the files are otherwise identical to those R007/R008 ran, so those results are unaffected.

## B4: Capsule and provenance on WIMSE (R012, Theorem 4a/4b instance)
Predictions: `R012_PREDICTIONS.md`, written 2026-10-10T02:24:29Z, before the models. Generator mode `gen_wimse.py <dir> capsule`; logs `results/R012/`.

Base: R009 subpop_didpreauth (POLICY push:any + SUBPOP + DIDPREAUTH), plus source-signed provenance from any registered source for any task (an attacker-influenced source exists, as in AbsChain). CAPSULE: H signs the task template when starting the task, and the DS requires the capsule on /exercise and checks the operation against it. PROV: the DS requires source-signed provenance for the operand (with CAPSULE, from the source the capsule names).

| Variant | CHAINAUTH | NOESC | ATTR_DS | ATTR_R | TASK st | TASK dyn | W1 | W2 | W3 | Exec st / dyn |
|---|---|---|---|---|---|---|---|---|---|---|
| r012_base | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ |
| r012_capsule | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found | ✓ / ✓ |
| r012_prov | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ |
| r012_capsule_prov | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | none | none | found | ✓ / ✓ |

**24/24 property cells, 12/12 witness cells and 8/8 executability lemmas match the predictions.** W3 is found directly here (158–376 s); the slowest lemma is dynamic executability with capsule + provenance (796 s).
- **(C1) Theorem 4a on a deployed-protocol model.** A human-signed capsule checked at the DS gives TASK-static on WIMSE even under the broad `push:any` policy and steered agents.
- **(C2) Theorem 4b instance, mechanized.** Capsule + source-signed provenance gives TASK-dynamic; provenance alone does not (the steered agent cites the attacker-influenced source), and the capsule alone does not (the hole is unchecked). Both ablations reopen the cell, so the evidence is minimal on this protocol.
- The DS is the natural enforcement point: it already verifies the DT and DPoP proof, so the capsule and provenance checks add two signature verifications per /exercise and no new party.

## B4: Capsule and provenance on MCP (R016, second-protocol minimality)
Predictions: `R016_PREDICTIONS.md`, written 2026-10-10T22:04:15Z, before the generator change. Motivation: result-to-claim (thread 6cecfb5d03e2) asked for Capsule + Prov minimality on a second protocol. Generator mode `gen_mcp.py <dir> capsule`; the steered MCP files it produces are byte-identical to `generated/mcp_check/`. Logs `results/R016/`.

Base: R007 `spec` (AUDM + SCOPECHK, broad `push:any`, steered client, bearer T1). Added knobs:
- OPENSRC: any registered source signs provenance for any task, so an attacker-influenced source exists.
- CAPSULE: H signs the task template at consent; the MCP server checks the action against it.
- PROV: M requires source-signed provenance; with CAPSULE, from the source the capsule names.

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK st | TASK dyn | W1 | W2 | W3 | Exec st / dyn | Time |
|---|---|---|---|---|---|---|---|---|---|---|
| r016_base | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ | 24 s |
| r016_capsule | ✓ | ✓ | ✗ | ✓ | ✗ | none | none | found | ✓ / ✓ | 105 s |
| r016_prov | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found | ✓ / ✓ | 38 s |
| r016_capsule_prov | ✓ | ✓ | ✗ | ✓ | ✓ | none | none | found | ✓ / ✓ | 109 s |
| mcp_allfix_cp | ✓ | ✓ | ✓ | ✓ | ✓ | none | none | none | ✓ / ✓ | 588 s |

**25/25 property cells, 15/15 witness cells and 10/10 executability lemmas match the predictions.** All wellformedness checks pass.
- **(C3) Capsule + Prov is minimal for TASK-dynamic on a second protocol.** On MCP, as on WIMSE (R012), each ablation reopens the cell. Provenance alone fails because the steered client cites the attacker-influenced source; the capsule alone fails because the hole is unchecked.
- **(C4) MCP reaches all properties.** With all its own fixes plus capsule and provenance (mcp_allfix_cp), MCP satisfies every property and no witness exists, including identity collapse (no trace, 5280 steps). Before this, only wimse_allfix did.

**Run notes.**
1. The first R016 attempt did not run: the machine had been re-provisioned and Tamarin/Maude were missing (exit 127; kept in `results/R016/failed_no_toolchain/`). The same versions were reinstalled (Tamarin 1.12.0 official linux64 binary, Maude 3.5.1 official build; `tamarin-prover test` passes). The AbsChain +ReqBind row was rerun and reproduced R003 exactly.
2. The second attempt had a wellformedness failure (variable `S` vs the token-scope variable `s`). Its verdicts are void and kept in `results/R016/void_wellformedness/`. The variable was renamed to `Src`; the table above is from the clean rerun, and its verdicts are identical to the void run's.

## B5: implementation replay on Keycloak token exchange (R013)
Predictions: `R013_PREDICTIONS.md`, written 2026-10-12T03:39:34Z, before any container or script existed. Target: Keycloak 26.7.5 (`quay.io/keycloak/keycloak:26.7.5`, start-dev), standard token exchange; replay script `models/r013/replay.mjs` (Node, no dependencies), raw output `models/results/R013/run1.json`. User alice, confidential clients agent-a1/agent-a2, resource client repo-r; alice's token obtained by password grant (dev-only stand-in for the code flow). The resource is a script that checks signature (realm JWKS), issuer, expiry and scope, and optionally audience.

| ID | Experiment | Prediction | Observed |
|---|---|---|---|
| K1 | agent-a2 exchanges T0 (aud excludes agent-a2) | rejected | **403 access_denied, "Client is not within the token audience"** |
| K2 | same after an audience mapper adds agent-a2 to A1's token | succeeds, azp=agent-a2 | **200; aud=repo-r, azp=agent-a2** |
| K3 | act claim in the exchanged token | absent | **absent**; only azp=agent-a2 names a client, A1's hop is not in the token |
| K4 | A1 presents T0 to R without audience check | accepted, logs alice; azp=agent-a1 present | **accepted; logged alice, azp=agent-a1, act none** |
| K5 | same with audience check | rejected | **rejected (T0 has no aud for repo-r)** |

**5/5 match.**
- **(K-F1)** Keycloak implements the MAYACT-equivalent check: the exchanging client must be in the subject token's audience. The F1 splice is blocked in this implementation, which confirms the fix rather than the attack.
- **(K-F2)** Act-stripping reproduces at a resource that skips audience validation: alice's pre-exchange token is accepted directly, with no act claim. A real-world nuance the model abstracts away is that the stripped token still carries azp=agent-a1, so a resource that logs azp sees the presenting client, though not as an act chain.
- **(K-chain)** Keycloak's exchanged tokens carry no act claim. A resource sees only the last client (azp), so multi-hop attribution collapses to one hop even in a correct deployment.
- Observation, not predicted: with only the custom scopes as defaults, T0 has no sub claim; the exchanged token does. This is irrelevant to the predictions.

## B4: Capsule and provenance on AIP (R017, fix for A2)
Predictions: `R017_PREDICTIONS.md`, written 2026-10-23T17:34:21Z, before any capsule variant of the AIP model existed. Model `models/AIP.spthy` with `-D=CAPSULE` and `-D=CAPSULE -D=PROV` (no flags = the R010 model). Toolchain reinstalled on 2026-10-23 (Tamarin 1.12.0 linux64 binary, Maude 3.5.1) under `~/tools`; logs `models/results/R017/`.

| Variant | AUTH | NOESC | ATTR | TASK static | TASK dynamic | witness_context_laundering | exec | time |
|---|---|---|---|---|---|---|---|---|
| aip_base (= R010) | ✓ | ✓ | ✗ | ✗ | ✗ | found (12 steps) | ✓ ✓ | 14 s |
| aip_capsule | ✓ | ✓ | ✗ | ✓ | ✗ | none | ✓ ✓ | 24 s |
| aip_capsule_prov | ✓ | ✓ | ✗ | ✓ | ✓ | none | ✓ ✓ | 29 s |

**15/15 property cells, 3/3 witnesses and 6/6 executability lemmas match the predictions.** aip_base reproduces every R010 verdict and step count on the reinstalled toolchain.
- A2 is fixed in an AIP model. The audit context stays agent-written, but the server checks a human-signed capsule against the accepted action, so no laundering trace exists.
- ATTR still fails, because the call is a bearer message and AIP defines no proof of possession.
- **Void first pass:** in the capsule rules, `cap` was bound before `t` in the `let` block. Tamarin warned about unbound variables, and AUTH/NOESC came out falsified. The pass is kept in `results/R017_void_unbound/` and excluded from the index.

## B4: MCP with DPoP but without XCHG (R018, half of the M3 pair)
Predictions: `R018_PREDICTIONS.md`, written 2026-10-23T17:34:21Z. Generator `gen_mcp.py <dir> dpoponly` → `spec_dpop` = {AUDM, SCOPECHK, DPOP}; logs `models/results/R018/`.

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK st | TASK dyn | W1 | W2 | W3 | exec | time |
|---|---|---|---|---|---|---|---|---|---|---|
| spec_dpop | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found (22 steps) | ✓ ✓ | 77 s |

**5/5 property cells, 3/3 witnesses and 2/2 executability lemmas match.** DPoP alone does not restore ATTR, because identity collapse persists. Together with R007 xchg, this means both halves of XCHG + DPOP are needed.

## B5: implementation replay on the MCP TypeScript SDK (R014)
Predictions: `R014_PREDICTIONS.md`, written 2026-10-23T22:44:26Z, after reading the SDK's bearer middleware and before the replay script existed. Target: `@modelcontextprotocol/sdk` 1.32.1 (published 2026-10-05; 1.32.2 was published hours before the run and was not used), express 4.21.2, Node v24.22.0. Script: `models/r014/replay.mjs`; raw output: `models/results/R014/run2.json`. Setup: an in-process token store as the MCP AS (opaque T1 with clientId, scopes, resource); M is an McpServer with a streamable HTTP transport behind `requireBearerAuth`, and its tool `push` calls R with H's stored upstream token.

| ID | Experiment | Prediction | Observed |
|---|---|---|---|
| K1 (M1) | client-a and client-b call push(repoX) | both accepted; identical R entries; no client field | **both accepted; the two R entries are byte-identical; no field names the client** |
| K2 (M2) | T1 scopes {mcp, repo:read}, tool without per-tool check | accepted; R executes the push | **accepted; 1 upstream push** |
| K2-fix | same, tool checks repo:write | rejected, nothing reaches R | **rejected by the tool ("insufficient scope"); 0 upstream calls** |
| K3 (M3) | client-a's T1 presented by another client process | accepted as client-a | **accepted; M saw clientId = client-a; push to repoY executed** |
| K4a | T1 for another resource, expectedResource set | 401 | **rejected: invalid_token "Token was not issued for this resource"** |
| K4b | same, expectedResource unset (default) | accepted | **accepted** |

**6/6 match.**
- M1, M2 and M3 reproduce on the reference SDK.
- The SDK enforces scopes server-wide only and has no sender constraint (no DPoP on the server side).
- The audience check required by the spec (a MUST) is opt-in: the `expectedResource` option is off by default.
- **Void first run** (`results/R014/void_port_race/run1.json`): K2-fix restarted M on the same port without waiting for the old listener to close, and the call failed with "fetch failed", not with the scope check. The rerun uses a separate port per configuration. All other verdicts are unchanged.

## Not yet run
R014 is done (MCP TypeScript SDK).
