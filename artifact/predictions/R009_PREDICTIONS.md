# R009 predictions: Credential Delegation for AI Agents (draft-sweeney-wimse-credential-delegation-00)

Written 2026-10-09T22:01:23Z, before any R009 model existed. Source: https://www.ietf.org/archive/id/draft-sweeney-wimse-credential-delegation-00.html (28 July 2026, individual submission to WIMSE, Standards Track intended, expires 29 January 2027). This is the "WIMSE credential delegation -00" named in the proposal.

## Spec facts the model relies on (verbatim or near-verbatim)
- §4.1: "An Agent MUST generate an Ed25519 or P-256 key pair at instantiation"; "The DS MUST NOT reject a DID it has not seen before."
- §4.3: "The DS MAY require Subject pre-authorization of specific agent DIDs or agent operators before issuing Delegation Tokens."
- §2: "An Agent MUST NOT possess or have access to the underlying credentials stored in the Credential Vault." §6.2: the DS calls the resource; the agent calls /exercise and gets only the API response. §6.3: native RS support is future work. The resource therefore sees the DS and the vault credential, never the agent.
- §6.1 (no BCP 14 keyword): the DS checks the DT signature and expiry, the DPoP binding, and that the operation is within `authorization_details`.
- §5.2: "The DS MUST validate that capabilities in a sub-delegation request are a strict subset of the parent DT's capabilities." §5.3: each hop "MUST produce a signed delegation receipt" (parent and child jti, both DIDs), carried as `prf`.
- §9.2: `prf` is presented as fixing RFC 8693 splicing. Nothing normative says who must authenticate a sub-delegation request: no proof of possession of the parent key is required.
- §8.1: when "an Agent requests a delegation that exceeds pre-authorized policies", the DS runs a CIBA request to the Subject. What the user is shown (exact operation and resource?) is unspecified.
- §9.4: "The blast radius of a compromised agent is bounded by its current DT's `authorization_details`."
- No token-exchange flow is specified normatively ("does not define new token formats, new OAuth grant types").

## Flow (n = 2: H → root agent D1 → sub-agent D2 → DS → R)
- H holds a vault credential at the DS for R. H may set a pre-authorized policy (here `push:any`), may pre-authorize agent DIDs, and starts tasks (static or dynamic).
- An agent requests a root DT for H's task with capability c, signed by its DID key. The DS issues it if c is within H's policy (or CIBA-approved).
- An agent holding a root DT requests a child DT for DID2 with c2 ⊆ c. The DS issues it with a receipt. Depth is limited to 2 in this run.
- The holder exercises operation a with a DPoP proof by its DID key. The DS checks the DT, the DPoP proof and that a ∈ c, then calls R with H's vault credential. R logs (H, DS).

Adversary:
- Agents are steered; DTs they hold are adversary-known (but DPoP-bound).
- The adversary can mint its own key pair and use its public key as a DID. This is the literal reading of §4.1: self-generated, never rejected.
- The DS, R and H are honest. The DS–R channel and the vault are private.

## Variant knobs
| Knob | Meaning | Draft status |
|---|---|---|
| POLICY | H pre-authorizes `push:any`; requests within it need no consent | described (§8.1) |
| SUBPOP | the DS requires a signature by the parent DT's DID key on a sub-delegation request | not specified |
| DIDPREAUTH | the DS issues DTs (root and child) only to DIDs H pre-authorized; pre-authorized DIDs are registered agents' keys | MAY (§4.3) |
| EXACT | no broad policy: the root DT needs CIBA approval. For a static task H approves exactly the intended operand; for a dynamic task H approves the operand the agent proposes. | CIBA described; display unspecified |

Variants:
- spec_min = POLICY
- subpop = POLICY+SUBPOP
- didpreauth = POLICY+DIDPREAUTH
- subpop_didpreauth = POLICY+SUBPOP+DIDPREAUTH
- exact_consent = SUBPOP+DIDPREAUTH+EXACT

## Properties
- CHAINAUTH (the §9.2 claim): if the DS issues a child DT from parent DID1 to DID2 and DID1 is a registered agent's key, then that agent requested this sub-delegation.
- NOESC (the §9.4 claim): every operation the DS executes for H is within H's policy or a CIBA approval by H.
- ATTR_DS: the DID the DS logs for an executed operation belongs to an agent that decided it (Request(did, a, tid)).
- ATTR_R: the principal R logs decided the request. R logs the DS.
- TASK static / dynamic: as before.

## Predicted verdicts
| Variant | CHAINAUTH | NOESC | ATTR_DS | ATTR_R | TASK st | TASK dyn |
|---|---|---|---|---|---|---|
| spec_min | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| subpop | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| didpreauth | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| subpop_didpreauth | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| exact_consent | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |

Reasons:
- Without SUBPOP, anyone holding a leaked root DT can request a child DT, so a splice works even with `prf` receipts. The receipt records the hop; it does not authenticate it.
- Without DIDPREAUTH, a steered agent (or the adversary directly, within policy) can obtain a DT for a key the adversary minted. The DS's audit trail then names a DID that is no agent: ATTR_DS fails. SUBPOP does not help, because the steered parent signs the sub-delegation to the adversary's DID.
- NOESC holds everywhere: the §9.4 blast-radius claim is correct for the capability bound.

## Witnesses (exists-trace), predicted
- W1 `witness_splice_child_without_parent_request`: a child DT is issued from a registered agent's DID without that agent's request. Exists iff not SUBPOP.
- W2 `witness_exercise_by_unregistered_did`: the DS executes an operation for H under a DID that is no registered agent's key. Exists iff not DIDPREAUTH.
- W3 `witness_identity_collapse_at_resource`: two different DIDs' operations reach R with identical logged principal (H, DS). Exists in all variants.

## Candidate findings
- (W-a) The `prf` receipt does not by itself prevent splicing. It closes F1 only when the DS also requires proof of possession by the parent on the sub-delegation request, which the draft does not state.
- (W-b) Self-generated, never-rejected DIDs make the audit trail attribute actions to keys, not agents. A steered agent can delegate to an adversary-held key within its capability. Attribution needs the MAY-level DID pre-authorization.
- (W-c) Credential wrapping moves attribution to the DS but recreates identity collapse at the resource (as MCP M1).
- (W-d) §9.4 holds for NOESC, but the capability is chosen by the steered agent within policy. TASK-static needs consent to the exact operand, and TASK-dynamic fails, as in F3 and M4.

Not modeled: depth > 2, revocation and cascade timing, expiry, CIBA UX details beyond EXACT, KEYCOMP, agent_operator claims, model attestation.

## Addendum: W3 under POLICY via trace-pruning restrictions (written 2026-10-10T01:36:05Z, before the run)
W3 timed out in spec_min, subpop, didpreauth and subpop_didpreauth. Restrictions only remove traces, so a W3 trace found in a model with extra restrictions is a W3 trace of the unrestricted model. Added restrictions (W3 search only): no dynamic tasks; no child DTs; root DT capabilities concrete (no <op,'any'>); root DTs only for registered keys. Prediction: W3 found in all four (two registered agents each get a root DT for H within push:any, each exercises, R logs (H, DS) twice). A timeout here would leave W3 unresolved, never falsified.

## Addendum: R009 KEYCOMP (written 2026-10-10T02:24:29Z, before the run)
Generator mode `gen_wimse.py <dir> kc` adds `Reveal_ltk` to the 5 steered variants. Guards: CHAINAUTH: DS or D1; NOESC, TASK: DS; ATTR_DS, ATTR_R: DS or the owner of the logged DID. Witnesses W1/W2 and executability carry "no reveal at all"; W3 is not rerun under KEYCOMP (search cost; covered by the steered run).
- (a) Property cells equal the steered table (30/30); W1/W2 keep their steered results (10/10); 10/10 executability verify.
- (b) Classic-baseline witnesses found in all 5: a DS reveal breaks NOESC; a reveal of the agent owning the logged DID breaks ATTR_DS.
