# R008 predictions: OAuth On-Behalf-Of User Authorization for AI Agents (draft-oauth-ai-agents-on-behalf-of-user-02)

Written 2026-10-09T21:41:45Z, before any R008 model existed. Source: https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-02.txt (dated 26 August 2025, Informational individual draft, expired 27 February 2026, not adopted by the OAuth WG; it is the -02 revision named in the proposal).

## Spec facts the model relies on (verbatim)
- §4.1: the authorization request "MUST include the requested_actor request parameter".
- §5: "The Authorization Server MUST bind the Authorization Code to the specific user, client (client_id), and requested actor (requested_actor) during issuance and verify this binding during the Token Request."
- §4.2.1: actor_token "MUST be a valid token issued to the actor and MUST include the sub claim identifying the actor".
- §4.2.2: the AS MUST verify "that the actor token is valid, not expired" and that "the authenticated actor identity (obtained from the Actor Token's sub claim) matches the requested_actor value that the user consented to".
- §5: "The method by which actors obtain and secure their Actor Tokens is critical and outside the scope of this specification".
- §4.3: the access token "MUST contain" `act` with REQUIRED `act.sub` (the actor). sub, azp, aud and scope appear only in examples.
- §4.4.1: the RS "MUST validate the Access Token", including "verifying the token contains the appropriate delegation claims (e.g., an act claim) for that Actor".
- §5: "Authorization Codes MUST be single-use"; "PKCE [RFC7636] is REQUIRED".
- There is no client-authentication requirement at the token endpoint and no sender-constraining (DPoP is not mentioned). `act` is a single object, so there is no multi-hop delegation.

## Flow (n = 2 in our chain: H → client K (orchestrating agent) → actor A (agent) → R)
1. K sends an authorization request (requested_actor A, scope s). H consents to (K, A, s). The AS stores code state bound to (H, K, A, s) and returns the code to K.
2. A token request carries the code and A's actor_token. The AS checks the actor_token signature and that its sub = A, consumes the code (single use), and issues AT = (sub H, azp K, act.sub A, s, cnf, tid).
3. A holder presents AT plus action a to R. R checks the AS signature and the scope, then logs (H, K, A, a).

Adversary:
- K and A are steered. Anything they hold (code, PKCE verifier, actor_token, AT) is adversary-known, because a steered agent can be made to leak it. With a steered client, PKCE adds nothing against this adversary; it protects only against third parties.
- The AS, R and humans are honest.

## Variant knobs
| Knob | Meaning | In draft? |
|---|---|---|
| ACTBIND | the actor proves participation in this specific flow: a signature by A's key over the code/flow id replaces the reusable bearer actor_token | no (§5 leaves actor credentials out of scope) |
| DPOPC | RFC 9449 as usually deployed: cnf = the key that proves possession at the token endpoint, i.e. the redeeming party (client K, or anyone holding the code, since there is no client authentication); R checks the proof against cnf | no |
| DPOPA | cnf = the actor A's registered key; R requires A's proof | no |

Variants: base, actbind, dpop_client, dpop_client_actbind, dpop_actor, dpop_actor_actbind.

## Properties
- AUTH_consent: R accepts (H, K, A, a) ⇒ H consented to client K with actor A for this flow.
- PARTICIPATION: R accepts with act.sub = A ⇒ A joined this specific delegation (ActorJoined(A, tid)).
- NOESC: the action is within the consented scope.
- ATTR_actor: the logged actor A decided the request (Request(A, a, tid)).
- TASK static / dynamic: as before. The scope is coarse and there is no RAR, so both are predicted ✗; this is not the focus.

## Predicted verdicts
| Variant | AUTH_consent | PARTICIPATION | NOESC | ATTR_actor | TASK st | TASK dyn |
|---|---|---|---|---|---|---|
| base | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| actbind | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| dpop_client | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| dpop_client_actbind | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| dpop_actor | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ |
| dpop_actor_actbind | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |

## Witnesses (exists-trace), predicted
- W1 `witness_client_acts_logged_as_actor` (framing the agent): R logs actor A for a request that client K made (Request(K, a, tid)) and A never made, with K ≠ A. Exists iff not DPOPA. In particular it exists in dpop_client, with a correctly sender-constrained token.
- W2 `witness_actor_named_without_participation`: R accepts a token naming A as actor although A never joined this delegation. Exists iff not ACTBIND.

## Candidate findings
- (O1) The draft names a party (act.sub) that never redeems the code. Standard DPoP binds the token to the redeemer (the client), so the RS attributes the client's requests to the agent. Sender-constraining fixes attribution only if the binding key is the actor's.
- (O2) The actor_token is a reusable credential with unspecified validation and no binding to the flow, so a client holding (or a steered agent leaking) A's actor_token can obtain delegations naming A that A never joined. The audit trail the draft promises ("essential information for auditing actions") is then not evidence of agent participation.
- (O3) Not modeled, noted only: act is a single object, so the draft cannot express a sub-agent hop.

Not modeled: PKCE as a separate mechanism (subsumed, see above), consent-screen UX, refresh tokens, KEYCOMP, aud/resource checks at R, RAR.

## KEYCOMP addendum (written 2026-10-09T21:57:44Z, before any R008 KEYCOMP model existed)
Variants `kc_<name>` for all 6 knob sets. `Reveal` can leak any long-term key, including the AS key. The AS key signs both actor tokens and access tokens. Lemmas are guarded by the keys they rely on:
- AUTH_consent, NOESC, TASK: AS;
- PARTICIPATION: AS and the actor Y (Y's key forges the flow-bound join signature);
- ATTR_actor: AS and Y (Y's key forges the actor-bound DPoP proof).

The client's key is in no guard. In dpop_client the cnf key is whatever the redeemer presents, so K's key never protects anything.

Prediction (a): the kc table equals the steered table (36/36). W1 and W2, restricted to traces with no reveal of AS or Y, keep their steered results (12/12). Executability lemmas, which forbid all reveals, verify (12/12).

Prediction (b), classic baseline, a trace in all 6 variants:
- `kc_witness_as_reveal_breaks_AUTH`: R accepts with no matching consent, using Reveal(AS);
- `kc_witness_actor_reveal_breaks_ATTR`: R logs actor Y but Y never requested, using Reveal(Y). In the dpop_actor variants this works by forging Y's DPoP proof.
