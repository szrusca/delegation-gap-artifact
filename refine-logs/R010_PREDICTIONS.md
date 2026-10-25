# R010 predictions: AIP (Biscuit chained mode), reduced per the W6 gate

Written 2026-10-10T02:28:05Z, before the model existed. Source: S. Prakash, "AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A", arXiv:2603.24775v1, 25 Mar 2026 (https://arxiv.org/abs/2603.24775).

W6 gate: P1–P4 already witness every lattice cell (Chain ⇒ AUTH ∧ NOESC; Chain ⇏ ATTR; ReqBind ⇒ ATTR; ReqBind ⇏ TASK; Capsule ⇒ TASK-static; Capsule + Prov ⇒ TASK-dynamic in R012). AIP is therefore reduced to the TASK counterexample, plus the cheap cells of the same model.

## Paper facts the model relies on
- Block 0 (authority) is signed by the human or initiating system: identity, rights (tool-level scopes), budget, max depth, expiry.
- Each delegation block is signed by the delegating agent, narrows scope (subset enforced) and carries a mandatory free-text `context` written by the delegator.
- The MCP server verifies all signatures, evaluates the Datalog policy against the requested tool (allowlist, budget, depth, time), requires a non-empty context. No argument-level constraint and no proof of possession are specified ("real-time replay within the TTL is not prevented by the token alone").
- Threat model: misuse within granted scope "is out of scope for the token layer"; prompt injection is not discussed.

## Model (`models/AIP.spthy`, n = 2)
H → A1 → A2 → MCP server M. Block 0 grants tool right push (caveat `<'push','any'>`). Steered A1 appends a delegation block with adversary-chosen delegatee, narrowed right and context. Steered A2 calls M with adversary-chosen tool arguments, presenting the token (bearer). M logs (A2, a, context).

## Predicted verdicts
| AUTH | NOESC | ATTR | TASK st | TASK dyn |
|---|---|---|---|---|
| ✓ | ✓ | ✗ | ✗ | ✗ |
Witness `witness_context_laundering` (new): M accepts a ≠ the human's intended operand while the audit context in the chain states exactly the human's intended operand. Expected found. Executability (static, dynamic) expected ✓.
