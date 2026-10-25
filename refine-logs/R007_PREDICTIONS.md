# R007 predictions: MCP authorization (spec revision 2026-07-28)

Written 2026-10-09T21:28:55Z, before any R007 model existed.
Sources: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization and .../authorization/security-considerations (fetched 2026-10-09).

## Spec facts the model relies on (verbatim)
- Roles: "A protected MCP server acts as an OAuth 2.1 resource server"; "An MCP client acts as an OAuth 2.1 client, making protected resource requests on behalf of a resource owner."
- Audience (MUST): "MCP servers MUST validate that access tokens were issued specifically for them as the intended audience"; "MCP servers MUST only accept tokens that are valid for use with their own resources." Clients "MUST" send the RFC 8707 `resource` parameter identifying the MCP server.
- Upstream (MUST NOT): "If the MCP server makes requests to upstream APIs, it may act as an OAuth client to them. The access token used at the upstream API is a separate token, issued by the upstream authorization server. The MCP server MUST NOT pass through the token it received from the MCP client." The spec says nothing about how that upstream token is obtained or which identity it carries.
- Scopes (SHOULD only): on insufficient scope "the server SHOULD respond with HTTP 403 Forbidden ... error=\"insufficient_scope\""; "The required scopes may be determined dynamically based on the specific request arguments and context"; "Servers MUST account for scope hierarchies".
- Token usage: `Authorization: Bearer <access-token>`. The spec has no sender-constraining mechanism (no DPoP or mTLS).
- The core spec defines no RAR, no `act` and no agent identity claim. Enterprise-Managed Authorization and other ext-auth extensions are out of scope for this run.

## Flow modeled (one tool hop)
- H consents to MCP client (agent) A for MCP server M: the MCP AS issues T1 = (sub H, client A, aud, scope s1, task id).
- Separately, H once authorizes M as an OAuth client of upstream AS2 for resource R. M stores a per-user upstream token.
- Steered A sends a tool call (action a) with T1 to M. M validates T1 and calls R with H's stored upstream token. R logs (sub H, logged client L).

Adversary:
- Agents are steered. Anything an LLM agent holds (T1) is adversary-known, because a steered agent can be made to leak it.
- M and R are non-LLM server code. Their stored secrets (upstream tokens) are private, and M→R runs over TLS.
- A token H issued for another MCP server M' (a malicious or unrelated tool) is therefore also adversary-known.

## Variant knobs
| Knob | Meaning | Spec status |
|---|---|---|
| AUDM | M checks aud = M | MUST |
| SCOPECHK | M requires T1's scope to cover the tool's operation (403 otherwise) | SHOULD |
| OPSCOPE | scopes at operand granularity: static task, H consents to the exact repo; dynamic task, the agent proposes the operand at step-up and H approves it | MAY ("determined dynamically based on request arguments") |
| XCHG | the upstream token carries the agent (RFC 8693 act = A) and R logs A instead of M's client id | not in the spec |
| DPOP | T1 is bound to A's key; M requires a proof over (a, M, T1) | not in the spec |

Variants:
- spec = AUDM+SCOPECHK
- spec_must = AUDM
- noaud = SCOPECHK
- noaud_noscope = none
- opscope = AUDM+SCOPECHK+OPSCOPE
- xchg = AUDM+SCOPECHK+XCHG
- xchg_dpop = AUDM+SCOPECHK+XCHG+DPOP

## Properties
- CONSENT_M (AUTH analogue): if M executes a call under a token naming (H, A), then H consented A for M.
- NOESC: if R accepts a for H via M, then H consented some client at M with a scope covering a.
- ATTR_agent: the client R logs is the agent that decided the call (a Request event by L for a).
- TASK static / dynamic: as in R003 and R006.

## Predicted verdicts
| Variant | CONSENT_M | NOESC | ATTR_agent | TASK static | TASK dyn |
|---|---|---|---|---|---|
| spec | ✓ | ✓ | ✗ | ✗ | ✗ |
| spec_must | ✓ | ✗ | ✗ | ✗ | ✗ |
| noaud | ✗ | ✗ | ✗ | ✗ | ✗ |
| noaud_noscope | ✗ | ✗ | ✗ | ✗ | ✗ |
| opscope | ✓ | ✓ | ✗ | ✓ | ✗ |
| xchg | ✓ | ✓ | ✗ | ✗ | ✗ |
| xchg_dpop | ✓ | ✓ | ✓ | ✗ | ✗ |

Reasons:
- ATTR_agent fails in every spec configuration because R logs M's client identity: no spec field carries the agent. This is identity collapse.
- With XCHG alone ATTR_agent still fails, because T1 is a bearer token the steered agent can leak, so the adversary makes calls A never decided (same as R006 F2: binding is needed).
- spec_must fails NOESC: M holds one broad upstream token per user, so any client H consented for a narrow scope at M can drive any upstream operation (scope escalation through the shared upstream token).

## Witnesses (exists-trace), predicted
- W1 `witness_cross_server_token_replay`: M executes on a token H issued for another server M'. Exists iff not AUDM.
- W2 `witness_scope_escalation_via_upstream_token`: R accepts an operation outside the scope H granted the calling client at M. Exists iff not SCOPECHK.
- W3 `witness_identity_collapse`: two different agents' calls produce R log entries with the same logged client for the same user. Exists iff not XCHG.

## Candidate findings
- (M1) Identity collapse is spec-level. The MCP spec forbids passthrough but leaves the upstream identity unspecified, so the resource cannot distinguish agents. This is the paper's motivating problem stated as a property of the spec, not of an implementation.
- (M2) The MCP-level scope check is only a SHOULD, yet it is the sole barrier against escalation through the server's shared per-user upstream token.
- (M3) Operand granularity: operand-level step-up scopes give TASK-static. TASK-dynamic fails because the human approves an agent-proposed operand without provenance (same as R006 F3).

Not modeled: token passthrough itself (it needs R to accept MCP-AS tokens), mix-up and issuer validation, CIMD/DCR, refresh tokens, KEYCOMP, multiple MCP hops, and the Enterprise-Managed Authorization extension.

## Addendum (written 2026-10-09T21:38:21Z, after the R007 steered run and the findings review, before either extension existed)

### (1) NOLEAK: attack bound for M3 (requested by reviewer thread 57032c976402)
Knob NOLEAK: T1 reaches the agent over a private channel and the tool call reaches M over TLS (modeled as linear facts). The steered agent still chooses the action, the server and which of its own tokens to use, but the adversary never learns T1.

New variants:
- spec_noleak = AUDM+SCOPECHK+NOLEAK
- xchg_noleak = AUDM+SCOPECHK+XCHG+NOLEAK

| Variant | CONSENT_M | NOESC | ATTR_agent | TASK static | TASK dyn | W1 | W2 | W3 |
|---|---|---|---|---|---|---|---|---|
| spec_noleak | ✓ | ✓ | ✗ | ✗ | ✗ | none | none | found |
| xchg_noleak | ✓ | ✓ | ✓ | ✗ | ✗ | none | none | none |

Meaning:
- M1 (identity collapse) does not depend on token leakage.
- The bearer half of M3 does: without leakage, carrying the agent upstream is enough for ATTR_agent.
- So DPoP is needed exactly when the agent's token can be exfiltrated. Under prompt injection that is the realistic case, but it is an assumption and the paper must state it.

### (2) KEYCOMP
Variants `kc_<name>` for the 7 original variants. `Reveal` can leak any long-term key, including the MCP AS key. Lemmas are guarded by the keys they rely on:
- CONSENT_M, NOESC, TASK: the AS key;
- ATTR_agent: the AS key and the key of the logged client L.

Prediction (a): the kc table equals the steered table cell for cell (35/35). W1–W3, restricted to traces with no AS reveal, keep their steered results (21/21). Executability lemmas, which forbid all reveals, verify (14/14).

Prediction (b), classic baseline, a trace in all 7 variants:
- `kc_witness_as_reveal_breaks_CONSENT_M`: M executes a call with no matching consent, using Reveal(AS);
- `kc_witness_client_reveal_breaks_ATTR`: R logs L but L never requested the call, using Reveal(L). In xchg_dpop this works by forging the DPoP proof.
