# R014 Predictions — implementation replay of M1–M3 on the official MCP TypeScript SDK

Written: 2026-10-23T22:44:26Z, after reading the SDK's bearer middleware (server/auth/middleware/bearerAuth.js) and before any replay script exists.

Target: @modelcontextprotocol/sdk 1.32.1 (npm, published 2026-10-05), Node v24.22.0, express 4.21.2. Setup in models/r014/:
- AS: an in-process token store standing in for the MCP authorization server. It issues opaque T1 tokens for user H with fields clientId, scopes, resource (audience), and expiresAt, and the SDK verifier interface returns them as AuthInfo.
- M: an McpServer with a streamable HTTP transport behind requireBearerAuth({ verifier, requiredScopes: ["mcp"], expectedResource: M }). Tool push(repo) calls the upstream resource R with H's stored upstream token U_H (spec: "a separate token, issued by the upstream authorization server").
- R: an HTTP server that logs Authorization and body of every call.
- Clients use the SDK's Client with StreamableHTTPClientTransport and an Authorization header.

| ID | Experiment | Prediction |
|---|---|---|
| K1 (M1) | client-a and client-b, both holding T1 for H, each call push(repoX) | both calls accepted; R's two log entries are identical (same token U_H, same body); no field names the client |
| K2 (M2) | client-c holds T1 with scopes {mcp, repo:read} and calls push(repoX); the tool has no per-tool scope check | accepted; R executes the push. The SDK checks only server-wide requiredScopes |
| K2-fix | same, with the tool checking that extra.authInfo.scopes contains repo:write | rejected; no call reaches R |
| K3 (M3) | client-a's T1 presented by a different process | accepted; M sees authInfo.clientId = client-a. The SDK server has no DPoP or sender constraint |
| K4a | T1 with resource = another server, M configured with expectedResource | rejected with 401 |
| K4b | same token, M configured without expectedResource (the middleware default) | accepted |

Expected outcome: M1, M2 and M3 reproduce on the reference SDK. The SDK's audience check is opt-in.
