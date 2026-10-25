import crypto from "node:crypto";

const KC = process.env.KC_URL ?? "http://127.0.0.1:18080";
const REALM = "r013";
const ADMIN_PASSWORD = process.env.KC_ADMIN_PASSWORD;
const results = [];

async function form(url, params) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params) });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  return { status: res.status, body };
}

async function admin(method, path, token, payload) {
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  if (res.status >= 300) throw new Error(`${method} ${path} -> ${res.status} ${await res.text()}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

function decode(jwt) {
  const [h, p] = jwt.split(".");
  return { header: JSON.parse(Buffer.from(h, "base64url")), payload: JSON.parse(Buffer.from(p, "base64url")) };
}

async function resourceAccepts(jwt, { audCheck }) {
  const jwks = await (await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/certs`)).json();
  const { header, payload } = decode(jwt);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return { accepted: false, reason: "unknown kid" };
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const [h, p, s] = jwt.split(".");
  const ok = crypto.verify("RSA-SHA256", Buffer.from(`${h}.${p}`), key, Buffer.from(s, "base64url"));
  if (!ok) return { accepted: false, reason: "bad signature" };
  if (payload.exp * 1000 < Date.now()) return { accepted: false, reason: "expired" };
  if (payload.iss !== `${KC}/realms/${REALM}`) return { accepted: false, reason: "issuer" };
  const scopes = String(payload.scope ?? "").split(" ");
  if (!scopes.includes("repo:push")) return { accepted: false, reason: "scope" };
  if (audCheck) {
    const aud = [].concat(payload.aud ?? []);
    if (!aud.includes("repo-r")) return { accepted: false, reason: `aud ${JSON.stringify(payload.aud)}` };
  }
  return { accepted: true, logged: { sub: payload.sub, preferred_username: payload.preferred_username, azp: payload.azp, act: payload.act ?? null } };
}

function client(clientId, extra = {}) {
  return {
    clientId,
    enabled: true,
    publicClient: false,
    secret: `${clientId}-secret`,
    standardFlowEnabled: false,
    directAccessGrantsEnabled: true,
    serviceAccountsEnabled: false,
    attributes: { "standard.token.exchange.enabled": "true" },
    defaultClientScopes: ["repo:push", "profile"],
    ...extra,
  };
}

async function setup() {
  const adminTok = (await form(`${KC}/realms/master/protocol/openid-connect/token`, { grant_type: "password", client_id: "admin-cli", username: "admin", password: ADMIN_PASSWORD })).body.access_token;
  try { await admin("DELETE", `/${REALM}`, adminTok); } catch {}
  await admin("POST", "", adminTok, { realm: REALM, enabled: true });
  await admin("POST", `/${REALM}/client-scopes`, adminTok, { name: "repo:push", protocol: "openid-connect", attributes: { "include.in.token.scope": "true" } });
  await admin("POST", `/${REALM}/clients`, adminTok, client("repo-r", { directAccessGrantsEnabled: false, bearerOnly: false }));
  await admin("POST", `/${REALM}/clients`, adminTok, client("agent-a1"));
  await admin("POST", `/${REALM}/clients`, adminTok, client("agent-a2"));
  await admin("POST", `/${REALM}/users`, adminTok, { username: "alice", enabled: true, email: "alice@example.org", emailVerified: true, firstName: "Alice", lastName: "Human", credentials: [{ type: "password", value: "alice-pw", temporary: false }] });
  return adminTok;
}

async function addAudienceMapper(adminTok, fromClient, audience) {
  const [c] = await admin("GET", `/${REALM}/clients?clientId=${fromClient}`, adminTok);
  await admin("POST", `/${REALM}/clients/${c.id}/protocol-mappers/models`, adminTok, {
    name: `aud-${audience}`, protocol: "openid-connect", protocolMapper: "oidc-audience-mapper",
    config: { "included.client.audience": audience, "access.token.claim": "true", "id.token.claim": "false" },
  });
}

const tokenUrl = `${KC}/realms/${REALM}/protocol/openid-connect/token`;
const login = (clientId) => form(tokenUrl, { grant_type: "password", client_id: clientId, client_secret: `${clientId}-secret`, username: "alice", password: "alice-pw", scope: "repo:push" });
const exchange = (clientId, subjectToken, audience) => form(tokenUrl, {
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", client_id: clientId, client_secret: `${clientId}-secret`,
  subject_token: subjectToken, subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
  requested_token_type: "urn:ietf:params:oauth:token-type:access_token", audience, scope: "repo:push",
});

const adminTok = await setup();
const t0 = await login("agent-a1");
if (!t0.body.access_token) throw new Error(`login failed ${JSON.stringify(t0.body)}`);
const T0 = t0.body.access_token;
results.push({ id: "T0", claims: decode(T0).payload });

const k1 = await exchange("agent-a2", T0, "repo-r");
results.push({ id: "K1", status: k1.status, body: k1.body, issued: k1.body.access_token ? decode(k1.body.access_token).payload : null });

await addAudienceMapper(adminTok, "agent-a1", "agent-a2");
await addAudienceMapper(adminTok, "agent-a2", "repo-r");
const T0b = (await login("agent-a1")).body.access_token;
results.push({ id: "T0b", claims: decode(T0b).payload });
const k2 = await exchange("agent-a2", T0b, "repo-r");
const T2 = k2.body.access_token;
results.push({ id: "K2", status: k2.status, body: T2 ? { issued: decode(T2).payload } : k2.body });
results.push({ id: "K3", act_present: T2 ? "act" in decode(T2).payload : null, azp: T2 ? decode(T2).payload.azp : null });
results.push({ id: "K2-resource", noAud: T2 ? await resourceAccepts(T2, { audCheck: false }) : null, audCheck: T2 ? await resourceAccepts(T2, { audCheck: true }) : null });

results.push({ id: "K4", result: await resourceAccepts(T0, { audCheck: false }) });
results.push({ id: "K5", result: await resourceAccepts(T0, { audCheck: true }) });

console.log(JSON.stringify(results, null, 2));
