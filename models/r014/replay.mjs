import express from 'express';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

const PORT_R = 18081;
const PORT_M = 18082;
const PORT_M_NOAUD = 18083;
const PORT_M_FIX = 18084;
const PORT_M3 = 18085;
const M_URL = `http://127.0.0.1:${PORT_M}/mcp`;
const M_NOAUD_URL = `http://127.0.0.1:${PORT_M_NOAUD}/mcp`;
const M_FIX_URL = `http://127.0.0.1:${PORT_M_FIX}/mcp`;
const M3_URL = `http://127.0.0.1:${PORT_M3}/mcp`;
const OTHER_RESOURCE = 'http://other-server.example/mcp';
const UPSTREAM_TOKEN_H = 'U_H_' + randomBytes(8).toString('hex');

const tokenStore = new Map();
function issueT1({ clientId, scopes, resource }) {
  const token = 'T1_' + randomBytes(12).toString('hex');
  tokenStore.set(token, { token, clientId, scopes, resource, expiresAt: Math.floor(Date.now() / 1000) + 600, extra: { sub: 'H' } });
  return token;
}
const verifier = {
  async verifyAccessToken(token) {
    const info = tokenStore.get(token);
    if (!info) throw new (await import('@modelcontextprotocol/sdk/server/auth/errors.js')).InvalidTokenError('unknown token');
    return info;
  },
};

const upstreamLog = [];
const r = express();
r.use(express.json());
r.post('/api/push', (req, res) => {
  upstreamLog.push({ authorization: req.headers.authorization, body: req.body, headerNames: Object.keys(req.headers).sort() });
  res.json({ ok: true });
});

const mLog = [];
function buildMcpApp({ expectedResource, perToolScope }) {
  const app = express();
  app.use(express.json());
  const auth = requireBearerAuth({ verifier, requiredScopes: ['mcp'], ...(expectedResource ? { expectedResource } : {}) });
  app.post('/mcp', auth, async (req, res) => {
    const server = new McpServer({ name: 'M', version: '1.0.0' });
    server.tool('push', { repo: z.string() }, async ({ repo }, extra) => {
      const authInfo = extra.authInfo;
      if (perToolScope && !authInfo.scopes.includes('repo:write')) {
        mLog.push({ event: 'tool_rejected', clientId: authInfo.clientId, repo });
        return { isError: true, content: [{ type: 'text', text: 'insufficient scope for push' }] };
      }
      mLog.push({ event: 'tool_call', clientId: authInfo.clientId, scopes: authInfo.scopes, repo });
      const resp = await fetch(`http://127.0.0.1:${PORT_R}/api/push`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${UPSTREAM_TOKEN_H}` },
        body: JSON.stringify({ op: 'push', repo }),
      });
      return { content: [{ type: 'text', text: `upstream ${resp.status}` }] };
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  return app;
}

async function callPush(url, token, repo, clientName) {
  const client = new Client({ name: clientName, version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: 'push', arguments: { repo } });
    await client.close();
    return { accepted: !result.isError, text: result.content?.[0]?.text ?? null };
  } catch (e) {
    try { await client.close(); } catch {}
    const m = String(e?.message ?? e);
    const status = (m.match(/\b(401|403)\b/) || [null])[0];
    return { accepted: false, status: status ? Number(status) : null, error: m.slice(0, 200) };
  }
}

function listen(app, port) {
  return new Promise(resolve => { const s = app.listen(port, '127.0.0.1', () => resolve(s)); });
}

const servers = [];
servers.push(await listen(r, PORT_R));
const results = { sdk: '1.32.1', node: process.version, startedAt: new Date().toISOString(), experiments: {} };

let app = buildMcpApp({ expectedResource: M_URL, perToolScope: false });
let ms = await listen(app, PORT_M);

const tA = issueT1({ clientId: 'client-a', scopes: ['mcp', 'repo:write'], resource: M_URL });
const tB = issueT1({ clientId: 'client-b', scopes: ['mcp', 'repo:write'], resource: M_URL });
const l0 = upstreamLog.length;
const k1a = await callPush(M_URL, tA, 'repoX', 'agent-a');
const k1b = await callPush(M_URL, tB, 'repoX', 'agent-b');
const e1 = upstreamLog.slice(l0);
results.experiments.K1 = {
  calls: [k1a, k1b], upstreamEntries: e1,
  identical: e1.length === 2 && JSON.stringify(e1[0]) === JSON.stringify(e1[1]),
  clientNamedUpstream: e1.some(e => JSON.stringify(e).includes('client-')),
};

const tC = issueT1({ clientId: 'client-c', scopes: ['mcp', 'repo:read'], resource: M_URL });
const l2 = upstreamLog.length;
const k2 = await callPush(M_URL, tC, 'repoX', 'agent-c');
results.experiments.K2 = { call: k2, upstreamCalls: upstreamLog.length - l2 };

const tCfix = issueT1({ clientId: 'client-c', scopes: ['mcp', 'repo:read'], resource: M_FIX_URL });
const msFix = await listen(buildMcpApp({ expectedResource: M_FIX_URL, perToolScope: true }), PORT_M_FIX);
const l2f = upstreamLog.length;
const m2f = mLog.length;
const k2f = await callPush(M_FIX_URL, tCfix, 'repoX', 'agent-c');
results.experiments.K2_fix = { call: k2f, upstreamCalls: upstreamLog.length - l2f, serverSaw: mLog.slice(m2f) };
await new Promise(res => msFix.close(res));

const tA3 = issueT1({ clientId: 'client-a', scopes: ['mcp', 'repo:write'], resource: M3_URL });
const ms3 = await listen(buildMcpApp({ expectedResource: M3_URL, perToolScope: false }), PORT_M3);
const m3 = mLog.length;
const k3 = await callPush(M3_URL, tA3, 'repoY', 'attacker-process');
results.experiments.K3 = { call: k3, serverSaw: mLog.slice(m3) };
await new Promise(res => ms3.close(res));

const tOther = issueT1({ clientId: 'client-a', scopes: ['mcp', 'repo:write'], resource: OTHER_RESOURCE });
const k4a = await callPush(M_URL, tOther, 'repoX', 'agent-a');
results.experiments.K4a = { call: k4a };
await new Promise(res => ms.close(res));

const appNoAud = buildMcpApp({ expectedResource: undefined, perToolScope: false });
const ms2 = await listen(appNoAud, PORT_M_NOAUD);
const k4b = await callPush(M_NOAUD_URL, tOther, 'repoX', 'agent-a');
results.experiments.K4b = { call: k4b };
ms2.close();

results.upstreamTokenRedacted = UPSTREAM_TOKEN_H.slice(0, 4) + '…';
const redact = s => s.replaceAll(UPSTREAM_TOKEN_H, 'U_H_<redacted>');
writeFileSync(process.argv[2] ?? 'run.json', redact(JSON.stringify(results, null, 2)));
for (const s of servers) s.close();
console.log(redact(JSON.stringify(Object.fromEntries(Object.entries(results.experiments).map(([k, v]) => [k, v.call ? v.call.accepted : v.identical])))));
process.exit(0);
