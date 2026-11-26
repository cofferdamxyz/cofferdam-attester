// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

// The attester's CDP client (workspace decision 0090; cdp-setup.md E7) against
// a fake CDP that checks what the real one checks: the bearer JWT under the
// API key's Ed25519 public key, the wallet JWT under the Wallet Secret's P-256
// public key, and `reqHash` against the body sent. Throwaway keys only.

import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { recoverTypedDataAddress, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { beforeAll, describe, expect, it } from 'vitest';

import { CdpKeyError, importApiKeySecret, requestHash, requiresWalletAuth, sortKeys } from '../src/cdp/auth.js';
import { CdpApiError, cdpCredentialsOf, CdpResponseError, createCdpClient, type CdpCredentials } from '../src/cdp/client.js';
import { ceremonyTypedData, CEREMONY_ACTIONS } from '../src/ceremony.js';

const KEY_ID = 'organizations/test/apiKeys/attester';
const NOW = 1_800_000_000;
// A throwaway key standing in for the CDP account's enclave key.
const ACCOUNT = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const REGISTRY: Hex = '0x44A2B59d5D39f773C2e65469e0Dd3217E53823Af';
const INPUTS = {
  chainId: 84532n,
  account: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9' as Hex,
  action: CEREMONY_ACTIONS['enroll-first-high'],
  newKeyHash: `0x${'11'.repeat(32)}` as Hex,
  partnerId: `0x${'22'.repeat(32)}` as Hex,
  nonce: 7n,
  notBefore: 1_800_000_000n,
  expiry: 1_800_000_600n,
};
const TYPED = ceremonyTypedData(INPUTS, REGISTRY);

const b64 = (bytes: ArrayBuffer | Uint8Array) => Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString('base64');
const fromB64Url = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const decodePart = (s: string) => JSON.parse(fromB64Url(s).toString('utf8')) as Record<string, unknown>;

let creds: CdpCredentials;
let apiPublic: CryptoKey;
let walletPublic: CryptoKey;

beforeAll(async () => {
  const ed = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const edJwk = (await crypto.subtle.exportKey('jwk', ed.privateKey)) as JsonWebKey;
  const seedAndPublic = Buffer.concat([fromB64Url(edJwk.d!), fromB64Url(edJwk.x!)]);
  const ec = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  creds = { apiKeyId: KEY_ID, apiKeySecret: b64(seedAndPublic), walletSecret: b64((await crypto.subtle.exportKey('pkcs8', ec.privateKey)) as ArrayBuffer) };
  apiPublic = ed.publicKey;
  walletPublic = ec.publicKey;
});

async function verifyJwt(token: string, key: CryptoKey, algorithm: Parameters<SubtleCrypto['verify']>[0]) {
  const [h, c, s] = token.split('.');
  const ok = await crypto.subtle.verify(algorithm, key, fromB64Url(s!), new TextEncoder().encode(`${h}.${c}`));
  return { ok, header: decodePart(h!), claims: decodePart(c!) };
}

interface Seen {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

/** A fake CDP: records each request, checks both JWTs, then answers with `reply`. */
function fakeCdp(reply: (req: Seen) => Promise<Response> | Response) {
  const seen: Seen[] = [];
  const problems: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req: Seen = {
      method: init?.method ?? 'GET',
      url: String(input),
      headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])),
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    seen.push(req);
    const url = new URL(req.url);
    const uri = `${req.method} ${url.host}${url.pathname}`;
    const bearer = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
    const b = await verifyJwt(bearer, apiPublic, { name: 'Ed25519' });
    if (!b.ok) problems.push('bearer signature');
    if (b.header.alg !== 'EdDSA' || b.header.kid !== KEY_ID || b.header.typ !== 'JWT' || !/^[0-9a-f]{32}$/.test(String(b.header.nonce))) problems.push('bearer header');
    if (b.claims.sub !== KEY_ID || b.claims.iss !== 'cdp' || b.claims.iat !== NOW || b.claims.nbf !== NOW || b.claims.exp !== NOW + 120) problems.push('bearer claims');
    if (JSON.stringify(b.claims.uris) !== JSON.stringify([uri])) problems.push('bearer uris');
    const walletAuth = req.headers['x-wallet-auth'];
    if (!walletAuth) problems.push('no wallet JWT');
    else {
      const w = await verifyJwt(walletAuth, walletPublic, { name: 'ECDSA', hash: 'SHA-256' });
      if (!w.ok) problems.push('wallet signature');
      if (w.header.alg !== 'ES256' || w.header.typ !== 'JWT' || 'kid' in w.header) problems.push('wallet header');
      if (w.claims.iat !== NOW || w.claims.nbf !== NOW || 'exp' in w.claims || !/^[0-9a-f]{32}$/.test(String(w.claims.jti))) problems.push('wallet claims');
      if (JSON.stringify(w.claims.uris) !== JSON.stringify([uri])) problems.push('wallet uris');
      // CDP's side: the hash of the body it received, keys sorted, by an independent SHA-256.
      const expected = req.body ? createHash('sha256').update(JSON.stringify(sortKeys(JSON.parse(req.body)))).digest('hex') : undefined;
      if (w.claims.reqHash !== expected) problems.push('wallet reqHash');
    }
    return reply(req);
  }) as typeof fetch;
  return { seen, problems, fetchFn };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('auth (copied from the plane)', () => {
  it('hashes the body with its keys sorted at every depth, arrays in order', async () => {
    const body = { b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } };
    expect(await requestHash(body)).toBe(createHash('sha256').update('{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}').digest('hex'));
  });

  it('asks for the wallet JWT on the typed-data signature', () => {
    expect(requiresWalletAuth('POST', new URL('https://api.cdp.coinbase.com/platform/v2/evm/accounts/0xabc/sign/typed-data'))).toBe(true);
  });

  it('refuses malformed keys by name, never echoing them', async () => {
    await expect(importApiKeySecret('not base64!')).rejects.toThrow(CdpKeyError);
    await expect(importApiKeySecret(b64(new Uint8Array(32)))).rejects.toThrow(/64 bytes/);
    const err = await importApiKeySecret('c2VjcmV0LXRoYXQtbXVzdC1ub3QtbGVhaw==').catch((e: Error) => e);
    expect(String(err)).not.toContain('c2VjcmV0');
    const client = createCdpClient({ ...creds, walletSecret: b64(new Uint8Array(40)) }, { fetch: fakeCdp(() => json({})).fetchFn });
    await expect(client.signTypedData(ACCOUNT.address, TYPED)).rejects.toThrow(/P-256/);
  });
});

describe('credentials', () => {
  it('needs all three secrets', () => {
    expect(cdpCredentialsOf({ CDP_API_KEY_ID: 'k', CDP_API_KEY_SECRET: 's', CDP_WALLET_SECRET: ' w ' })).toEqual({ apiKeyId: 'k', apiKeySecret: 's', walletSecret: 'w' });
    expect(cdpCredentialsOf({ CDP_API_KEY_ID: 'k', CDP_API_KEY_SECRET: 's' })).toBeNull();
    expect(cdpCredentialsOf({ CDP_API_KEY_ID: '', CDP_API_KEY_SECRET: 's', CDP_WALLET_SECRET: 'w' })).toBeNull();
  });
});

describe('signTypedData of the ceremony', () => {
  it('sends the CeremonyAttestation the policy pins, and returns a signature that recovers to the account over the typed digest', async () => {
    const cdp = fakeCdp(async (req) => {
      const body = JSON.parse(req.body!) as { domain: Record<string, unknown>; types: Record<string, unknown>; primaryType: string; message: Record<string, unknown> };
      expect(body.types.EIP712Domain).toEqual([
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ]);
      // What the ceremony-attester policy reads: the verifying contract and the primary type.
      expect(body.domain).toEqual({ name: 'Cofferdam Ceremony', version: '1', chainId: 84532, verifyingContract: REGISTRY });
      expect(body.primaryType).toBe('CeremonyAttestation');
      expect(body.message).toMatchObject({ nonce: '7', notBefore: 1_800_000_000, expiry: 1_800_000_600 });
      return json({ signature: await ACCOUNT.signTypedData(TYPED) });
    });
    const client = createCdpClient(creds, { fetch: cdp.fetchFn, now: () => NOW });
    const sig = await client.signTypedData(ACCOUNT.address, TYPED);
    expect(cdp.problems).toEqual([]);
    expect(cdp.seen).toHaveLength(1);
    expect(cdp.seen[0]!.method).toBe('POST');
    expect(cdp.seen[0]!.url).toBe(`https://api.cdp.coinbase.com/platform/v2/evm/accounts/${ACCOUNT.address}/sign/typed-data`);
    await expect(recoverTypedDataAddress({ ...TYPED, signature: sig })).resolves.toBe(ACCOUNT.address);
  });

  it('refuses a signature made by another key', async () => {
    const other = privateKeyToAccount(`0x${'22'.repeat(32)}`);
    const cdp = fakeCdp(async () => json({ signature: await other.signTypedData(TYPED) }));
    const client = createCdpClient(creds, { fetch: cdp.fetchFn });
    await expect(client.signTypedData(ACCOUNT.address, TYPED)).rejects.toThrow(/another key/);
  });

  it('refuses a malformed definition before any request', async () => {
    const cdp = fakeCdp(() => json({}));
    const client = createCdpClient(creds, { fetch: cdp.fetchFn });
    const bad = { ...TYPED, message: { ...TYPED.message, newKeyHash: '0x12' as Hex } };
    await expect(client.signTypedData(ACCOUNT.address, bad)).rejects.toThrow();
    expect(cdp.seen).toHaveLength(0);
  });

  it('refuses an answer of the wrong shape', async () => {
    const client = createCdpClient(creds, { fetch: fakeCdp(() => json({ signature: '0x1234' })).fetchFn });
    await expect(client.signTypedData(ACCOUNT.address, TYPED)).rejects.toThrow(CdpResponseError);
  });

  it("carries CDP's error type and correlation id, and keeps its message out of every log of the error", async () => {
    const quoted = REGISTRY.toLowerCase();
    const cdp = fakeCdp(() => json({ errorType: 'policy_violation', errorMessage: `rejected: verifyingContract ${quoted}`, correlationId: 'corr-1' }, 403));
    const client = createCdpClient(creds, { fetch: cdp.fetchFn });
    const err = (await client.signTypedData(ACCOUNT.address, TYPED).catch((e: unknown) => e)) as CdpApiError;
    expect(err).toBeInstanceOf(CdpApiError);
    expect([err.status, err.errorType, err.correlationId, err.retryable]).toEqual([403, 'policy_violation', 'corr-1', false]);
    expect(err.errorMessage).toContain(quoted);
    for (const logged of [err.message, JSON.stringify(err), inspect(err), String(err)]) expect(logged.toLowerCase()).not.toContain(quoted);
  });

  it('maps a rate limit, an answer without an error body and no answer as retryable', async () => {
    const sign = (fetchFn: typeof fetch) =>
      createCdpClient(creds, { fetch: fetchFn })
        .signTypedData(ACCOUNT.address, TYPED)
        .then(
          () => {
            throw new Error('the signature should have failed');
          },
          (e: unknown) => e as CdpApiError,
        );
    const limited = await sign(fakeCdp(() => json({ errorType: 'rate_limit_exceeded', errorMessage: 'slow down' }, 429)).fetchFn);
    expect([limited.errorType, limited.retryable]).toEqual(['rate_limit_exceeded', true]);
    const down = await sign(fakeCdp(() => new Response('upstream', { status: 503 })).fetchFn);
    expect([down.errorType, down.retryable]).toEqual(['service_unavailable', true]);
    const gone = await sign((async () => {
      throw new TypeError('fetch failed');
    }) as typeof fetch);
    expect([gone.status, gone.errorType, gone.retryable]).toEqual([0, 'network_error', true]);
  });

  it('never puts a secret in a request beyond its signed tokens', async () => {
    const cdp = fakeCdp(async () => json({ signature: await ACCOUNT.signTypedData(TYPED) }));
    await createCdpClient(creds, { fetch: cdp.fetchFn }).signTypedData(ACCOUNT.address, TYPED);
    const wire = JSON.stringify(cdp.seen);
    for (const secret of [creds.apiKeySecret, creds.walletSecret]) expect(wire).not.toContain(secret);
  });
});
