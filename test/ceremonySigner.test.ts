// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * The ceremony signer behind its switch (workspace decision 0090,
 * cdp-setup.md E7): which signer `CEREMONY_SIGNER` picks, that nothing falls
 * back to the raw key, that `cdp` signs only the EIP-712 form, that a CDP
 * failure is logged and thrown by CDP's status, type and correlation id only,
 * and `signCeremony` end to end on a fake CDP account. No real key.
 */

import { recoverAddress, recoverTypedDataAddress, type Address, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';

import type * as CdpClientModule from '../src/cdp/client.js';
import type { SignCeremonyRequest } from '../src/rpc.js';

const cdp = vi.hoisted(() => ({ fake: null as unknown, created: 0 }));
vi.mock('cloudflare:workers', () => ({
  WorkerEntrypoint: class {
    constructor(
      readonly ctx: unknown,
      readonly env: unknown,
    ) {}
  },
}));
vi.mock('../src/cdp/client.js', async (importOriginal) => ({
  ...(await importOriginal<typeof CdpClientModule>()),
  createCdpClient: () => {
    cdp.created++;
    return cdp.fake;
  },
}));

const { default: CofferdamAttester } = await import('../src/index.js');
const { AttesterError } = await import('../src/bind.js');
const { CdpKeyError } = await import('../src/cdp/auth.js');
const { CdpApiError, CdpResponseError } = await import('../src/cdp/client.js');
const { ceremonyTypedData, ceremonyTypedHash, prepareCeremonyRequest } = await import('../src/ceremony.js');
const { ceremonySigner, ceremonySignerSpecOf } = await import('../src/ceremonySigner.js');

type CdpClient = CdpClientModule.CdpClient;

const CDP_ACCOUNT = privateKeyToAccount(generatePrivateKey());
const RAW_KEY = generatePrivateKey();
const RAW_ACCOUNT = privateKeyToAccount(RAW_KEY);
const REGISTRY: Hex = '0x44A2B59d5D39f773C2e65469e0Dd3217E53823Af';
const ACCOUNT: Hex = '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9';
// Shaped as CDP's (base64 of 64 bytes; base64), never real.
const CREDS = {
  CDP_API_KEY_ID: 'organizations/test/apiKeys/attester',
  CDP_API_KEY_SECRET: Buffer.alloc(64, 7).toString('base64'),
  CDP_WALLET_SECRET: Buffer.from('wallet-secret-value').toString('base64'),
};
const CDP_ENV = { CEREMONY_SIGNER: 'cdp', CEREMONY_CDP_ADDRESS: CDP_ACCOUNT.address, ...CREDS };

/** A fake CDP account: signs typed data with its key, or answers each call from `answers` in turn. */
function fakeCdp(answers: Array<'sign' | Error | Hex> = ['sign']) {
  const calls: Array<{ address: Address; typedData: unknown }> = [];
  const client: CdpClient = {
    signTypedData: (address, typedData) => {
      calls.push({ address, typedData });
      const next = answers[Math.min(calls.length, answers.length) - 1]!;
      if (next instanceof Error) return Promise.reject(next);
      if (next === 'sign') return CDP_ACCOUNT.signTypedData(typedData as never);
      return Promise.resolve(next);
    },
  };
  return { client, calls };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(AttesterError);
    return (err as InstanceType<typeof AttesterError>).code;
  }
  throw new Error('expected a throw');
}

const now = () => BigInt(Math.floor(Date.now() / 1000));
function request(overrides: Partial<SignCeremonyRequest> = {}): SignCeremonyRequest {
  return {
    chainId: '84532',
    registry: REGISTRY,
    account: ACCOUNT,
    action: 'enroll-first-high',
    newKeyHash: `0x${'11'.repeat(32)}`,
    partnerId: `0x${'22'.repeat(32)}`,
    nonce: '7',
    notBefore: (now() - 60n).toString(),
    expiry: (now() + 600n).toString(),
    ...overrides,
  };
}
const PINS_712 = { chainIdStr: '84532', signatureStr: 'eip712', registryStr: REGISTRY };
const PINS_191 = { ...PINS_712, signatureStr: 'eip191' };

let log: MockInstance<typeof console.log>;
const lines = () => log.mock.calls.map(([line]) => String(line));
beforeEach(() => {
  log = vi.spyOn(console, 'log').mockImplementation(() => {});
  cdp.fake = null;
  cdp.created = 0;
});
afterEach(() => {
  log.mockRestore();
});

describe('ceremonySignerSpecOf: which signer the switch names', () => {
  it('defaults to the raw key, and refuses a missing or malformed one', () => {
    expect(ceremonySignerSpecOf({ CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY }, 'eip191')).toEqual({ kind: 'key', privateKey: RAW_KEY });
    expect(ceremonySignerSpecOf({ CEREMONY_SIGNER: ' KEY ', CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY }, 'eip712').kind).toBe('key');
    expect(ceremonySignerSpecOf({ CEREMONY_SIGNER: '', CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY }, 'eip712').kind).toBe('key');
    expect(codeOf(() => ceremonySignerSpecOf({}, 'eip191'))).toBe('BAD_ATTESTER_KEY');
    expect(codeOf(() => ceremonySignerSpecOf({ CEREMONY_ATTESTER_PRIVATE_KEY: '0x1234' }, 'eip191'))).toBe('BAD_ATTESTER_KEY');
  });

  it('under cdp names the account and the credentials', () => {
    expect(ceremonySignerSpecOf(CDP_ENV, 'eip712')).toEqual({
      kind: 'cdp',
      address: CDP_ACCOUNT.address,
      credentials: { apiKeyId: CREDS.CDP_API_KEY_ID, apiKeySecret: CREDS.CDP_API_KEY_SECRET, walletSecret: CREDS.CDP_WALLET_SECRET },
    });
    expect(ceremonySignerSpecOf({ ...CDP_ENV, CEREMONY_SIGNER: 'CDP' }, 'eip712').kind).toBe('cdp');
  });

  it('under cdp without a piece is not configured, and never falls back to a raw key that is set', () => {
    const withKey = { ...CDP_ENV, CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY };
    expect(ceremonySignerSpecOf(withKey, 'eip712').kind).toBe('cdp');
    for (const broken of [
      { CEREMONY_CDP_ADDRESS: undefined },
      { CEREMONY_CDP_ADDRESS: '0xnot' },
      // Not EIP-55: the attester's address vars are checksummed.
      { CEREMONY_CDP_ADDRESS: CDP_ACCOUNT.address.toLowerCase() },
      { CDP_API_KEY_ID: '' },
      { CDP_API_KEY_SECRET: undefined },
      { CDP_WALLET_SECRET: ' ' },
      // A malformed secret is caught before any request: 32 bytes, not base64.
      { CDP_API_KEY_SECRET: Buffer.alloc(32, 7).toString('base64') },
      { CDP_WALLET_SECRET: 'not base64!' },
    ]) {
      expect(codeOf(() => ceremonySignerSpecOf({ ...withKey, ...broken }, 'eip712'))).toBe('BAD_ATTESTER_KEY');
    }
  });

  it('refuses an unknown switch instead of guessing', () => {
    let err: unknown;
    try {
      ceremonySignerSpecOf({ CEREMONY_SIGNER: 'cpd', CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY }, 'eip712');
    } catch (e) {
      err = e;
    }
    expect((err as Error).message).toBe('BAD_ATTESTER_KEY: CEREMONY_SIGNER must be "key" or "cdp"');
  });

  it('under cdp signs only the EIP-712 form: EIP-191 is a hash signature the project policy refuses', () => {
    expect(codeOf(() => ceremonySignerSpecOf(CDP_ENV, 'eip191'))).toBe('BAD_CEREMONY_SIGNATURE_VAR');
  });

  it('names what is missing by name, never by value', () => {
    let err: unknown;
    try {
      ceremonySignerSpecOf({ ...CDP_ENV, CEREMONY_CDP_ADDRESS: undefined }, 'eip712');
    } catch (e) {
      err = e;
    }
    const message = (err as Error).message;
    expect(message).toContain('CEREMONY_CDP_ADDRESS');
    for (const value of Object.values(CREDS)) expect(message).not.toContain(value);
  });
});

describe('ceremonySigner under cdp', () => {
  const spec = { kind: 'cdp' as const, address: CDP_ACCOUNT.address, credentials: { apiKeyId: 'id', apiKeySecret: 's', walletSecret: 'w' } };
  const prepared = () => prepareCeremonyRequest(PINS_712, request());

  it('signs the typed CeremonyAttestation through the account; the signature recovers to it over the typed digest', async () => {
    const { client, calls } = fakeCdp();
    const p = prepared();
    const signed = await ceremonySigner(spec, { environment: 'staging', cdp: client }).sign(p);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.address).toBe(CDP_ACCOUNT.address);
    expect(calls[0]!.typedData).toEqual(ceremonyTypedData(p, REGISTRY));
    expect(signed.attesterAddress).toBe(CDP_ACCOUNT.address);
    expect(signed.messageHash).toBe(ceremonyTypedHash(p, REGISTRY));
    await expect(recoverAddress({ hash: signed.messageHash, signature: signed.signature })).resolves.toBe(CDP_ACCOUNT.address);
    await expect(recoverTypedDataAddress({ ...ceremonyTypedData(p, REGISTRY), signature: signed.signature })).resolves.toBe(CDP_ACCOUNT.address);
  });

  it('refuses an EIP-191 ceremony before CDP sees anything', async () => {
    const { client, calls } = fakeCdp();
    const p = prepareCeremonyRequest(PINS_191, request());
    await expect(ceremonySigner(spec, { environment: 'staging', cdp: client }).sign(p)).rejects.toThrow(/^BAD_CEREMONY_SIGNATURE_VAR/);
    expect(calls).toHaveLength(0);
  });

  it.each([
    [new CdpApiError(403, 'policy_violation', 'c-1', `rejected: verifyingContract ${REGISTRY}`), 'CDP_REFUSED', false],
    [new CdpApiError(401, 'unauthorized', 'c-2', 'revoked key'), 'CDP_REFUSED', false],
    [new CdpApiError(503, 'service_unavailable', 'c-3', 'upstream'), 'CDP_UNAVAILABLE', true],
    [new CdpApiError(429, 'rate_limit_exceeded', undefined, 'slow down'), 'CDP_UNAVAILABLE', true],
    [new CdpApiError(0, 'timeout', undefined, ''), 'CDP_UNAVAILABLE', true],
  ])("maps CDP's %s by status and type, logging never CDP's message", async (cdpErr, code, retryable) => {
    const { client } = fakeCdp([cdpErr]);
    const err = (await ceremonySigner(spec, { environment: 'staging', cdp: client })
      .sign(prepared())
      .catch((e: unknown) => e)) as InstanceType<typeof AttesterError>;
    expect(err).toBeInstanceOf(AttesterError);
    expect([err.code, err.retryable]).toEqual([code, retryable]);
    expect(err.message).toBe(`${code}: ${cdpErr.message}`);
    expect(lines()).toHaveLength(1);
    const line = JSON.parse(lines()[0]!) as Record<string, unknown>;
    expect(line).toMatchObject({ kind: 'attester.signCeremonyFailed', signer: 'cdp', code, retryable, status: cdpErr.status, errorType: cdpErr.errorType, account: ACCOUNT });
    expect(line.correlationId).toBe(cdpErr.correlationId);
    if (cdpErr.errorMessage) {
      expect(lines()[0]).not.toContain(cdpErr.errorMessage);
      expect(err.message).not.toContain(cdpErr.errorMessage);
    }
  });

  it('refuses a signature that is not the account\'s, and a secret that will not import', async () => {
    const other = fakeCdp([new CdpResponseError('CDP signed with another key than the account named')]);
    await expect(ceremonySigner(spec, { environment: 'staging', cdp: other.client }).sign(prepared())).rejects.toThrow(/^CDP_BAD_SIGNATURE: /);
    const badKey = fakeCdp([new CdpKeyError('the CDP Wallet Secret is not a P-256 PKCS#8 key')]);
    await expect(ceremonySigner(spec, { environment: 'staging', cdp: badKey.client }).sign(prepared())).rejects.toThrow(/^BAD_ATTESTER_KEY: /);
  });

  it('names any other failure by its error name only', async () => {
    const { client } = fakeCdp([new RangeError(`something about ${ACCOUNT} and secrets`)]);
    const err = (await ceremonySigner(spec, { environment: 'staging', cdp: client })
      .sign(prepared())
      .catch((e: unknown) => e)) as Error;
    expect(err.message).toBe('CDP_SIGN_FAILED: cdp RangeError');
    expect(lines()[0]).not.toContain('secrets');
  });
});

describe('signCeremony on the Worker', () => {
  const base = {
    ENVIRONMENT: 'staging',
    BASE_CHAIN_ID: '84532',
    CEREMONY_REGISTRY_ADDRESS: REGISTRY,
  };
  const attester = (env: Record<string, unknown>) => new CofferdamAttester({} as never, env as never);

  it('under cdp signs through the account, answers its address and logs the signer', async () => {
    const { client, calls } = fakeCdp();
    cdp.fake = client;
    const env = { ...base, CEREMONY_SIGNATURE: 'eip712', ...CDP_ENV, CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY };
    const res = await attester(env).signCeremony(request());
    expect(calls).toHaveLength(1);
    expect(res.attesterAddress).toBe(CDP_ACCOUNT.address);
    expect(res.signatureForm).toBe('eip712');
    await expect(recoverAddress({ hash: res.messageHash, signature: res.signature })).resolves.toBe(CDP_ACCOUNT.address);
    const line = JSON.parse(lines()[0]!) as Record<string, unknown>;
    expect(line).toMatchObject({ kind: 'attester.signCeremony', signer: 'cdp', attesterAddress: CDP_ACCOUNT.address, messageHash: res.messageHash });
    for (const value of [...Object.values(CREDS), RAW_KEY, res.signature]) expect(lines().join('\n')).not.toContain(value);
  });

  it('under key keeps signing with the raw key in either form, and builds no CDP client', async () => {
    for (const form of ['eip191', 'eip712'] as const) {
      const env = { ...base, CEREMONY_SIGNATURE: form, CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY, ...CREDS };
      const res = await attester(env).signCeremony(request());
      expect(res.attesterAddress).toBe(RAW_ACCOUNT.address);
      expect(res.signatureForm).toBe(form);
    }
    expect(cdp.created).toBe(0);
    expect(JSON.parse(lines()[0]!)).toMatchObject({ signer: 'key', signatureForm: 'eip191' });
    expect(JSON.parse(lines()[1]!)).toMatchObject({ signer: 'key', signatureForm: 'eip712' });
  });

  it('under cdp with eip191 refuses before any request, even with a raw key set', async () => {
    const { client, calls } = fakeCdp();
    cdp.fake = client;
    const env = { ...base, CEREMONY_SIGNATURE: 'eip191', ...CDP_ENV, CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY };
    await expect(attester(env).signCeremony(request())).rejects.toThrow(/^BAD_CEREMONY_SIGNATURE_VAR/);
    expect(calls).toHaveLength(0);
    expect(cdp.created).toBe(0);
  });

  it('under cdp without its secrets is not configured, and builds no CDP client', async () => {
    const env = { ...base, CEREMONY_SIGNATURE: 'eip712', ...CDP_ENV, CDP_WALLET_SECRET: undefined, CEREMONY_ATTESTER_PRIVATE_KEY: RAW_KEY };
    await expect(attester(env).signCeremony(request())).rejects.toThrow(/^BAD_ATTESTER_KEY/);
    expect(cdp.created).toBe(0);
    expect(lines()).toHaveLength(0);
  });

  it('still refuses a malformed request before the signer is read', async () => {
    const env = { ...base, CEREMONY_SIGNATURE: 'eip712', CEREMONY_SIGNER: 'cdp' };
    await expect(attester(env).signCeremony(request({ chainId: '8453' }))).rejects.toThrow(/^WRONG_CHAIN_ID/);
  });
});
