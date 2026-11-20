// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * The audit lines never carry the nullifier next to the account (the identity
 * log policy, workspace decision 0080): `attester.signBind`,
 * `attester.signRebind` and `attester.celoGateRejected` name the account, so a
 * nullifier beside it would join a passport to an account in logs kept off the
 * chain. The Celo gate is a fake; the key is a test key.
 */

import { concat, encodePacked, pad, type Hex } from 'viem';
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';

import type { SignBindRequest } from '../src/rpc.js';

const gate = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock('cloudflare:workers', () => ({
  WorkerEntrypoint: class {
    constructor(
      readonly ctx: unknown,
      readonly env: unknown,
    ) {}
  },
}));
vi.mock('../src/celoGate.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/celoGate.js')>()),
  createCeloReads: () => ({}),
  verifyProofOnCelo: gate.verify,
}));

const { default: CofferdamAttester } = await import('../src/index.js');
const { CeloGateError, PASSPORT_DISCLOSE_INDEX } = await import('../src/celoGate.js');
const { calculateUserIdentifierHash } = await import('../src/sign.js');

const REGISTRY: Hex = '0x2843F55C9E1491a6d47F65f041E68F96E3aeB3d4';
const ACCOUNT: Hex = '0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695';
/** A distinctive nullifier, so a leak is found anywhere in a line. */
const NULLIFIER = 918273645091827364509182736450918273645n;

const env = {
  ENVIRONMENT: 'staging',
  BASE_CHAIN_ID: '84532',
  NULLIFIER_REGISTRY_ADDRESS: REGISTRY,
  CELO_RPC_URL: 'https://forno.example',
  SELF_CELO_CHAIN_ID: '42220',
  SELF_HUB_ADDRESS: '0xe57F4773bd9c9d8b6Cd70431117d353298B9f5BF',
  SELF_PASSPORT_REGISTRY_ADDRESS: '0x37F5CB8cB1f6B00aa768D8aA99F1A9289802A968',
  ATTESTER_PRIVATE_KEY: `0x${'11'.repeat(32)}`,
};

function request(): SignBindRequest {
  const ctx = concat([encodePacked(['uint256'], [42220n]), pad(ACCOUNT, { size: 32 })]);
  const pubSignals = new Array<bigint>(21).fill(0n);
  pubSignals[PASSPORT_DISCLOSE_INDEX.NULLIFIER] = NULLIFIER;
  pubSignals[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID] = 1n;
  pubSignals[PASSPORT_DISCLOSE_INDEX.USER_IDENTIFIER] = calculateUserIdentifierHash(ctx);
  return { registry: REGISTRY, account: ACCOUNT, pubSignals: pubSignals.map((x) => x.toString()), userContextData: ctx };
}

let log: MockInstance<typeof console.log>;
const lines = () => log.mock.calls.map(([line]) => String(line));

beforeEach(() => {
  log = vi.spyOn(console, 'log').mockImplementation(() => {});
  gate.verify.mockResolvedValue({ chainId: 42220n, registry: env.SELF_PASSPORT_REGISTRY_ADDRESS, merkleRoot: 7n, proofDate: '2026-11-13' });
});
afterEach(() => {
  log.mockRestore();
  vi.resetAllMocks();
});

function expectNoNullifier(): void {
  expect(lines().length).toBeGreaterThan(0);
  for (const line of lines()) {
    expect(line).not.toContain(NULLIFIER.toString());
    expect(Object.keys(JSON.parse(line) as object)).not.toContain('nullifier');
    expect(JSON.parse(line)).toMatchObject({ account: ACCOUNT });
  }
}

describe('the audit lines', () => {
  const attester = () => new CofferdamAttester({} as never, env as never);

  it('signBind names the account and the message hash, never the nullifier', async () => {
    const signed = await attester().signBind(request());
    expectNoNullifier();
    expect(JSON.parse(lines()[0]!)).toMatchObject({ kind: 'attester.signBind', messageHash: signed.messageHash });
  });

  it('signRebind never logs the nullifier', async () => {
    await attester().signRebind({ ...request(), epoch: '2' });
    expectNoNullifier();
    expect(JSON.parse(lines()[0]!)).toMatchObject({ kind: 'attester.signRebind', epoch: '2' });
  });

  it('a Celo gate refusal never logs the nullifier', async () => {
    gate.verify.mockRejectedValue(new CeloGateError('CELO_ROOT_UNKNOWN', 'root not on Celo', false));
    await expect(attester().signBind(request())).rejects.toThrow(/CELO_ROOT_UNKNOWN/);
    expectNoNullifier();
    expect(JSON.parse(lines()[0]!)).toMatchObject({ kind: 'attester.celoGateRejected', code: 'CELO_ROOT_UNKNOWN' });
  });
});
