// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { recoverMessageAddress, type Hex } from 'viem';

import { AttesterError } from '../src/bind.js';
import {
  CEREMONY_ACTIONS,
  CEREMONY_TAG,
  ceremonyHash,
  prepareCeremonyRequest,
  signCeremonyAttestation,
} from '../src/ceremony.js';
import type { SignCeremonyRequest } from '../src/rpc.js';

// Known-answer vector produced 2026-10-14 by `CofferdamAccount4337.ceremonyHash`
// on an in-memory Hardhat chain (chain id 31337, account deployed through the
// decision 0016 constructor). If this moves, the on-chain preimage changed.
const KAT = {
  chainId: 31337n,
  account: '0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9' as Hex,
  action: CEREMONY_ACTIONS['enroll-first-high'],
  newKeyHash: `0x${'11'.repeat(32)}` as Hex,
  partnerId: `0x${'22'.repeat(32)}` as Hex,
  nonce: 7n,
  notBefore: 1_700_000_000n,
  expiry: 1_700_000_600n,
};
const KAT_HASH: Hex = '0xf54c34987d65c680e82cafe965795f4f1c51a06a58d7306ba6366c37c059ec0c';
const TEST_KEY: Hex = `0x${'11'.repeat(32)}`;
const TEST_SIGNER: Hex = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';

const NOW = 1_700_000_300n;
const PINS = { chainIdStr: '31337' };

function validRequest(overrides: Partial<SignCeremonyRequest> = {}): SignCeremonyRequest {
  return {
    chainId: '31337',
    account: KAT.account,
    action: 'enroll-first-high',
    newKeyHash: KAT.newKeyHash,
    partnerId: KAT.partnerId,
    nonce: '7',
    notBefore: '1700000000',
    expiry: '1700000600',
    ...overrides,
  };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(AttesterError);
    return (err as AttesterError).code;
  }
  throw new Error('expected a throw');
}

describe('ceremonyHash', () => {
  it('uses the contract domain tag and action hashes', () => {
    expect(CEREMONY_TAG).toMatch(/^0x[0-9a-f]{64}$/);
    expect(CEREMONY_ACTIONS['enroll-first-high']).toBe(
      '0x576812806b2b1bd14ce155ba9d5337803c10ece5f435ca8686a823e35f1e2ed8',
    );
  });

  it('matches the pinned on-chain vector', () => {
    expect(ceremonyHash(KAT)).toBe(KAT_HASH);
  });

  it('changes with every input', () => {
    expect(ceremonyHash({ ...KAT, chainId: 84532n })).not.toBe(KAT_HASH);
    expect(ceremonyHash({ ...KAT, action: CEREMONY_ACTIONS['replace-partner'] })).not.toBe(KAT_HASH);
    expect(ceremonyHash({ ...KAT, nonce: 8n })).not.toBe(KAT_HASH);
    expect(ceremonyHash({ ...KAT, expiry: KAT.expiry + 1n })).not.toBe(KAT_HASH);
    expect(ceremonyHash({ ...KAT, partnerId: `0x${'00'.repeat(32)}` })).not.toBe(KAT_HASH);
  });
});

describe('prepareCeremonyRequest', () => {
  it('accepts a well-formed request inside the window', () => {
    const p = prepareCeremonyRequest(PINS, validRequest(), NOW);
    expect(p.chainId).toBe(31337n);
    expect(p.account).toBe(KAT.account);
    expect(p.action).toBe(KAT.action);
    expect(p.actionName).toBe('enroll-first-high');
    expect(p.nonce).toBe(7n);
    expect(ceremonyHash(p)).toBe(KAT_HASH);
  });

  it('pins the chain id', () => {
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ chainId: '84532' }), NOW))).toBe('WRONG_CHAIN_ID');
  });

  it('rejects malformed fields', () => {
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ account: '0x12' as Hex }), NOW))).toBe('BAD_ACCOUNT');
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ action: 'mint' as never }), NOW))).toBe(
      'BAD_CEREMONY_ACTION',
    );
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ newKeyHash: '0x11' as Hex }), NOW))).toBe(
      'BAD_CEREMONY_FIELD',
    );
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ nonce: '-1' }), NOW))).toBe('BAD_CEREMONY_FIELD');
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ expiry: '281474976710656' }), NOW))).toBe(
      'BAD_CEREMONY_FIELD',
    );
  });

  it('bounds the validity window', () => {
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ expiry: '1700000000' }), NOW))).toBe(
      'BAD_CEREMONY_WINDOW',
    );
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest({ expiry: '1700003601' }), NOW))).toBe(
      'BAD_CEREMONY_WINDOW',
    );
    expect(codeOf(() => prepareCeremonyRequest(PINS, validRequest(), NOW + 1_000n))).toBe('BAD_CEREMONY_WINDOW');
  });
});

describe('signCeremonyAttestation', () => {
  it('signs the hash with EIP-191 so verifyAttesterSig recovers the key', async () => {
    const signed = await signCeremonyAttestation(TEST_KEY, KAT);
    expect(signed.attesterAddress).toBe(TEST_SIGNER);
    expect(signed.messageHash).toBe(KAT_HASH);
    expect(signed.signature).toMatch(/^0x[0-9a-f]{130}$/);
    expect(await recoverMessageAddress({ message: { raw: KAT_HASH }, signature: signed.signature })).toBe(TEST_SIGNER);
  });
});
