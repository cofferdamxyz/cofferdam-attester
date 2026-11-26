// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { hashTypedData, recoverAddress, recoverMessageAddress, recoverTypedDataAddress, type Hex } from 'viem';

import { AttesterError } from '../src/bind.js';
import {
  CEREMONY_ACTIONS,
  CEREMONY_DOMAIN_NAME,
  CEREMONY_DOMAIN_VERSION,
  CEREMONY_TAG,
  CEREMONY_TYPES,
  ceremonyHash,
  ceremonyTypedData,
  ceremonyTypedHash,
  prepareCeremonyRequest,
  signCeremonyAttestation,
} from '../src/ceremony.js';
import type { SignCeremonyRequest } from '../src/rpc.js';
// cofferdam-sdk packages/core/test/fixtures/ceremonyTypes.json (decision 0090
// item 5), copied byte for byte: the SDK builds it, the contract pins it.
import FIXTURE from './fixtures/ceremonyTypes.json';

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
const REGISTRY: Hex = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const PINS = { chainIdStr: '31337', signatureStr: 'eip191', registryStr: REGISTRY };
const PINS_712 = { ...PINS, signatureStr: 'eip712' };

function validRequest(overrides: Partial<SignCeremonyRequest> = {}): SignCeremonyRequest {
  return {
    chainId: '31337',
    registry: REGISTRY,
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

  it('takes the form from the pins, never the request', () => {
    expect(prepareCeremonyRequest(PINS, validRequest(), NOW).form).toBe('eip191');
    const p = prepareCeremonyRequest(PINS_712, { ...validRequest(), signatureForm: 'eip191' } as SignCeremonyRequest, NOW);
    expect(p.form).toBe('eip712');
    expect(p.registry).toBe(REGISTRY);
  });

  it('pins the registry the request names', () => {
    for (const pins of [PINS, PINS_712]) {
      expect(codeOf(() => prepareCeremonyRequest(pins, validRequest({ registry: KAT.account }), NOW))).toBe(
        'REGISTRY_NOT_ALLOWED',
      );
      expect(codeOf(() => prepareCeremonyRequest(pins, validRequest({ registry: undefined as never }), NOW))).toBe(
        'REGISTRY_NOT_ALLOWED',
      );
    }
    // Case does not matter; the address does.
    expect(prepareCeremonyRequest(PINS_712, validRequest({ registry: REGISTRY.toLowerCase() as Hex }), NOW).registry).toBe(
      REGISTRY,
    );
  });

  it('refuses every request while a pin is malformed', () => {
    for (const signatureStr of ['', 'EIP712', 'eip-712', 'both']) {
      expect(codeOf(() => prepareCeremonyRequest({ ...PINS, signatureStr }, validRequest(), NOW))).toBe(
        'BAD_CEREMONY_SIGNATURE_VAR',
      );
    }
    for (const registryStr of ['', '0x12', REGISTRY.toLowerCase()]) {
      expect(codeOf(() => prepareCeremonyRequest({ ...PINS_712, registryStr }, validRequest(), NOW))).toBe(
        'BAD_CEREMONY_REGISTRY_VAR',
      );
    }
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

describe('the typed ceremony (decision 0090 item 5)', () => {
  it('agrees with the SDK fixture: domain, types, digests and signatures', async () => {
    expect(CEREMONY_DOMAIN_NAME).toBe(FIXTURE.domain.name);
    expect(CEREMONY_DOMAIN_VERSION).toBe(FIXTURE.domain.version);
    expect(CEREMONY_TYPES.CeremonyAttestation).toEqual(FIXTURE.fields);
    expect(CEREMONY_ACTIONS['enroll-first-high']).toBe(FIXTURE.actions['enroll-first-high']);
    expect(CEREMONY_ACTIONS['replace-partner']).toBe(FIXTURE.actions['replace-partner']);
    for (const v of FIXTURE.vectors) {
      const inputs = {
        chainId: BigInt(v.domain.chainId),
        account: v.message.account as Hex,
        action: v.message.action as Hex,
        newKeyHash: v.message.newKeyHash as Hex,
        partnerId: v.message.partnerId as Hex,
        nonce: BigInt(v.message.nonce),
        notBefore: BigInt(v.message.notBefore),
        expiry: BigInt(v.message.expiry),
      };
      const registry = v.domain.verifyingContract as Hex;
      expect(ceremonyTypedHash(inputs, registry)).toBe(v.digest);
      const signed = await signCeremonyAttestation(FIXTURE.attester.privateKey as Hex, { ...inputs, form: 'eip712', registry });
      expect(signed.messageHash).toBe(v.digest);
      // RFC 6979: the same key and digest give the SDK's signature.
      expect(signed.signature).toBe(v.signature);
      expect(signed.attesterAddress).toBe(FIXTURE.attester.address);
    }
  });

  it('signs typed data that recovers over the digest with no prefix', async () => {
    const signed = await signCeremonyAttestation(TEST_KEY, { ...KAT, form: 'eip712', registry: REGISTRY });
    const typed = ceremonyTypedData(KAT, REGISTRY);
    expect(typed.domain).toEqual({ name: 'Cofferdam Ceremony', version: '1', chainId: 31337n, verifyingContract: REGISTRY });
    expect(signed.messageHash).toBe(hashTypedData(typed));
    expect(signed.messageHash).not.toBe(KAT_HASH);
    expect(await recoverTypedDataAddress({ ...typed, signature: signed.signature })).toBe(TEST_SIGNER);
    expect(await recoverAddress({ hash: signed.messageHash, signature: signed.signature })).toBe(TEST_SIGNER);
    // Not personal_sign: the EIP-191 reading of it is another address.
    expect(await recoverMessageAddress({ message: { raw: signed.messageHash }, signature: signed.signature })).not.toBe(
      TEST_SIGNER,
    );
  });

  it('binds the account and the registry', () => {
    const h = ceremonyTypedHash(KAT, REGISTRY);
    expect(ceremonyTypedHash({ ...KAT, account: TEST_SIGNER }, REGISTRY)).not.toBe(h);
    expect(ceremonyTypedHash(KAT, KAT.account)).not.toBe(h);
    expect(ceremonyTypedHash({ ...KAT, chainId: 8453n }, REGISTRY)).not.toBe(h);
  });
});

describe('signCeremonyAttestation', () => {
  it('signs the hash with EIP-191 so verifyAttesterSig recovers the key', async () => {
    const signed = await signCeremonyAttestation(TEST_KEY, { ...KAT, form: 'eip191', registry: REGISTRY });
    expect(signed.attesterAddress).toBe(TEST_SIGNER);
    expect(signed.messageHash).toBe(KAT_HASH);
    expect(signed.signature).toMatch(/^0x[0-9a-f]{130}$/);
    expect(await recoverMessageAddress({ message: { raw: KAT_HASH }, signature: signed.signature })).toBe(TEST_SIGNER);
  });
});
