// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { recoverMessageAddress, type Hex } from 'viem';

import { REBIND_TAG, attesterMessageHash, rebindMessageHash, signRebindAttestation } from '../src/sign.js';

// Known-answer vector produced 2026-10-14 by `NullifierRegistry.rebindMessageHash`
// and `attesterMessageHash` on an in-memory Hardhat chain (chain id 31337).
const REGISTRY: Hex = '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0';
const ACCOUNT: Hex = '0xfa4D920d5592289A1A0F73CA49D626EF8FE4D695';
const USER_IDENTIFIER = 485990643273764334479787657733009101342132995857n;
const REBIND_HASH: Hex = '0x7eeeeea0c4028c83f3aca7695601351bbf1441fb040b07df2cc3c83dbe75c5ef';
const BIND_HASH: Hex = '0x761745b9038d3e80dc9d7e7154eebd6833b2773d774d68da2161c8e082041c6b';
const TEST_KEY: Hex = `0x${'11'.repeat(32)}`;
const TEST_SIGNER: Hex = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';

function vectorPubSignals(): bigint[] {
  const s = Array.from({ length: 21 }, (_, i) => BigInt(i));
  s[20] = USER_IDENTIFIER;
  return s;
}
const inputs = { chainId: 31337n, registry: REGISTRY, account: ACCOUNT, pubSignals: vectorPubSignals() };

describe('rebindMessageHash', () => {
  it('matches the pinned on-chain vector and differs from the bind hash of the same inputs', () => {
    expect(REBIND_TAG).toMatch(/^0x[0-9a-f]{64}$/);
    expect(rebindMessageHash({ ...inputs, epoch: 3n })).toBe(REBIND_HASH);
    expect(attesterMessageHash(inputs)).toBe(BIND_HASH);
  });

  it('changes with the epoch, the account and the chain', () => {
    expect(rebindMessageHash({ ...inputs, epoch: 4n })).not.toBe(REBIND_HASH);
    expect(rebindMessageHash({ ...inputs, epoch: 3n, account: REGISTRY })).not.toBe(REBIND_HASH);
    expect(rebindMessageHash({ ...inputs, epoch: 3n, chainId: 84532n })).not.toBe(REBIND_HASH);
  });
});

describe('signRebindAttestation', () => {
  it('signs with EIP-191 so verifyAttesterSig recovers the key', async () => {
    const signed = await signRebindAttestation(TEST_KEY, { ...inputs, epoch: 3n });
    expect(signed.attesterAddress).toBe(TEST_SIGNER);
    expect(signed.messageHash).toBe(REBIND_HASH);
    expect(await recoverMessageAddress({ message: { raw: REBIND_HASH }, signature: signed.signature })).toBe(TEST_SIGNER);
  });
});
