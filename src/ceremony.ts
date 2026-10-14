// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Ceremony co-sign (decision 0016): the Cofferdam attestation that
 * `CofferdamAccount4337.enrollFirstHigh` (the first High passkey on a Partner
 * or Managed account) and `replacePartnerAuthority` (the pre-High Partner
 * re-key) consume through `CofferdamCeremonyAttesterRegistry.verifyAttesterSig`.
 *
 * This module is pure: it reproduces `CofferdamAccount4337.ceremonyHash`
 * byte-for-byte and signs it with EIP-191 personal_sign, exactly like
 * `sign.ts` does for the Self bind. The gate (is this request coming from a
 * ceremony on a Cofferdam surface, for a Cofferdam account that has no High
 * yet, with a new key that proved itself over the account's own challenge?)
 * lives in `cofferdam-api`, which has the Base reads; this Worker only pins
 * the chain, bounds the validity window and signs. A ceremony key never
 * shares a list with the Self bind key, so it is a separate secret
 * (`CEREMONY_ATTESTER_PRIVATE_KEY`).
 *
 * On-chain preimage (`CofferdamAccount4337.ceremonyHash`):
 *
 *     keccak256(abi.encode(
 *         keccak256("cofferdam-ceremony-v1"),   // bytes32 CEREMONY_TAG
 *         block.chainid,                        // uint256
 *         address(this),                        // address (the account)
 *         action,                               // bytes32
 *         newKeyHash,                           // bytes32 keccak256(newConfig)
 *         partnerId,                            // bytes32 (0 for Managed)
 *         nonce,                                // uint256 ceremonyNonce
 *         notBefore,                            // uint48
 *         expiry                                // uint48
 *     ))
 */

import { encodeAbiParameters, getAddress, isAddress, isHex, keccak256, size, toBytes, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AttesterError, badRequest } from './bind.js';
import type { CeremonyAction, SignCeremonyRequest } from './rpc.js';

/** `keccak256("cofferdam-ceremony-v1")`, the domain tag of every ceremony hash. */
export const CEREMONY_TAG: Hex = keccak256(toBytes('cofferdam-ceremony-v1'));

/** `CofferdamAccount4337.ACTION_*`, keyed by the wire name. */
export const CEREMONY_ACTIONS: Record<CeremonyAction, Hex> = {
  'enroll-first-high': keccak256(toBytes('enroll-first-high')),
  'replace-partner': keccak256(toBytes('replace-partner')),
};

/** Longest window the attester will sign; the API asks for ten minutes. */
export const MAX_CEREMONY_WINDOW_SECONDS = 3_600n;

const UINT48_MAX = (1n << 48n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;

export interface CeremonyHashInputs {
  readonly chainId: bigint;
  /** The `CofferdamAccount4337` the ceremony is for. */
  readonly account: Hex;
  /** `CEREMONY_ACTIONS[...]`. */
  readonly action: Hex;
  /** `keccak256(newConfig)`: the new authority config the account will store. */
  readonly newKeyHash: Hex;
  /** Word 3 of the signing Partner authority's config, or zero for Managed. */
  readonly partnerId: Hex;
  /** The account's `ceremonyNonce` at signing time. */
  readonly nonce: bigint;
  readonly notBefore: bigint;
  readonly expiry: bigint;
}

/** Reproduces `CofferdamAccount4337.ceremonyHash` off-chain. */
export function ceremonyHash(inputs: CeremonyHashInputs): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'uint256' },
        { type: 'uint48' },
        { type: 'uint48' },
      ],
      [
        CEREMONY_TAG,
        inputs.chainId,
        inputs.account,
        inputs.action,
        inputs.newKeyHash,
        inputs.partnerId,
        inputs.nonce,
        // `uint48` words; viem types them as `number`, and they are < 2^53.
        Number(inputs.notBefore),
        Number(inputs.expiry),
      ],
    ),
  );
}

/** Deploy-time pins the ceremony signer refuses to sign outside of. */
export interface CeremonyPins {
  /** `BASE_CHAIN_ID` var, decimal string. */
  readonly chainIdStr: string;
}

export interface PreparedCeremony extends CeremonyHashInputs {
  readonly chainIdStr: string;
  readonly actionName: CeremonyAction;
}

function parseUint(raw: unknown, field: string, max: bigint): bigint {
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    badRequest('BAD_CEREMONY_FIELD', `${field} must be a non-negative decimal string`);
  }
  const v = BigInt(raw);
  if (v > max) badRequest('BAD_CEREMONY_FIELD', `${field} out of range`);
  return v;
}

function parseWord(raw: unknown, field: string): Hex {
  if (typeof raw !== 'string' || !isHex(raw) || size(raw) !== 32) {
    badRequest('BAD_CEREMONY_FIELD', `${field} must be a 0x-prefixed 32-byte hex string`);
  }
  return raw.toLowerCase() as Hex;
}

/**
 * Validate a `signCeremony` request against the pins and the window rules.
 * `now` is injected so the window checks unit-test deterministically.
 */
export function prepareCeremonyRequest(
  pins: CeremonyPins,
  req: SignCeremonyRequest,
  now: bigint = BigInt(Math.floor(Date.now() / 1000)),
): PreparedCeremony {
  if (!/^\d+$/.test(pins.chainIdStr)) {
    throw new AttesterError('BAD_CHAIN_ID_VAR', `BASE_CHAIN_ID var is malformed: ${pins.chainIdStr}`);
  }
  if (typeof req.chainId !== 'string' || req.chainId !== pins.chainIdStr) {
    badRequest('WRONG_CHAIN_ID', `attester is pinned to chain ${pins.chainIdStr}, request names ${String(req.chainId)}`);
  }
  if (typeof req.account !== 'string' || !isAddress(req.account)) {
    badRequest('BAD_ACCOUNT', 'account must be an EIP-55 address');
  }
  const action = CEREMONY_ACTIONS[req.action as CeremonyAction];
  if (!action) badRequest('BAD_CEREMONY_ACTION', `unknown ceremony action ${String(req.action)}`);

  const newKeyHash = parseWord(req.newKeyHash, 'newKeyHash');
  const partnerId = parseWord(req.partnerId, 'partnerId');
  const nonce = parseUint(req.nonce, 'nonce', UINT256_MAX);
  const notBefore = parseUint(req.notBefore, 'notBefore', UINT48_MAX);
  const expiry = parseUint(req.expiry, 'expiry', UINT48_MAX);
  if (expiry <= notBefore) badRequest('BAD_CEREMONY_WINDOW', 'expiry must be after notBefore');
  if (expiry - notBefore > MAX_CEREMONY_WINDOW_SECONDS) {
    badRequest('BAD_CEREMONY_WINDOW', `window exceeds ${MAX_CEREMONY_WINDOW_SECONDS.toString()} seconds`);
  }
  if (expiry < now) badRequest('BAD_CEREMONY_WINDOW', 'expiry is in the past');

  return {
    chainId: BigInt(pins.chainIdStr),
    chainIdStr: pins.chainIdStr,
    account: getAddress(req.account),
    action,
    actionName: req.action,
    newKeyHash,
    partnerId,
    nonce,
    notBefore,
    expiry,
  };
}

export interface SignedCeremonyAttestation {
  readonly attesterAddress: Hex;
  readonly messageHash: Hex;
  /** 65-byte EIP-191 signature, the `CeremonyAttestation.signature` bytes. */
  readonly signature: Hex;
}

/** Sign a prepared ceremony with EIP-191 personal_sign over the raw hash. */
export async function signCeremonyAttestation(
  privateKey: Hex,
  inputs: CeremonyHashInputs,
): Promise<SignedCeremonyAttestation> {
  const account = privateKeyToAccount(privateKey);
  const messageHash = ceremonyHash(inputs);
  const signature = await account.signMessage({ message: { raw: messageHash } });
  return { attesterAddress: account.address, messageHash, signature };
}
