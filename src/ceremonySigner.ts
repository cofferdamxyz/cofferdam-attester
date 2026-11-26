// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Who signs the ceremony co-sign, behind a switch (workspace decision 0090;
 * runbook `docs/runbooks/cdp-setup.md`, E7), mirroring the plane's hot
 * signers (`cofferdam-api/src/services/hotSigner.ts`, E4):
 *
 *   CEREMONY_SIGNER   `key` (default): `CEREMONY_ATTESTER_PRIVATE_KEY`
 *                     `cdp`: the `ceremony-attester` account of the attester's
 *                     own CDP project, `CEREMONY_CDP_ADDRESS`, with the
 *                     secrets `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` and
 *                     `CDP_WALLET_SECRET`
 *
 * Any other value, or `cdp` without its address or a secret, or a secret of
 * the wrong shape, is not configured: `BAD_ATTESTER_KEY`, which the plane
 * answers `503 attester_unavailable`. Nothing falls back to the raw key
 * (decision 0090 item 12): under `cdp` the raw key is never read, set or not.
 *
 * Under `cdp` only the EIP-712 form signs (`CEREMONY_SIGNATURE=eip712`). An
 * EIP-191 signature over a raw hash is CDP's `signEvmHash`, which the project
 * policy refuses (decision 0090 items 5 and 9), so `cdp` with `eip191` is a
 * configuration error (`BAD_CEREMONY_SIGNATURE_VAR`, also a 503), found
 * before any request to CDP.
 *
 * A CDP failure is logged and thrown by CDP's status, `errorType` and
 * `correlationId` only (`CdpApiError.message`), never CDP's own message,
 * which can quote the request:
 *
 *   no answer, 429, 5xx      `CDP_UNAVAILABLE` (retryable)
 *   any other refusal        `CDP_REFUSED` (a policy, a revoked key)
 *   a signature not the      `CDP_BAD_SIGNATURE`
 *   account's, or malformed
 *   a secret that will not   `BAD_ATTESTER_KEY`
 *   import
 */

import { getAddress, hashTypedData, isAddress, isHex, type Address, type Hex } from 'viem';
import { AttesterError } from './bind.js';
import { CdpKeyError } from './cdp/auth.js';
import {
  CdpApiError,
  CdpResponseError,
  cdpCredentialsOf,
  createCdpClient,
  type CdpClient,
  type CdpCredentials,
} from './cdp/client.js';
import {
  ceremonyTypedData,
  signCeremonyAttestation,
  type CeremonySignatureForm,
  type PreparedCeremony,
  type SignedCeremonyAttestation,
} from './ceremony.js';

export type CeremonySignerKind = 'key' | 'cdp';

/** Where the ceremony signer comes from, read from the env; never the CDP client itself. */
export type CeremonySignerSpec =
  | { readonly kind: 'key'; readonly privateKey: Hex }
  | { readonly kind: 'cdp'; readonly address: Address; readonly credentials: CdpCredentials };

/** The env the switch reads. */
export interface CeremonySignerEnv {
  CEREMONY_SIGNER?: string;
  CEREMONY_ATTESTER_PRIVATE_KEY?: string;
  CEREMONY_CDP_ADDRESS?: string;
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
  CDP_WALLET_SECRET?: string;
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * The secrets' shapes, checked before any request: the API key's secret is
 * base64 of 64 bytes (Ed25519 seed and public key), the Wallet Secret base64.
 * The curves are checked when the keys are imported, at first use.
 */
function credentialShapesHold(c: CdpCredentials): boolean {
  if (!BASE64.test(c.apiKeySecret) || !BASE64.test(c.walletSecret)) return false;
  try {
    return atob(c.apiKeySecret).length === 64 && atob(c.walletSecret).length > 0;
  } catch {
    return false;
  }
}

function notConfigured(detail: string): never {
  throw new AttesterError('BAD_ATTESTER_KEY', detail);
}

/**
 * The ceremony signer the switch names, for the Worker's pinned form, or a
 * thrown operator error naming what is missing by name, never by value.
 */
export function ceremonySignerSpecOf(env: CeremonySignerEnv, form: CeremonySignatureForm): CeremonySignerSpec {
  const kind = (env.CEREMONY_SIGNER?.trim() || 'key').toLowerCase();
  if (kind === 'key') {
    const pk = env.CEREMONY_ATTESTER_PRIVATE_KEY;
    if (typeof pk !== 'string' || !isHex(pk) || pk.length !== 66 /* 0x + 64 hex chars */) {
      notConfigured('CEREMONY_ATTESTER_PRIVATE_KEY secret is missing or malformed (expected 0x + 64 hex chars)');
    }
    return { kind: 'key', privateKey: pk };
  }
  if (kind !== 'cdp') notConfigured('CEREMONY_SIGNER must be "key" or "cdp"');
  if (form !== 'eip712') {
    // EIP-191 over a raw hash is CDP's signEvmHash, which the project policy refuses.
    throw new AttesterError('BAD_CEREMONY_SIGNATURE_VAR', 'CEREMONY_SIGNER=cdp signs only CEREMONY_SIGNATURE=eip712');
  }
  const address = env.CEREMONY_CDP_ADDRESS?.trim() ?? '';
  const credentials = cdpCredentialsOf(env);
  if (!isAddress(address) || getAddress(address) !== address || !credentials || !credentialShapesHold(credentials)) {
    notConfigured(
      'CEREMONY_SIGNER=cdp needs CEREMONY_CDP_ADDRESS (EIP-55) and well-formed CDP_API_KEY_ID, CDP_API_KEY_SECRET and CDP_WALLET_SECRET',
    );
  }
  return { kind: 'cdp', address, credentials };
}

/** One CDP failure, as the audit log and the thrown error name it. */
interface CdpFailure {
  readonly code: 'CDP_UNAVAILABLE' | 'CDP_REFUSED' | 'CDP_BAD_SIGNATURE' | 'BAD_ATTESTER_KEY' | 'CDP_SIGN_FAILED';
  readonly retryable: boolean;
  /** Safe to log and to return: CDP's status, type and correlation id, or an error's name. */
  readonly detail: string;
  readonly status?: number;
  readonly errorType?: string;
  readonly correlationId?: string;
}

function cdpFailureOf(err: unknown): CdpFailure {
  if (err instanceof CdpApiError) {
    return {
      code: err.retryable ? 'CDP_UNAVAILABLE' : 'CDP_REFUSED',
      retryable: err.retryable,
      // `CdpApiError.message` names the status, the type and the correlation id only.
      detail: err.message,
      status: err.status,
      errorType: err.errorType,
      correlationId: err.correlationId,
    };
  }
  if (err instanceof CdpResponseError) return { code: 'CDP_BAD_SIGNATURE', retryable: false, detail: err.message };
  // The key error's message names what is malformed, never a byte of it.
  if (err instanceof CdpKeyError) return { code: 'BAD_ATTESTER_KEY', retryable: false, detail: err.message };
  return { code: 'CDP_SIGN_FAILED', retryable: false, detail: `cdp ${err instanceof Error ? err.name : 'error'}` };
}

export interface CeremonySigner {
  readonly kind: CeremonySignerKind;
  /** Sign a prepared ceremony; a CDP failure is logged and thrown as an `AttesterError`. */
  sign(prepared: PreparedCeremony): Promise<SignedCeremonyAttestation>;
}

export interface CeremonySignerContext {
  /** Logged on every CDP failure line. */
  readonly environment: string;
  /** Injected by the tests; built from the spec's credentials otherwise. */
  readonly cdp?: CdpClient;
}

/** The signer a spec describes. */
export function ceremonySigner(spec: CeremonySignerSpec, ctx: CeremonySignerContext): CeremonySigner {
  if (spec.kind === 'key') {
    return { kind: 'key', sign: (prepared) => signCeremonyAttestation(spec.privateKey, prepared) };
  }
  return {
    kind: 'cdp',
    async sign(prepared) {
      if (prepared.form !== 'eip712') {
        throw new AttesterError('BAD_CEREMONY_SIGNATURE_VAR', 'CEREMONY_SIGNER=cdp signs only CEREMONY_SIGNATURE=eip712');
      }
      const typed = ceremonyTypedData(prepared, prepared.registry);
      let signature: Hex;
      try {
        const client = ctx.cdp ?? createCdpClient(spec.credentials);
        // The client refuses an answer that does not recover to `spec.address` over this typed data.
        signature = await client.signTypedData(spec.address, typed);
      } catch (err) {
        const failure = cdpFailureOf(err);
        console.log(
          JSON.stringify({
            kind: 'attester.signCeremonyFailed',
            environment: ctx.environment,
            signer: 'cdp',
            code: failure.code,
            retryable: failure.retryable,
            ...(failure.status !== undefined ? { status: failure.status } : {}),
            ...(failure.errorType !== undefined ? { errorType: failure.errorType } : {}),
            ...(failure.correlationId !== undefined ? { correlationId: failure.correlationId } : {}),
            ...(failure.status === undefined ? { detail: failure.detail } : {}),
            attesterAddress: spec.address,
            account: prepared.account,
            action: prepared.actionName,
          }),
        );
        throw new AttesterError(failure.code, failure.detail, failure.retryable);
      }
      return { attesterAddress: spec.address, messageHash: hashTypedData(typed), signature };
    },
  };
}
