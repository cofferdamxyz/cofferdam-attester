// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Cofferdam Self attester Worker — entry point.
 *
 * Exposes three RPC methods. `signBind` returns an EIP-191 personal_sign over
 * `NullifierRegistry.attesterMessageHash(...)` — but only after the Celo gate
 * has confirmed the proof's identity-commitment root, OFAC roots and date
 * against Self's own registry (decision 0004). `signCeremony` co-signs a
 * passkey ceremony for `CofferdamAccount4337` (decision 0016) with a separate
 * key; `signRebind` co-signs a nullifier rebind (decision 0022) with the bind
 * key over an epoch-bound message. This Worker is the only place in the Cofferdam stack where either
 * private key is ever deserialised; every other surface reaches it through
 * this binding.
 *
 * Defense layers:
 *   1. `workers_dev: false` + zero routes → no public ingress.
 *   2. Service-binding only → only Workers in this Cloudflare account call it.
 *   3. Pinned Base chain id + registry allowlist → a compromised consumer
 *      Worker cannot obtain a signature usable on another chain or registry.
 *   4. Strict input validation (`bind.ts`) → malformed requests reject before
 *      any network call or signing.
 *   5. Celo gate (`celoGate.ts`) → the one check Base cannot do itself: the
 *      proof's Merkle root is a root Self actually published.
 *   6. Audit log per request → every sign and every rejection hits Workers
 *      Logs; a replay auditor reconciles sign events against on-chain
 *      `NullifierBound` events.
 */

import { WorkerEntrypoint } from 'cloudflare:workers';
import { getAddress, isAddress, isHex, type Address, type Hex } from 'viem';
import { AttesterError, badRequest, prepareBindRequest, type PreparedBind } from './bind.js';
import {
  CeloGateError,
  PASSPORT_DISCLOSE_INDEX,
  createCeloReads,
  verifyProofOnCelo,
  type CeloGateConfig,
  type CeloGateResult,
  type CeloReads,
} from './celoGate.js';
import type { Env } from './env.js';
import { prepareCeremonyRequest, signCeremonyAttestation } from './ceremony.js';
import type {
  AttesterRpc,
  SignBindRequest,
  SignBindResponse,
  SignCeremonyRequest,
  SignCeremonyResponse,
  SignRebindRequest,
  SignRebindResponse,
} from './rpc.js';
import { signBindAttestation, signRebindAttestation } from './sign.js';

/** One viem client per isolate per RPC URL; rebuilt only if the var changes. */
let celoReadsCache: { rpcUrl: string; reads: CeloReads } | null = null;
function celoReadsFor(rpcUrl: string): CeloReads {
  if (!celoReadsCache || celoReadsCache.rpcUrl !== rpcUrl) {
    celoReadsCache = { rpcUrl, reads: createCeloReads(rpcUrl) };
  }
  return celoReadsCache.reads;
}

function assertPrivateKey(pk: string, name = 'ATTESTER_PRIVATE_KEY'): asserts pk is Hex {
  if (!isHex(pk) || pk.length !== 66 /* 0x + 64 hex chars */) {
    throw new AttesterError('BAD_ATTESTER_KEY', `${name} secret is missing or malformed (expected 0x + 64 hex chars)`);
  }
}

export default class CofferdamAttester extends WorkerEntrypoint<Env> implements AttesterRpc {
  /**
   * Gate and sign a bind.
   *
   * Validates the request against the deploy-time pins, re-verifies the
   * proof's Celo-anchored facts, recomputes `attesterMessageHash` exactly as
   * the on-chain registry does, signs it, and emits an audit line.
   */
  async signBind(req: SignBindRequest): Promise<SignBindResponse> {
    const prepared = prepareBindRequest(
      {
        chainIdStr: this.env.BASE_CHAIN_ID,
        allowedRegistryRaw: this.env.NULLIFIER_REGISTRY_ADDRESS,
      },
      req,
    );
    const celo = await this.#gateOnCelo(prepared);
    return this.#signPrepared(prepared, celo);
  }

  /**
   * Gate and co-sign a rebind (decision 0022): the same request shape and
   * Celo gate as a bind, signed over `rebindMessageHash` with the registry
   * epoch the API read, so the signature is single-use and never a bind.
   */
  async signRebind(req: SignRebindRequest): Promise<SignRebindResponse> {
    const prepared = prepareBindRequest(
      {
        chainIdStr: this.env.BASE_CHAIN_ID,
        allowedRegistryRaw: this.env.NULLIFIER_REGISTRY_ADDRESS,
      },
      req,
    );
    if (typeof req.epoch !== 'string' || !/^\d+$/.test(req.epoch)) {
      badRequest('BAD_EPOCH', 'epoch must be a non-negative decimal string');
    }
    const epoch = BigInt(req.epoch);
    const celo = await this.#gateOnCelo(prepared);

    assertPrivateKey(this.env.ATTESTER_PRIVATE_KEY);
    const signed = await signRebindAttestation(this.env.ATTESTER_PRIVATE_KEY, {
      chainId: prepared.chainId,
      registry: prepared.registry,
      account: prepared.account,
      pubSignals: prepared.pubSignals,
      epoch,
    });
    console.log(
      JSON.stringify({
        kind: 'attester.signRebind',
        environment: this.env.ENVIRONMENT,
        chainId: prepared.chainIdStr,
        registry: prepared.registry,
        account: prepared.account,
        nullifier: prepared.nullifier.toString(),
        epoch: epoch.toString(),
        attesterAddress: signed.attesterAddress,
        messageHash: signed.messageHash,
        gate: 'celo',
        merkleRoot: celo.merkleRoot.toString(),
        proofDate: celo.proofDate,
      }),
    );
    return {
      attesterAddress: signed.attesterAddress,
      messageHash: signed.messageHash,
      signature: signed.signature,
      chainId: prepared.chainIdStr,
      registry: prepared.registry,
      account: prepared.account,
      userContextData: prepared.userContextData,
      gate: 'celo',
      celo: {
        chainId: celo.chainId.toString(),
        registry: celo.registry,
        merkleRoot: celo.merkleRoot.toString(),
        proofDate: celo.proofDate,
      },
      epoch: epoch.toString(),
    };
  }

  /**
   * Co-sign a passkey ceremony (decision 0016): the first High on a Partner or
   * Managed account, or a pre-High Partner re-key. `cofferdam-api` has already
   * read the account (no High yet, current `ceremonyNonce`, the new key's
   * assertion over `firstHighChallenge`); this Worker pins the chain, bounds
   * the window, reproduces `ceremonyHash` and signs with the ceremony key,
   * which is never the Self bind key.
   */
  async signCeremony(req: SignCeremonyRequest): Promise<SignCeremonyResponse> {
    const prepared = prepareCeremonyRequest({ chainIdStr: this.env.BASE_CHAIN_ID }, req);
    assertPrivateKey(this.env.CEREMONY_ATTESTER_PRIVATE_KEY, 'CEREMONY_ATTESTER_PRIVATE_KEY');
    const signed = await signCeremonyAttestation(this.env.CEREMONY_ATTESTER_PRIVATE_KEY, prepared);

    // The new key hash is a hash of a public key, the partner id is public
    // on the account; nothing here links a person to the account.
    console.log(
      JSON.stringify({
        kind: 'attester.signCeremony',
        environment: this.env.ENVIRONMENT,
        chainId: prepared.chainIdStr,
        account: prepared.account,
        action: prepared.actionName,
        newKeyHash: prepared.newKeyHash,
        partnerId: prepared.partnerId,
        nonce: prepared.nonce.toString(),
        notBefore: prepared.notBefore.toString(),
        expiry: prepared.expiry.toString(),
        attesterAddress: signed.attesterAddress,
        messageHash: signed.messageHash,
      }),
    );

    return {
      attesterAddress: signed.attesterAddress,
      messageHash: signed.messageHash,
      signature: signed.signature,
      chainId: prepared.chainIdStr,
      account: prepared.account,
      action: prepared.actionName,
      nonce: prepared.nonce.toString(),
      notBefore: prepared.notBefore.toString(),
      expiry: prepared.expiry.toString(),
    };
  }

  /** Read and validate the Celo pins. Malformed vars are operator errors, not caller errors. */
  #celoConfig(): CeloGateConfig & { rpcUrl: string } {
    const rpcUrl = this.env.CELO_RPC_URL;
    if (typeof rpcUrl !== 'string' || !/^https:\/\//.test(rpcUrl)) {
      throw new AttesterError('BAD_CELO_RPC_VAR', 'CELO_RPC_URL must be an https:// URL');
    }
    const chainIdStr = this.env.SELF_CELO_CHAIN_ID;
    if (!/^\d+$/.test(chainIdStr ?? '')) {
      throw new AttesterError('BAD_CELO_CHAIN_ID_VAR', `SELF_CELO_CHAIN_ID var is malformed: ${chainIdStr}`);
    }
    const hub = this.env.SELF_HUB_ADDRESS;
    if (!isAddress(hub ?? '')) {
      throw new AttesterError('BAD_SELF_HUB_VAR', `SELF_HUB_ADDRESS var is malformed: ${hub}`);
    }
    const passportRegistry = this.env.SELF_PASSPORT_REGISTRY_ADDRESS;
    if (!isAddress(passportRegistry ?? '')) {
      throw new AttesterError(
        'BAD_SELF_REGISTRY_VAR',
        `SELF_PASSPORT_REGISTRY_ADDRESS var is malformed: ${passportRegistry}`,
      );
    }
    return {
      rpcUrl,
      chainId: BigInt(chainIdStr),
      hub: getAddress(hub) as Address,
      passportRegistry: getAddress(passportRegistry) as Address,
    };
  }

  async #gateOnCelo(prepared: PreparedBind): Promise<CeloGateResult> {
    const config = this.#celoConfig();

    // The proof commits to Self's destination chain inside userContextData.
    // It must be the Celo we are about to query, and the registry on Base
    // pins the same value immutably.
    if (prepared.selfDestChainId !== config.chainId) {
      badRequest(
        'WRONG_DEST_CHAIN_ID',
        `userContextData declares destination chain ${prepared.selfDestChainId.toString()}, ` +
          `attester is pinned to Celo ${config.chainId.toString()}`,
      );
    }

    try {
      return await verifyProofOnCelo(celoReadsFor(config.rpcUrl), config, prepared.pubSignals);
    } catch (err) {
      if (err instanceof CeloGateError) {
        // A spike in one code is a signal: CELO_REGISTRY_MISMATCH means Self
        // migrated its registry; CELO_OFAC_ROOTS_STALE in bulk means a
        // sanctions snapshot rolled mid-session; CELO_RPC_UNAVAILABLE is ours.
        console.log(
          JSON.stringify({
            kind: 'attester.celoGateRejected',
            environment: this.env.ENVIRONMENT,
            code: err.code,
            retryable: err.retryable,
            message: err.message,
            account: prepared.account,
            nullifier: prepared.nullifier.toString(),
          }),
        );
        throw new AttesterError(err.code, err.message, err.retryable);
      }
      throw err;
    }
  }

  async #signPrepared(prepared: PreparedBind, celo: CeloGateResult): Promise<SignBindResponse> {
    const { chainId, chainIdStr, registry, account, pubSignals, userContextData } = prepared;

    assertPrivateKey(this.env.ATTESTER_PRIVATE_KEY);
    const signed = await signBindAttestation(this.env.ATTESTER_PRIVATE_KEY, {
      chainId,
      registry,
      account,
      pubSignals,
    });

    // Privacy-safe audit line: the nullifier is public on bind anyway, so
    // logging it here adds no linkability. Full pubSignals are NOT logged —
    // the revealed-data words can carry disclosure fields.
    console.log(
      JSON.stringify({
        kind: 'attester.signBind',
        environment: this.env.ENVIRONMENT,
        chainId: chainIdStr,
        registry,
        account,
        attestationId: pubSignals[PASSPORT_DISCLOSE_INDEX.ATTESTATION_ID]!.toString(),
        scope: pubSignals[PASSPORT_DISCLOSE_INDEX.SCOPE]!.toString(),
        nullifier: prepared.nullifier.toString(),
        attesterAddress: signed.attesterAddress,
        messageHash: signed.messageHash,
        gate: 'celo',
        celoChainId: celo.chainId.toString(),
        celoRegistry: celo.registry,
        merkleRoot: celo.merkleRoot.toString(),
        proofDate: celo.proofDate,
      }),
    );

    return {
      attesterAddress: signed.attesterAddress,
      messageHash: signed.messageHash,
      signature: signed.signature,
      chainId: chainIdStr,
      registry,
      account,
      userContextData,
      gate: 'celo',
      celo: {
        chainId: celo.chainId.toString(),
        registry: celo.registry,
        merkleRoot: celo.merkleRoot.toString(),
        proofDate: celo.proofDate,
      },
    };
  }

  /**
   * Non-RPC fetch handler. The Worker is service-binding only, but a default
   * export needs `fetch`; 405 makes the boundary explicit if `workers_dev`
   * is ever flipped by accident.
   */
  override async fetch(): Promise<Response> {
    return new Response('cofferdam-attester is service-binding-only; use the ATTESTER RPC', {
      status: 405,
    });
  }
}
