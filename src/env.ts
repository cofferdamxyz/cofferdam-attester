// Copyright (c) 2026 Cofferdam Inc
// SPDX-License-Identifier: Apache-2.0

/**
 * Typed environment bindings for the Cofferdam Self attester Worker.
 *
 * Mirrors the `vars` and secrets declared in `wrangler.jsonc`. This Worker
 * has one job (gate and sign bind messages and ceremony co-signs), zero
 * resource bindings (KV/R2/D1/services) and two egresses: read-only JSON-RPC
 * to Celo for the bind gate, and, only under `CEREMONY_SIGNER=cdp`, CDP's
 * REST API for the ceremony's typed-data signature (`src/cdp/`, decision
 * 0090, E7). Adding a binding or an egress here widens the blast radius of
 * the signing key — audit before doing so.
 */
export interface Env {
  // ── vars ────────────────────────────────────────────────────────

  /** 'development' | 'staging' | 'production'. Logged with every audit line. */
  ENVIRONMENT: 'development' | 'staging' | 'production';

  /**
   * Base chain id as a decimal string: Base Sepolia `84532`, Base mainnet
   * `8453`. Part of the signed preimage. A mainnet attester is a separate
   * Worker deploy, never a second value on this one.
   */
  BASE_CHAIN_ID: string;

  /**
   * EIP-55 address of the sole `NullifierRegistry` this attester signs for.
   * Must equal `SEPOLIA_DEPLOYMENTS.NullifierRegistry` in
   * `cofferdam-api/src/chain/deployments.ts`.
   */
  NULLIFIER_REGISTRY_ADDRESS: string;

  /**
   * JSON-RPC endpoint for Celo, the chain Self anchors its registries on.
   * Public `https://forno.celo.org` is fine; if you move to a keyed provider,
   * delete this var and set a secret of the same name instead.
   */
  CELO_RPC_URL: string;

  /**
   * Chain id `CELO_RPC_URL` must report (mainnet `42220`). Also the
   * `SelfApp.chainID` the app declares, which `NullifierRegistry.selfDestChainId`
   * pins immutably — the attester refuses a proof whose `userContextData`
   * names any other destination chain.
   */
  SELF_CELO_CHAIN_ID: string;

  /** Self `IdentityVerificationHubImplV2` proxy on Celo. */
  SELF_HUB_ADDRESS: string;

  /**
   * Self `IdentityRegistryImplV1` proxy for E_PASSPORT on Celo. The gate
   * cross-checks `hub.registry(E_PASSPORT)` against this pin and refuses on
   * mismatch, so a Self-side registry migration fails loudly.
   */
  SELF_PASSPORT_REGISTRY_ADDRESS: string;

  /**
   * How this Worker signs ceremony co-signs (workspace decision 0090 item 5):
   * `eip712` for the production account generation of decision 0080 on (the
   * typed `CeremonyAttestation`), `eip191` for Base Sepolia's deployed
   * generation only, until the next Sepolia generation replaces it. Anything
   * else refuses every `signCeremony`. Never chosen by a request.
   */
  CEREMONY_SIGNATURE: string;

  /**
   * EIP-55 address of the generation's `CofferdamCeremonyAttesterRegistry`:
   * the EIP-712 domain's `verifyingContract`, and the registry a request must
   * name. Must equal the `CofferdamCeremonyAttesterRegistry` of the chain's
   * table in `cofferdam-api/src/chain/deployments.ts`.
   */
  CEREMONY_REGISTRY_ADDRESS: string;

  /**
   * Who signs the ceremony co-sign (workspace decision 0090, E7;
   * `src/ceremonySigner.ts`): `key` (the default when unset,
   * `CEREMONY_ATTESTER_PRIVATE_KEY`) or `cdp` (the attester project's
   * `ceremony-attester` account, `CEREMONY_CDP_ADDRESS`, with the three CDP
   * secrets). Any other value, or `cdp` without its address or a well-formed
   * secret, refuses every `signCeremony` with `BAD_ATTESTER_KEY`; nothing falls
   * back to the raw key (item 12). `cdp` needs `CEREMONY_SIGNATURE=eip712`,
   * since an EIP-191 hash signature is the `signEvmHash` the project policy
   * refuses (items 5 and 9).
   */
  CEREMONY_SIGNER?: string;

  /**
   * EIP-55 address of the `ceremony-attester` CDP account (not a secret), read
   * only under `CEREMONY_SIGNER=cdp`. It must be listed in the generation's
   * `CofferdamCeremonyAttesterRegistry`, and its account policy pins
   * `CEREMONY_REGISTRY_ADDRESS` (`scripts/cdp/policies.mjs` in the workspace).
   */
  CEREMONY_CDP_ADDRESS?: string;

  // ── secrets (set via `wrangler secret put NAME`) ────────────────

  /**
   * 0x-prefixed 32-byte secp256k1 private key. Its address must be
   * allow-listed in `SelfAttesterRegistry`, otherwise on-chain
   * `verifyAttesterSig` rejects every signature this Worker produces.
   *
   * Never log, persist or echo this value. Read once per request to derive
   * a viem account, then dropped.
   */
  ATTESTER_PRIVATE_KEY: string;

  /**
   * 0x-prefixed 32-byte secp256k1 private key of the ceremony co-signer
   * (decision 0016). Its address must be listed in
   * `CofferdamCeremonyAttesterRegistry`, the registry every account from the
   * factory pins; it is never the Self bind key above, so the two lists never
   * share a signer. Read once per `signCeremony` and only while
   * `CEREMONY_SIGNER` is `key`, never logged. Deleted once the attester signs
   * through CDP.
   */
  CEREMONY_ATTESTER_PRIVATE_KEY?: string;

  /**
   * The attester's own CDP project credentials (decision 0090, question A of
   * `docs/runbooks/cdp-setup.md`: a project of its own, so its Wallet Secret is
   * never the plane's), read only under `CEREMONY_SIGNER=cdp`: the Secret API
   * key's id and its Ed25519 secret as base64 of seed ‖ public key (signing
   * only, never the Manage restriction, never export), and the project's
   * Wallet Secret as base64 PKCS#8. Set by the founder with `wrangler secret
   * put`, copies in the vault (decision 0054). Never logged; an error names
   * what is malformed, never a byte of it.
   */
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
  CDP_WALLET_SECRET?: string;
}
