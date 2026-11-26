# cofferdam-attester

The Cofferdam attester: a private Cloudflare Worker that holds two signing keys and co-signs what Cofferdam's Base contracts require a Cofferdam signature for. It re-verifies a Self.xyz `disclose` proof against Self's registry on Celo before signing the `NullifierRegistry` bind or rebind message, and it co-signs passkey ceremonies for `CofferdamAccount4337`. It has no URL: `workers_dev` is off, there are no routes, and the only caller is [`cofferdam-api`](https://github.com/cofferdamxyz/cofferdam-api) through its `ATTESTER` service binding, so even a compromised API can call the RPC methods but never read a key. There is no Cofferdam prover: Self proves in its own enclave.

## Layout

```
src/
  index.ts      WorkerEntrypoint with the RPC methods; audit log line per sign or rejection
  rpc.ts        request and response types (mirrored by cofferdam-api/src/services/attester.ts)
  bind.ts       request validation against the pins (chain, registry, userContextData)
  celoGate.ts   the Celo reads and checks
  sign.ts       bind and rebind preimages, EIP-191 signing
  ceremony.ts   ceremony typed data and EIP-191 preimage (CofferdamAccount4337.ceremonyHash), pins and window rules
  ceremonySigner.ts  CEREMONY_SIGNER: the raw ceremony key or the CDP account, no fallback
  cdp/          CDP Server Wallet REST client: the two JWTs (auth.ts, a copy of cofferdam-api's) and signTypedData (client.ts)
  env.ts        typed vars and secrets
test/           Vitest: gate, validation, signing, rebind, ceremony, the signer switch and the CDP client against a fake CDP; celoGate.live.test.ts behind CELO_LIVE=1
```

## RPC methods

| Method | Signs | Key |
|---|---|---|
| `signBind` | `NullifierRegistry.attesterMessageHash(chainId, registry, account, pubSignals)`, after the Celo gate | `ATTESTER_PRIVATE_KEY`, trusted by `SelfAttesterRegistry` |
| `signRebind` | the rebind message bound to the registry's `rebindCount` epoch, after the same gate (workspace decision 0022) | `ATTESTER_PRIVATE_KEY` |
| `signCeremony` | `CofferdamAccount4337.ceremonyHash` for `enroll-first-high` or `replace-partner`, within a window of at most one hour, in the form the Worker pins (`CEREMONY_SIGNATURE`): `eip712`, the typed `CeremonyAttestation` under the domain ("Cofferdam Ceremony", "1", chainId, `CEREMONY_REGISTRY_ADDRESS`), for the production account generation on (workspace decision 0090 item 5), or `eip191` for Base Sepolia's deployed generation; the request must name the pinned registry (`REGISTRY_NOT_ALLOWED`) and never picks the form; the gate itself runs in `cofferdam-api`, which exposes `enroll-first-high` today | `CEREMONY_SIGNER`: `key` (default), `CEREMONY_ATTESTER_PRIVATE_KEY`; or `cdp`, the `ceremony-attester` CDP account `CEREMONY_CDP_ADDRESS` (EIP-712 only); either listed in `CofferdamCeremonyAttesterRegistry` |

Every response echoes the signer address, the message hash and the audit fields; `attester.signCeremony` also names the signer (`key` or `cdp`). Each sign or refusal writes one JSON audit line naming the account; no line carries the nullifier beside it (the identity log policy, workspace decision 0080), so a sign reconciles with its on-chain `NullifierBound` event by account and message hash (`test/auditLog.test.ts`). **Planned:** the co-sign for hard recovery (`recoverHigh`, workspace decision 0023); the contracts are on Sepolia, the method is not built.

## The Celo gate

1. The hub at `SELF_HUB_ADDRESS` must still route E_PASSPORT to `SELF_PASSPORT_REGISTRY_ADDRESS` (`CELO_REGISTRY_MISMATCH`).
2. The proof's identity-commitment root (`pubSignals[9]`) must be one Self published (`checkIdentityCommitmentRoot`, `CELO_ROOT_UNKNOWN`).
3. Its OFAC roots (`pubSignals[16..18]`) must be current (`checkOfacRoots`, `CELO_OFAC_ROOTS_STALE`); the RPC must answer chain 42220 (`CELO_CHAIN_MISMATCH`).
4. The proof date must be within ±1 day UTC; the attestation must be E_PASSPORT and `userContextData` must name Celo as destination.
5. All reads are read-only `eth_call`s to Celo mainnet; the Groth16 proof itself is verified on Base by `NullifierRegistry` (workspace decision 0004).

## Develop

yarn only; never `npm install`.

```bash
yarn install
yarn test               # unit, offline
CELO_LIVE=1 yarn test   # also runs the gate against forno.celo.org
yarn typecheck
yarn wrangler dev --port 8788   # cofferdam-api owns 8787 and discovers this Worker
```

`.dev.vars` (ignored) holds `ATTESTER_PRIVATE_KEY`, `CEREMONY_ATTESTER_PRIVATE_KEY` and `ENVIRONMENT=development`; local development keeps `CEREMONY_SIGNER` on `key`. Exercise it through the API: `POST /v1/attester/test-sign` returns `onchainValid: true` when the whole rail works. After a key rotation, update `.dev.vars` too, or local signatures come from a retired key.

## Deploy

From the Mac with the workspace `.envrc` loaded, before the API when a pin moves: `direnv exec .. yarn deploy` (it reports "No deploy targets", as expected). See `docs/runbooks/cloudflare-deploys.md` in the cofferdam workspace repository.

## Key facts

- Pins in `wrangler.jsonc`: `BASE_CHAIN_ID` (84532), `NULLIFIER_REGISTRY_ADDRESS` (must equal `SEPOLIA_DEPLOYMENTS.NullifierRegistry` in `cofferdam-api`, or every call fails `REGISTRY_NOT_ALLOWED`), `CEREMONY_SIGNATURE` (`eip191` while Sepolia's deployed generation is current; `eip712` from the next generation, a malformed value refusing every ceremony) and `CEREMONY_REGISTRY_ADDRESS` (EIP-55, the chain's `CofferdamCeremonyAttesterRegistry` in `cofferdam-api/src/chain/deployments.ts`), and the four Celo pins. Base mainnet gets its own deployment rather than a second value here.
- Secrets enter only through `wrangler secret put`. The bind key and the ceremony key are separate keys on separate allow-lists.
- The ceremony signer is a switch (workspace decision 0090, `docs/runbooks/cdp-setup.md` E7): `CEREMONY_SIGNER` `key` (the default) signs with `CEREMONY_ATTESTER_PRIVATE_KEY`; `cdp` signs through the `ceremony-attester` account of the attester's own CDP project, `CEREMONY_CDP_ADDRESS` (a var, EIP-55) with the secrets `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` and `CDP_WALLET_SECRET`, over CDP's REST API (`POST /v2/evm/accounts/{address}/sign/typed-data`; the answer must recover to the account). An unknown value, a missing piece or a malformed secret refuses every ceremony with `BAD_ATTESTER_KEY`, and nothing falls back to the raw key. `cdp` signs only `CEREMONY_SIGNATURE` `eip712`: EIP-191 over a raw hash is CDP's `signEvmHash`, which the project policy refuses, so `cdp` with `eip191` is `BAD_CEREMONY_SIGNATURE_VAR`. A CDP failure is `CDP_UNAVAILABLE` (no answer, 429, 5xx; retryable), `CDP_REFUSED` (a policy, a revoked key), `CDP_BAD_SIGNATURE` or `CDP_SIGN_FAILED`, logged as `attester.signCeremonyFailed` with CDP's status, `errorType` and `correlationId` only. Base Sepolia's deployed generation stays on `key`. Not yet run against CDP.
- Rotating the bind key is `base-contracts/scripts/rotate-self-attester.ts` on Base, the deployed secret and `.dev.vars`, together.
- A change to an RPC shape or the gate ships with its caller in `cofferdam-api`.
- `test/fixtures/ceremonyTypes.json` is cofferdam-sdk's shared fixture of the typed ceremony, copied byte for byte; the attester's signatures equal the SDK's for its vectors.

## Documentation

Design documentation lives in the cofferdam workspace repository under `docs/` and will be published at docs.cofferdam.xyz: `docs/architecture/plane.md`, `docs/architecture/identity.md`, `docs/runbooks/cloudflare-deploys.md`, `docs/runbooks/self-verification.md`.

## License

Apache License 2.0. Copyright 2026 Cofferdam Inc. See `LICENSE` and `NOTICE`.
