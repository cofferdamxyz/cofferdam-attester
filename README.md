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
  ceremony.ts   ceremony preimage (CofferdamAccount4337.ceremonyHash) and window rules
  env.ts        typed vars and secrets
test/           Vitest: gate, validation, signing, rebind, ceremony; celoGate.live.test.ts behind CELO_LIVE=1
```

## RPC methods

| Method | Signs | Key |
|---|---|---|
| `signBind` | `NullifierRegistry.attesterMessageHash(chainId, registry, account, pubSignals)`, after the Celo gate | `ATTESTER_PRIVATE_KEY`, trusted by `SelfAttesterRegistry` |
| `signRebind` | the rebind message bound to the registry's `rebindCount` epoch, after the same gate (workspace decision 0022) | `ATTESTER_PRIVATE_KEY` |
| `signCeremony` | `CofferdamAccount4337.ceremonyHash` for `enroll-first-high` or `replace-partner`, within a window of at most one hour; the gate itself runs in `cofferdam-api`, which exposes `enroll-first-high` today | `CEREMONY_ATTESTER_PRIVATE_KEY`, listed in `CofferdamCeremonyAttesterRegistry` |

Every response echoes the signer address, the message hash and the audit fields. **Planned:** the co-sign for hard recovery (`recoverHigh`, workspace decision 0023); the contracts are on Sepolia, the method is not built.

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

`.dev.vars` (ignored) holds `ATTESTER_PRIVATE_KEY`, `CEREMONY_ATTESTER_PRIVATE_KEY` and `ENVIRONMENT=development`. Exercise it through the API: `POST /v1/attester/test-sign` returns `onchainValid: true` when the whole rail works. After a key rotation, update `.dev.vars` too, or local signatures come from a retired key.

## Deploy

From the Mac with the workspace `.envrc` loaded, before the API when a pin moves: `direnv exec .. yarn deploy` (it reports "No deploy targets", as expected). See `docs/runbooks/cloudflare-deploys.md` in the cofferdam workspace repository.

## Key facts

- Pins in `wrangler.jsonc`: `BASE_CHAIN_ID` (84532), `NULLIFIER_REGISTRY_ADDRESS` (must equal `SEPOLIA_DEPLOYMENTS.NullifierRegistry` in `cofferdam-api`, or every call fails `REGISTRY_NOT_ALLOWED`), and the four Celo pins. Base mainnet gets its own deployment rather than a second value here.
- Secrets enter only through `wrangler secret put`. The bind key and the ceremony key are separate keys on separate allow-lists.
- Rotating the bind key is `base-contracts/scripts/rotate-self-attester.ts` on Base, the deployed secret and `.dev.vars`, together.
- A change to an RPC shape or the gate ships with its caller in `cofferdam-api`.

## Documentation

Design documentation lives in the cofferdam workspace repository under `docs/` and will be published at docs.cofferdam.xyz: `docs/architecture/plane.md`, `docs/architecture/identity.md`, `docs/runbooks/cloudflare-deploys.md`, `docs/runbooks/self-verification.md`.

## License

Apache License 2.0. Copyright 2026 Cofferdam Inc. See `LICENSE` and `NOTICE`.
