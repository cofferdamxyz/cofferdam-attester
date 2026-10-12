# AGENTS Instructions — cofferdam-attester

## Scope

Service-binding-only Cloudflare Worker that re-verifies a Self.xyz disclose
proof against Self's registry on Celo and signs the `NullifierRegistry` bind
message with the registered `SelfAttester` ECDSA key. The only caller is
`cofferdam-api` through its `services` binding: `workers_dev` is off and there
are no routes. `README.md` documents the RPC surface and the Celo gate; the
trust model is `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` and workspace
decision 0004. There is no Cofferdam prover: Self proves in its own enclave.

## Rules

- yarn only; never `npm install`. `yarn test` (vitest) and `yarn typecheck`
  before a commit.
- Secrets (`ATTESTER_PRIVATE_KEY`) enter only through `wrangler secret put`,
  never `wrangler.jsonc`, tests or docs. The deployment runs
  `ENVIRONMENT=staging`; `.dev.vars` sets `development` for `wrangler dev`.
- Deploys run from the Mac with the workspace `.envrc` sourced (Cofferdam Inc.
  Cloudflare account), never from a cloud session; no hardcoded `account_id`.
- A change to the RPC shape or the gate walks `README.md` and the caller in
  `cofferdam-api` in the same pass.
- Workspace rules: `rules/cofferdam-identity.md`,
  `rules/cofferdam-infrastructure.md` in the `cofferdam` repository (`../` on
  the Mac, `../cofferdam/` in a cloud session).
