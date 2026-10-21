# AGENTS Instructions — cofferdam-attester

## Scope

Service-binding-only Cloudflare Worker that re-verifies a Self.xyz disclose
proof against Self's registry on Celo and signs `NullifierRegistry` bind and
rebind messages with the registered `SelfAttester` ECDSA key, and decision 0016
ceremony co-signs with the ceremony attester key. The only caller is
`cofferdam-api` through its `services` binding: `workers_dev` is off and there
are no routes. `README.md` documents the RPC surface and the Celo gate; the
trust model is the workspace `docs/architecture/plane.md` and decision 0004.
The hard-recovery co-sign of decision 0023 is not built yet. There is no Cofferdam prover: Self proves in its own enclave.

## Rules

- yarn only; never `npm install`. `yarn test` (vitest) and `yarn typecheck`
  before a commit.
- Secrets (`ATTESTER_PRIVATE_KEY`, `CEREMONY_ATTESTER_PRIVATE_KEY`) enter only through `wrangler secret put`,
  never `wrangler.jsonc`, tests or docs. The deployment runs
  `ENVIRONMENT=staging`; `.dev.vars` sets `development` for `wrangler dev`.
- Deploys run from the Mac with the workspace `.envrc` sourced (Cofferdam Inc.
  Cloudflare account), never from a cloud session; no hardcoded `account_id`.
  Runbook: `docs/runbooks/cloudflare-deploys.md` in the workspace.
- A change to the RPC shape or the gate walks `README.md`, the caller in
  `cofferdam-api` and the workspace `docs/architecture/plane.md` in the same pass.
- Workspace rules: `rules/cofferdam-identity.md`,
  `rules/cofferdam-infrastructure.md` in the `cofferdam` repository (`../` on
  the Mac, `../cofferdam/` in a cloud session).

## Review

`REVIEW.md` says what failure looks like here and how a reviewer reports it: any review (`/code-review`, a hosted reviewer) reads it with this file. Before the last push a delegated session reviews its own diff against it and answers every finding (workspace decision 0052, `docs/runbooks/code-review.md`).
