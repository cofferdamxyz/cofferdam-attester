# REVIEW.md — cofferdam-attester

Read with `AGENTS.md` and `README.md`. All of this repository is **high risk**: it holds the keys that sign `NullifierRegistry` binds, rebinds and ceremony co-signs. Here failure means **it signs something it should have refused**.

## What failure looks like

- A path to `signBind`, `signRebind` or `signCeremony` that skips or weakens the Celo gate (`celoGate.ts`) or the ceremony's checks, or signs a message whose fields the gate did not check.
- A reachable surface other than the `cofferdam-api` service binding: `workers_dev` on, a route, a `fetch` handler that does more than refuse.
- A key (`ATTESTER_PRIVATE_KEY`, `CEREMONY_ATTESTER_PRIVATE_KEY`) or a signature logged, returned in an error, or present in `wrangler.jsonc`, a test or a doc.
- A development or staging shortcut reachable when `ENVIRONMENT` says otherwise.
- An RPC shape change without `README.md`, the caller in `cofferdam-api` and the workspace `docs/architecture/plane.md` in the same pass.

## How to report

- Every finding names a file and line and quotes the code or text that is wrong. A guess from a name or a path is not a finding.
- Tag each one **Important** (wrong behaviour, a broken rule above, a security or money risk), **Nit** (at most three per review; style alone is never one) or **Pre-existing** (true, but not introduced by this diff; never blamed on it).
- Flag a class of bug once with every instance, not one finding per line. Do not repeat a finding already answered in an earlier round; after the second round read only the new diff.
- Start the summary with the count ("2 Important, 1 Nit, 1 Pre-existing"), and say "Nothing to fix" plainly when that is the result.
- Name the risk tier the diff falls in (workspace `docs/runbooks/code-review.md`).
