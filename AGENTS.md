# Working in this repo (agent guidance)

The domain vocabulary is in `CONTEXT.md`; the work protocol is `work/protocol/` (dorfl's `work/` contract).

## Acceptance gate

```sh
pnpm install && pnpm verify   # prettier --check, tsc, vitest
```

Fix formatting with `pnpm format`, not by hand.

## The wire is frozen

The publication message (`originPublicKeyPublicationMessage`) and the request envelope (`requestMessage`) are signed by wallets and apps in production, and checked by several services. Their tests pin them byte for byte. Never edit either: a new format is a new purpose line accepted beside the old one, with a changelog entry, and its consumers (missiv, push-notification-server, the trigger service, `@etherplay/connect-core`) told.

## Releases

Bump `version` in package.json, then publish (`pnpm build && npm stage publish`, approved by the owner with 2FA). The API is small on purpose: add to it only what two consumers need.

## Git transitions

When dispatched to build a work task, do no git: the runner or the human owns every commit, push and `work/` move.
