# CONTEXT: delegated-identity domain language

## What delegated-identity is

A small library for proving, without a wallet prompt per request, that a request speaks for an Ethereum account in an app. It is shared by every service that checks such requests (missiv, push-notification-server, the trigger service) and by the apps that sign them.

## Core domain terms

- **account**: the wallet's Ethereum address (lowercased), whom a request speaks for.
- **app origin**: the origin of the app the wallet authorized a key for (`https://game.example`, `http://192.168.1.10:5173`); a bare domain names `https://<domain>` (`http://` for localhost) through `fromDomainToOrigin`.
- **delegate key**: a secp256k1 key the app holds for the account (with `@etherplay/connect`, the derived "origin key"); its public key is compressed hex.
- **ownership proof**: the wallet's EIP-191 signature over the publication message naming the delegate key and the app origin. Its text is frozen (byte-identical to `@etherplay/connect-core`'s).
- **request envelope**: what a delegate key signs per request: the purpose line, the server origin, the route, a timestamp, the body's keccak256.
- **server origin**: the origin of the service a request is for; it binds a signature to one service.

## Conventions

- The publication message and the envelope's format are a wire contract: changing either invalidates every signature made over it, so a change is a new purpose line (`... request v2`) accepted beside the old, never an edit.
- Tests open no port and need no network.
