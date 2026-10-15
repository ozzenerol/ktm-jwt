# Changelog

## v0.1.0 (2026-10-15)

The first release: JSON Web Tokens for ktm, written in ktm on the stdlib's `crypto`.

- Signing: HS256/384/512, ES256, RS256/384/512; any `@json` struct as the claims; `kid`.
- Verifying: `Verifier.verify<T>` and `valid`; `exp`, `nbf`, `iat` with a leeway, `iss`,
  `aud` (a string or an array); keys chosen by `kid`, else by `alg`; `alg` must be the
  key's exactly (`"none"` and algorithm confusion refused).
- JWK Sets as text or from a URL: fetched at once, again after `refreshSec` and on an
  unknown `kid` (at most every `jwksRetrySec`), waiting only the coroutine in a handler;
  safe while other threads verify.
- `jwt.header` and `jwt.decodeUnverified<T>` read tokens without checking them.
- Errors: `ERR_MALFORMED`, `ERR_ALG`, `ERR_KEY`, `ERR_SIGNATURE`, `ERR_EXPIRED`,
  `ERR_NOT_YET`, `ERR_CLAIM`.
- Needs ktm 0.22.
