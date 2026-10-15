# Changelog

## v0.2.0

- EdDSA (Ed25519, RFC 8037), ES384 and ES512 (P-384, P-521), PS256/384/512 (RSA-PSS):
  Signers, Verifier keys, and JWKS keys (`OKP`/Ed25519, P-384/P-521 curves, `PS*` RSA keys).
  A JWK that claims an HMAC `alg` is skipped.
- JWE (RFC 7516), compact: dir, A128KW/A192KW/A256KW, RSA-OAEP-256, ECDH-ES,
  ECDH-ES+A128KW, ECDH-ES+A256KW with A128GCM/A192GCM/A256GCM and
  A128CBC-HS256/A192CBC-HS384/A256CBC-HS512. `jwt.Encrypter` (`encrypt`, `encryptToken`),
  decryption through the Verifier, signed tokens nested in encrypted ones (`cty` JWT).
  A public-key JWE holding claims, not a signed token, is refused unless
  `Verifier.allowUnsignedJwe`.
- `crit` (RFC 7515 4.1.11): `Signer.header(name, json, critical)`, `Verifier.understand(name)`,
  `jwt.headerValue(token, name)`. A token with a `crit` header was refused outright before.
- `jwt.jwksKey(jwks, kid)`: a recipient's public key from their JWK Set.
- `Header` has `enc` and `cty`.
- Needs ktm 0.23.

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
