# ktm-jwt

JSON Web Tokens for [ktm](https://github.com/ozzenerol/ktm-lang): sign and verify JWTs
(RFC 7519) as JWS compact tokens (RFC 7515), with keys from a JWK Set (RFC 7517), given
as text or fetched from a URL.

```c
import "github.com/ozzenerol/ktm-jwt";      // the package is named jwt
```

- HS256, HS384, HS512 (a shared secret), ES256 (ECDSA P-256), RS256, RS384, RS512 (RSA).
- `exp`, `nbf`, `iat`, `iss` and `aud` checked, with a leeway for clocks that differ.
- JWKS from a URL, fetched again when it is old or a token names a key it doesn't have;
  the fetch waits only the coroutine in a `net.http` handler.
- A `Verifier` is configured once and shared by every thread of a server.
- Needs ktm 0.22 (crypto's RSA keys and JWK parts). Written in ktm, on the stdlib's
  `crypto` (mbedTLS); nothing else to install.

Get it with `ktm get github.com/ozzenerol/ktm-jwt@v0.1.0`.

## Signing

```c
import "github.com/ozzenerol/ktm-jwt";
import date, json, reflect, str;

@json struct Claims { String sub; i64 exp; String role; };

i32 main()
{
    ad jwt.Signer *s = jwt.hs256("a secret of 32 bytes or more....");
    Claims c;
    c.sub = str.from("42");
    c.exp = date.unixNow() + 3600;
    c.role = str.from("admin");
    String token = s.sign(c);               // header.payload.signature, a new String
    printf("%.*s\n", token.len, token.ptr);
    json.free(reflect.of(c));
    token.free();
    return 0;
}
```

The claims are any `@json` struct. `sign` infers its type from the argument
(`s.sign<Claims>(c)` says it out loud).

| Signer | Key |
|---|---|
| `jwt.hs256(secret, kid = "")`, `hs384`, `hs512` | A shared secret, copied: 32 random bytes or more |
| `jwt.es256(key, kid = "")` | A private P-256 `crypto.Key` (`crypto.generateKey()`, `crypto.privateKey(pem)`) |
| `jwt.rs256(key, kid = "")`, `rs384`, `rs512` | A private RSA `crypto.Key` of 2048 bits or more |

A `crypto.Key` stays yours: keep it while the Signer (or Verifier) uses it, free it after.
With a `kid`, the header carries it, so a verifier with several keys knows which one.

## Verifying

```c
ad jwt.Verifier *v = jwt.verifier();
v.hs256("a secret of 32 bytes or more....");
v.issuer = "https://auth.example.com";      // optional: iss must be this
v.audience = "api";                         // optional: aud must hold this
Claims c = v.verify<Claims>(token);         // throws jwt.ERR_* when it isn't good
```

`verify` checks, in order: the token's form, its `alg` against the keys trusted, the
signature, then the claims, and returns them decoded into `T`. `v.valid(token)` does the
same without the claims and says true or false.

| Field | Default | What |
|---|---|---|
| `issuer` | `""` (not checked) | `iss` must equal it |
| `audience` | `""` (not checked) | `aud` (a string, or an array) must hold it |
| `leewaySec` | 60 | Seconds a clock may be off, for `exp`, `nbf` and `iat` |
| `requireExp` | true | A token without `exp` is refused |
| `jwksRetrySec` | 60 | An unknown `kid` fetches the JWKS again at most this often |
| `now` | 0 (the clock) | The time, in Unix seconds: for tests |

`issuer` and `audience` are views: the text must outlive the Verifier (a literal does).

### Which key checks a token

- A token with a `kid` is checked only with the key that has that `kid`. A `kid` no key
  has is an error (`ERR_KEY`), after one fetch of the JWKS when there is a URL.
- A token without a `kid` is checked with each key whose algorithm is the header's `alg`,
  until one matches.
- `alg` must be exactly the key's: `"none"`, an `alg` no key has, or a key of another kind
  (an HMAC secret for an RS256 token, or the reverse) is `ERR_ALG`. So a public RSA key
  can't be used as an HMAC secret, the old algorithm-confusion attack.
- ES256 signatures are the 64 bytes r||s the standard says; the DER form is refused.

| Trust | |
|---|---|
| `v.hs256(secret, kid = "")`, `hs384`, `hs512` | Tokens made with this secret (copied) |
| `v.es256(key, kid = "")` | ES256 tokens of this P-256 key (public or private) |
| `v.rs256(key, kid = "")`, `rs384`, `rs512` | RSA tokens of this key |
| `v.jwks(text)` | The keys of a JWK Set, JSON text |
| `v.jwksUrl(url, refreshSec = 3600)` | The JWK Set at `url`, kept fresh |

Configure a Verifier before it verifies; after that `verify` can run in many threads at once.

## A JWK Set

```c
ad jwt.Verifier *v = jwt.verifier();
v.jwksUrl("https://auth.example.com/.well-known/jwks.json");
v.issuer = "https://auth.example.com";
v.audience = "my-api";
```

- `jwksUrl` fetches the set at once, so a wrong URL fails early (`ERR_KEY`).
- It is fetched again after `refreshSec`, and when a token's `kid` isn't in it (at most every
  `jwksRetrySec`). A fetch that fails keeps the keys there were.
- The fetch happens inside `verify` and waits for the answer. In a loop coroutine (a
  `net.http` handler, `coro.go`) only that coroutine waits; on a plain thread the thread does.
- Keys used: `"kty": "EC"` with `"crv": "P-256"` (ES256), and `"kty": "RSA"` (its `"alg"`, or
  RS256 when it has none). Others (`oct`, P-384, Ed25519, `"use": "enc"`) are skipped.

## Errors

Every failure throws, with a message saying what was wrong:

| Code | When |
|---|---|
| `jwt.ERR_MALFORMED` | Not a token: three base64url parts (unpadded), a JSON header and payload; a `crit` header |
| `jwt.ERR_ALG` | `alg` is `"none"`, or no key of that `alg` is trusted |
| `jwt.ERR_KEY` | No key with the token's `kid`; a bad key; a JWKS that can't be had |
| `jwt.ERR_SIGNATURE` | The signature doesn't match: forged or altered |
| `jwt.ERR_EXPIRED` | `exp` has passed |
| `jwt.ERR_NOT_YET` | `nbf` is still to come, or `iat` is in the future |
| `jwt.ERR_CLAIM` | `iss` or `aud` aren't as configured, `exp` is missing, or the claims don't fit `T` |

An HTTP handler usually answers 401 to all of them.

```c
try {
    Claims c = v.verify<Claims>(token);
    ...
} catch (Error e) {
    if (e.code == jwt.ERR_EXPIRED) { ... }   // ask for a new token
}
```

## Reading without verifying

`jwt.header(token)` (alg, typ, kid) and `jwt.decodeUnverified<T>(token)` read a token
without checking it: to log it or to choose a key, never to trust what it says.

## Not here (yet)

EdDSA (Ed25519; planned for 0.2.0: mbedTLS has no Ed25519), ES384/ES512, PS256, JWE
(encrypted tokens) and `crit` header extensions.

## Tests

```sh
ktm test .                  # compiled
ktm test -jit -Memsafe .    # the JIT, with memory checks
```

They cover RFC 7515's HS256 example, tokens openssl signed (RS256/384/512 and ES256,
`testdata/`, remade by `testdata/gen.py`), tampering, `alg` attacks, `kid`, every claim,
malformed tokens, and a JWK Set served over HTTP while threads verify and the set changes.

## License

BSD 2-Clause, as ktm.
