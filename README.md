# ktm-jwt

JSON Web Tokens for [ktm](https://github.com/ozzenerol/ktm-lang): sign and verify JWTs
(RFC 7519) as JWS compact tokens (RFC 7515), encrypt and decrypt them as JWE (RFC 7516),
with keys from a JWK Set (RFC 7517), given as text or fetched from a URL.

```c
import "github.com/ozzenerol/ktm-jwt";      // the package is named jwt
```

- Signatures: HS256/384/512 (a shared secret), ES256/384/512 (ECDSA P-256, P-384, P-521),
  RS256/384/512 and PS256/384/512 (RSA, PKCS#1 v1.5 and PSS), EdDSA (Ed25519, RFC 8037).
- Encryption (JWE): dir, A128KW/A192KW/A256KW, RSA-OAEP-256, ECDH-ES (+A128KW, +A256KW),
  with A128GCM/A192GCM/A256GCM and A128CBC-HS256/A192CBC-HS384/A256CBC-HS512; a signed
  token inside an encrypted one.
- `crit` header extensions (RFC 7515 4.1.11).
- `exp`, `nbf`, `iat`, `iss` and `aud` checked, with a leeway for clocks that differ.
- JWKS from a URL, fetched again when it is old or a token names a key it doesn't have;
  the fetch waits only the coroutine in a `net.http` handler.
- A `Verifier` is configured once and shared by every thread of a server.
- Needs ktm 0.23 (crypto's Ed25519, P-384/P-521, RSA-PSS and JWE primitives). Written in
  ktm, on the stdlib's `crypto` (mbedTLS, and Monocypher for Ed25519); nothing else to install.

Get it with `ktm get github.com/ozzenerol/ktm-jwt@v0.2.0`.

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
| `jwt.es384(key, kid = "")`, `es512` | A private P-384 or P-521 key (`crypto.generateKey(crypto.KeyKind.ec384)`, `ec521`) |
| `jwt.rs256(key, kid = "")`, `rs384`, `rs512` | A private RSA `crypto.Key` of 2048 bits or more |
| `jwt.ps256(key, kid = "")`, `ps384`, `ps512` | The same RSA key, signing with PSS (randomised: two tokens of the same claims differ) |
| `jwt.eddsa(key, kid = "")` | A private Ed25519 key (`crypto.generateKey(crypto.KeyKind.ed25519)`) |

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
| `v.es256(key, kid = "")`, `es384`, `es512` | ES tokens of this P-256, P-384 or P-521 key (public or private) |
| `v.rs256(key, kid = "")`, `rs384`, `rs512`, `ps256`, `ps384`, `ps512` | RSA tokens of this key |
| `v.eddsa(key, kid = "")` | EdDSA tokens of this Ed25519 key |
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
- Keys used: `"kty": "EC"` with `"crv"` P-256, P-384 or P-521 (ES256, ES384, ES512),
  `"kty": "OKP"` with `"crv": "Ed25519"` (EdDSA), and `"kty": "RSA"` (its `"alg"`: RS* or
  PS*, RS256 when it has none). A key whose `"alg"` disagrees with its curve or kind, one
  claiming an HMAC `"alg"`, `oct` keys and `"use": "enc"` keys are skipped.

## Header extensions (crit)

```c
ad jwt.Signer *s = jwt.es256(key);
s.header("tenant", "\"acme\"", true);          // a JSON value; true: listed in "crit"

ad jwt.Verifier *v = jwt.verifier();
v.es256(key);
v.understand("tenant");                         // without it, the token is refused
Claims c = v.verify<Claims>(token);
String tenant = jwt.headerValue(token, "tenant");   // "\"acme\"", after verify
```

A token whose `crit` lists a name the Verifier wasn't told it understands is refused
(`ERR_MALFORMED`), as RFC 7515 says it must be; so is a `crit` that is empty, lists a header
the specs define, or a name the header hasn't. `"b64"` (RFC 7797, unencoded payloads)
isn't supported.

## Encrypted tokens (JWE)

```c
// the sender: sign, then encrypt to the recipient's public key
ad jwt.Signer *s = jwt.es256(myKey);
ad jwt.Encrypter *e = jwt.rsaOaep256(jwt.Enc.a256gcm, theirKey);
String token = e.encryptToken(s.sign(claims));     // "cty": "JWT"

// the recipient: one Verifier decrypts and checks the signature inside
ad jwt.Verifier *v = jwt.verifier();
v.rsaOaep256(myPrivateKey);
v.es256(sendersKey);
Claims c = v.verify<Claims>(token);
```

| Encrypter | Key |
|---|---|
| `jwt.dir(enc, key, kid = "")` | A shared key of the enc's size: 16/24/32 bytes for A*GCM, 32/48/64 for A*CBC-HS* |
| `jwt.a128kw(enc, kek, kid = "")`, `a192kw`, `a256kw` | A shared key-wrapping key of 16, 24 or 32 bytes |
| `jwt.rsaOaep256(enc, key, kid = "")` | The recipient's RSA key (public is enough) |
| `jwt.ecdhEs(enc, key, kid = "")`, `ecdhEsA128kw`, `ecdhEsA256kw` | The recipient's EC key, P-256, P-384 or P-521 |

`enc` is a `jwt.Enc`: `a128gcm`, `a192gcm`, `a256gcm`, `a128cbcHs256`, `a192cbcHs384`,
`a256cbcHs512`. `e.encrypt(claims)` encrypts claims themselves; `e.encryptToken(jws)` a
signed token. The Verifier decrypts with `v.dir(key)`, `v.a128kw(kek)` ..., `v.rsaOaep256(key)`,
`v.ecdhEs(key)`, `v.ecdhEsA128kw(key)`, `v.ecdhEsA256kw(key)` (private keys), chosen as signing
keys are: by `kid` first, else every key of the token's `alg`. `jwt.jwksKey(jwks, kid)` finds
a recipient's public key in their JWK Set.

- A token whose `cty` is `JWT` holds a signed token: it is verified with the Verifier's
  signing keys, and its claims are the result.
- One that holds claims, not a signed token, is taken when it was made with a shared key
  (`dir`, `A*KW`): whoever made it holds the key, as with HS256. With RSA-OAEP-256 or ECDH-ES
  anyone who has the public key can make one, so it proves nothing about who did: it is
  refused (`ERR_SIGNATURE`) unless `v.allowUnsignedJwe = true`, for when encryption alone
  is what you want.
- A wrong key and an altered token give the same `ERR_SIGNATURE`, with no detail. The CBC-HS
  tag is checked, in constant time, before anything is decrypted.
- The ephemeral key of ECDH-ES must be on the key's curve (`ERR_KEY` otherwise).
- Not taken: RSA1_5 (padding oracles), RSA-OAEP with SHA-1, A*GCMKW, PBES2, compressed
  tokens (`"zip"`), the JSON serialization: `ERR_ALG` or `ERR_MALFORMED`.

## Errors

Every failure throws, with a message saying what was wrong:

| Code | When |
|---|---|
| `jwt.ERR_MALFORMED` | Not a token: three (or five) base64url parts (unpadded), a JSON header and payload; a `crit` not understood |
| `jwt.ERR_ALG` | `alg` is `"none"` or not taken, no key of that `alg` is trusted, an `enc` not taken, `zip` |
| `jwt.ERR_KEY` | No key with the token's `kid`; a bad key; a JWKS that can't be had |
| `jwt.ERR_SIGNATURE` | The signature doesn't match, or a JWE doesn't decrypt: forged, altered, another key; a public-key JWE without a signed token |
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

`jwt.header(token)` (alg, typ, kid; enc and cty of a JWE), `jwt.headerValue(token, name)` and
`jwt.decodeUnverified<T>(token)` (a JWS's) read a token without checking it: to log it or to
choose a key, never to trust what it says.

## Not here (yet)

Ed448, ES256K (secp256k1), the JWE algorithms listed above as not taken, unencoded
payloads (`b64`), and the JSON serializations of JWS and JWE.

## Tests

```sh
ktm test .                  # compiled
ktm test -jit -Memsafe .    # the JIT, with memory checks
```

They cover RFC 7515's HS256 example, RFC 8037's EdDSA one, RFC 7516 A.3 (A128KW with
A128CBC-HS256) and RFC 7518 C (ECDH-ES's key); tokens openssl signed (every signing alg but
HS*, `testdata/gen.py`) and tokens Python's `cryptography` encrypted (`testdata/gen_jwe.py`);
every JWE alg with every enc, both ways and nested; tampering of each part; `alg` attacks,
`kid`, `crit`, every claim, malformed tokens, and a JWK Set served over HTTP while threads
verify and the set changes.

## License

BSD 2-Clause, as ktm.
