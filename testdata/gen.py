#!/usr/bin/env python3
"""Makes the test fixtures with openssl, independently of ktm: keys, a JWKS
of their public parts, and RS256/384/512 and ES256 tokens openssl signed.
Run it from testdata/ (python3 gen.py); it overwrites what is here."""
import base64, json, re, subprocess

def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout

def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "rsa-key.pem")
run("openssl", "pkey", "-in", "rsa-key.pem", "-pubout", "-out", "rsa-pub.pem")
run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "ec-key.pem")
run("openssl", "pkey", "-in", "ec-key.pem", "-pubout", "-out", "ec-pub.pem")

n = bytes.fromhex(run("openssl", "rsa", "-pubin", "-in", "rsa-pub.pem", "-noout", "-modulus")
                  .decode().strip().split("=")[1])
text = run("openssl", "ec", "-pubin", "-in", "ec-pub.pem", "-noout", "-text").decode()
point = bytes.fromhex(re.sub(r"[\s:]", "", text.split("pub:")[1].split("ASN1")[0]))
assert point[0] == 4 and len(point) == 65
jwks = {"keys": [
    {"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256", "n": b64(n), "e": "AQAB"},
    {"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64(point[1:33]), "y": b64(point[33:])},
    {"kty": "oct", "kid": "sym", "k": "c2VjcmV0"},
    {"kty": "EC", "kid": "p384", "crv": "P-384", "x": "AA", "y": "AA"},
    {"kty": "RSA", "kid": "enc1", "use": "enc", "n": b64(n), "e": "AQAB"},
]}
open("jwks.json", "w").write(json.dumps(jwks, indent=1) + "\n")

claims = {"sub": "ext", "iss": "https://issuer.example", "aud": ["api", "other"],
          "iat": 1700000000, "exp": 4102444800}

def der_to_raw(der):
    # SEQUENCE { INTEGER r, INTEGER s } -> r || s, 32 bytes each
    assert der[0] == 0x30
    i = 2
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        ln = der[i + 1]
        v = der[i + 2:i + 2 + ln].lstrip(b"\0")
        out += v.rjust(32, b"\0")
        i += 2 + ln
    return out

for alg, key, kid in [("RS256", "rsa-key.pem", "rsa1"), ("RS384", "rsa-key.pem", None),
                      ("RS512", "rsa-key.pem", None), ("ES256", "ec-key.pem", "ec1")]:
    head = {"alg": alg, "typ": "JWT"}
    if kid:
        head["kid"] = kid
    signing = b64(json.dumps(head, separators=(",", ":")).encode()) + "." + \
        b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = run("openssl", "dgst", "-sha" + alg[2:], "-sign", key, data=signing.encode())
    if alg == "ES256":
        sig = der_to_raw(sig)
        open("es256-der.jwt", "w").write(signing + "." + b64(run(
            "openssl", "dgst", "-sha256", "-sign", key, data=signing.encode())) + "\n")
    open(alg.lower() + ".jwt", "w").write(signing + "." + b64(sig) + "\n")
