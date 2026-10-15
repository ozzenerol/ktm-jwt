#!/usr/bin/env python3
"""Makes the test fixtures with openssl, independently of ktm: keys, a JWKS
of their public parts, and RS256/384/512, ES256/384/512, PS256 and EdDSA
tokens openssl signed.
Run it from testdata/ (python3 gen.py); it overwrites what is here."""
import base64, json, os, re, subprocess

def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout

def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "rsa-key.pem")
run("openssl", "pkey", "-in", "rsa-key.pem", "-pubout", "-out", "rsa-pub.pem")
run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "ec-key.pem")
run("openssl", "pkey", "-in", "ec-key.pem", "-pubout", "-out", "ec-pub.pem")
for curve, name in [("P-384", "ec384"), ("P-521", "ec521")]:
    run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve, "-out", name + "-key.pem")
    run("openssl", "pkey", "-in", name + "-key.pem", "-pubout", "-out", name + "-pub.pem")
run("openssl", "genpkey", "-algorithm", "ED25519", "-out", "ed-key.pem")
run("openssl", "pkey", "-in", "ed-key.pem", "-pubout", "-out", "ed-pub.pem")

n = bytes.fromhex(run("openssl", "rsa", "-pubin", "-in", "rsa-pub.pem", "-noout", "-modulus")
                  .decode().strip().split("=")[1])
def ec_point(pem, n):
    text = run("openssl", "ec", "-pubin", "-in", pem, "-noout", "-text").decode()
    pt = bytes.fromhex(re.sub(r"[\s:]", "", text.split("pub:")[1].split("ASN1")[0]))
    assert pt[0] == 4 and len(pt) == 1 + 2 * n
    return pt[1:1 + n], pt[1 + n:]

point = b"\x04" + b"".join(ec_point("ec-pub.pem", 32))
x384, y384 = ec_point("ec384-pub.pem", 48)
x521, y521 = ec_point("ec521-pub.pem", 66)
ed_x = run("openssl", "pkey", "-pubin", "-in", "ed-pub.pem", "-outform", "DER")[-32:]
jwks = {"keys": [
    {"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256", "n": b64(n), "e": "AQAB"},
    {"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64(point[1:33]), "y": b64(point[33:])},
    {"kty": "oct", "kid": "sym", "k": "c2VjcmV0"},
    {"kty": "EC", "kid": "p384", "crv": "P-384", "x": "AA", "y": "AA"},
    {"kty": "RSA", "kid": "enc1", "use": "enc", "n": b64(n), "e": "AQAB"},
    {"kty": "EC", "kid": "ec384", "crv": "P-384", "x": b64(x384), "y": b64(y384)},
    {"kty": "EC", "kid": "ec521", "crv": "P-521", "alg": "ES512", "x": b64(x521), "y": b64(y521)},
    {"kty": "OKP", "kid": "ed1", "crv": "Ed25519", "x": b64(ed_x)},
    {"kty": "RSA", "kid": "pss1", "alg": "PS256", "n": b64(n), "e": "AQAB"},
    {"kty": "RSA", "kid": "hs-on-rsa", "alg": "HS256", "n": b64(n), "e": "AQAB"},
    {"kty": "EC", "kid": "lying", "crv": "P-384", "alg": "ES256", "x": b64(x384), "y": b64(y384)},
]}
open("jwks.json", "w").write(json.dumps(jwks, indent=1) + "\n")

claims = {"sub": "ext", "iss": "https://issuer.example", "aud": ["api", "other"],
          "iat": 1700000000, "exp": 4102444800}

def der_to_raw(der, n=32):
    # SEQUENCE { INTEGER r, INTEGER s } -> r || s, n bytes each
    assert der[0] == 0x30
    i = 2 if der[1] < 0x80 else 3
    out = b""
    for _ in range(2):
        assert der[i] == 0x02
        ln = der[i + 1]
        v = der[i + 2:i + 2 + ln].lstrip(b"\0")
        out += v.rjust(n, b"\0")
        i += 2 + ln
    return out

for alg, key, kid in [("RS256", "rsa-key.pem", "rsa1"), ("RS384", "rsa-key.pem", None),
                      ("RS512", "rsa-key.pem", None), ("ES256", "ec-key.pem", "ec1"),
                      ("ES384", "ec384-key.pem", "ec384"), ("ES512", "ec521-key.pem", "ec521"),
                      ("PS256", "rsa-key.pem", "pss1"), ("EdDSA", "ed-key.pem", "ed1")]:
    head = {"alg": alg, "typ": "JWT"}
    if kid:
        head["kid"] = kid
    signing = b64(json.dumps(head, separators=(",", ":")).encode()) + "." + \
        b64(json.dumps(claims, separators=(",", ":")).encode())
    if alg == "EdDSA":
        open("ed-in.bin", "wb").write(signing.encode())
        sig = run("openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", "ed-in.bin")
        os.remove("ed-in.bin")
    elif alg.startswith("PS"):
        sig = run("openssl", "dgst", "-sha" + alg[2:], "-sigopt", "rsa_padding_mode:pss",
                  "-sigopt", "rsa_pss_saltlen:digest", "-sign", key, data=signing.encode())
    else:
        sig = run("openssl", "dgst", "-sha" + alg[2:], "-sign", key, data=signing.encode())
    if alg in ("ES384", "ES512"):
        sig = der_to_raw(sig, 48 if alg == "ES384" else 66)
    if alg == "ES256":
        sig = der_to_raw(sig)
        open("es256-der.jwt", "w").write(signing + "." + b64(run(
            "openssl", "dgst", "-sha256", "-sign", key, data=signing.encode())) + "\n")
    open(alg.lower() + ".jwt", "w").write(signing + "." + b64(sig) + "\n")
