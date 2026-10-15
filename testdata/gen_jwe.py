#!/usr/bin/env python3
"""Makes JWE fixtures independently of ktm, with Python's cryptography
(pip install cryptography): tokens jwe_test.ktm decrypts. Uses the keys
gen.py made (rsa-key.pem, ec-key.pem, ec384-key.pem); run it after gen.py,
from testdata/."""
import base64, hmac, hashlib, json, os, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import padding as sympad

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def key(name): return serialization.load_pem_private_key(open(name, "rb").read(), None)

CEK = {"A128GCM": 16, "A192GCM": 24, "A256GCM": 32, "A128CBC-HS256": 32, "A192CBC-HS384": 48,
       "A256CBC-HS512": 64}

def content(enc, cek, aad, plain):
    if enc.endswith("GCM"):
        iv = os.urandom(12)
        out = AESGCM(cek).encrypt(iv, plain, aad)
        return iv, out[:-16], out[-16:]
    half = len(cek) // 2
    iv = os.urandom(16)
    p = sympad.PKCS7(128).padder()
    data = p.update(plain) + p.finalize()
    e = Cipher(algorithms.AES(cek[half:]), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    h = {"A128CBC-HS256": hashlib.sha256, "A192CBC-HS384": hashlib.sha384, "A256CBC-HS512": hashlib.sha512}[enc]
    tag = hmac.new(cek[:half], aad + iv + ct + struct.pack(">Q", len(aad) * 8), h).digest()[:half]
    return iv, ct, tag

def kdf(z, size, alg_id, apu=b"", apv=b""):
    li = lambda b: struct.pack(">I", len(b)) + b
    other = li(alg_id.encode()) + li(apu) + li(apv) + struct.pack(">I", size * 8)
    return ConcatKDFHash(algorithm=hashes.SHA256(), length=size, otherinfo=other).derive(z)

def jwe(alg, enc, plain, recipient=None, kek=None, cek_dir=None, cty=None, kid=None, apu=b"", apv=b""):
    head = {"alg": alg, "enc": enc}
    if kid: head["kid"] = kid
    if cty: head["cty"] = cty
    size = CEK[enc]
    ek = b""
    if alg == "dir":
        cek = cek_dir
    elif alg.startswith("ECDH-ES"):
        eph = ec.generate_private_key(recipient.curve)
        n = eph.public_key().public_numbers()
        ln = (recipient.curve.key_size + 7) // 8
        head["epk"] = {"kty": "EC", "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[recipient.curve.key_size],
                       "x": b64(n.x.to_bytes(ln, "big")), "y": b64(n.y.to_bytes(ln, "big"))}
        if apu: head["apu"] = b64(apu)
        if apv: head["apv"] = b64(apv)
        z = eph.exchange(ec.ECDH(), recipient)
        if alg == "ECDH-ES":
            cek = kdf(z, size, enc, apu, apv)
        else:
            wrap = kdf(z, 16 if alg.endswith("A128KW") else 32, alg, apu, apv)
            cek = os.urandom(size)
            ek = aes_key_wrap(wrap, cek)
    else:
        cek = os.urandom(size)
        if alg == "RSA-OAEP-256":
            ek = recipient.encrypt(cek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                     label=None))
        else:
            ek = aes_key_wrap(kek, cek)
    h64 = b64(json.dumps(head, separators=(",", ":")).encode())
    iv, ct, tag = content(enc, cek, h64.encode(), plain)
    return ".".join([h64, b64(ek), b64(iv), b64(ct), b64(tag)])

claims = json.dumps({"sub": "py", "iss": "me", "exp": 4102444800}).encode()
rsa = key("rsa-key.pem").public_key()
ec256 = key("ec-key.pem").public_key()
ec384 = key("ec384-key.pem").public_key()
kek256 = bytes(range(32))
dir128 = bytes(range(100, 116))
out = {
    "rsa-oaep-256.A256GCM": jwe("RSA-OAEP-256", "A256GCM", claims, recipient=rsa),
    "ECDH-ES+A128KW.A128CBC-HS256": jwe("ECDH-ES+A128KW", "A128CBC-HS256", claims, recipient=ec256, kid="e1"),
    "ECDH-ES.A256GCM.p384.apu": jwe("ECDH-ES", "A256GCM", claims, recipient=ec384, apu=b"Alice", apv=b"Bob"),
    "A256KW.A256CBC-HS512": jwe("A256KW", "A256CBC-HS512", claims, kek=kek256),
    "dir.A128GCM": jwe("dir", "A128GCM", claims, cek_dir=dir128),
    # a signed token inside: rs256.jwt (openssl's, gen.py)
    "nested.rsa-oaep-256.A128GCM": jwe("RSA-OAEP-256", "A128GCM", open("rs256.jwt").read().strip().encode(),
                                       recipient=rsa, cty="JWT"),
}
for name, tok in out.items():
    open("jwe-" + name + ".txt", "w").write(tok + "\n")
