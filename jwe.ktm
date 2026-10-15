module jwt;
import crypto, encoding.base64, json, mem, reflect, str;

/* Encrypted tokens: JWE (RFC 7516), compact serialization, with JWA's
 * (RFC 7518) key management dir, A128KW, A192KW, A256KW, RSA-OAEP-256,
 * ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A256KW and content encryption A128GCM,
 * A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512.
 *
 *   scoped jwt.Encrypter *e = jwt.rsaOaep256(jwt.Enc.a256gcm, theirPublicKey);
 *   String token = e.encryptToken(signedToken);     // a JWS inside
 *
 *   v.rsaOaep256(myPrivateKey);                      // the Verifier decrypts
 *   Claims c = v.verify<Claims>(token);
 *
 * A Verifier decrypts with the keys given to dir(), a128kw() ...; a token
 * whose "cty" is "JWT" holds a signed token, verified with its signing
 * keys. One without a signed token inside is only taken with a key of
 * dir or A*KW (whoever made it holds the key), unless allowUnsignedJwe:
 * anyone can encrypt to a public key. */

/* The content encryption */
pub enum Enc {
    a128gcm,            /* A128GCM */
    a192gcm,            /* A192GCM */
    a256gcm,            /* A256GCM */
    a128cbcHs256,       /* A128CBC-HS256 */
    a192cbcHs384,       /* A192CBC-HS384 */
    a256cbcHs512        /* A256CBC-HS512 */
};

/* The key management */
enum KAlg { dir, a128kw, a192kw, a256kw, rsaOaep256, ecdhEs, ecdhEsA128kw, ecdhEsA256kw };

static u8 *kalgName(KAlg a) {
    if (a == KAlg.dir) { return "dir"; }
    if (a == KAlg.a128kw) { return "A128KW"; }
    if (a == KAlg.a192kw) { return "A192KW"; }
    if (a == KAlg.a256kw) { return "A256KW"; }
    if (a == KAlg.rsaOaep256) { return "RSA-OAEP-256"; }
    if (a == KAlg.ecdhEs) { return "ECDH-ES"; }
    if (a == KAlg.ecdhEsA128kw) { return "ECDH-ES+A128KW"; }
    return "ECDH-ES+A256KW";
}

static bool kalgOf(u8[] name, KAlg *out) {
    for (i64 i = 0; i <= (i64)KAlg.ecdhEsA256kw; i++) {
        if (str.equals(name, cstrView(kalgName((KAlg)i)))) {
            *out = (KAlg)i;
            return true;
        }
    }
    return false;
}

static u8 *encName(Enc e) {
    if (e == Enc.a128gcm) { return "A128GCM"; }
    if (e == Enc.a192gcm) { return "A192GCM"; }
    if (e == Enc.a256gcm) { return "A256GCM"; }
    if (e == Enc.a128cbcHs256) { return "A128CBC-HS256"; }
    if (e == Enc.a192cbcHs384) { return "A192CBC-HS384"; }
    return "A256CBC-HS512";
}

static bool encOf(u8[] name, Enc *out) {
    for (i64 i = 0; i <= (i64)Enc.a256cbcHs512; i++) {
        if (str.equals(name, cstrView(encName((Enc)i)))) {
            *out = (Enc)i;
            return true;
        }
    }
    return false;
}

static bool isGcm(Enc e) {
    return e == Enc.a128gcm || e == Enc.a192gcm || e == Enc.a256gcm;
}

/* The content encryption key's size in bytes (CBC-HS: the MAC key and
 * the AES key together) */
static i64 cekSize(Enc e) {
    if (e == Enc.a128gcm) { return 16; }
    if (e == Enc.a192gcm) { return 24; }
    if (e == Enc.a256gcm || e == Enc.a128cbcHs256) { return 32; }
    if (e == Enc.a192cbcHs384) { return 48; }
    return 64;
}

/* A key-wrapping key's size for alg (A*KW, ECDH-ES+A*KW), 0 for others */
static i64 kekSize(KAlg a) {
    if (a == KAlg.a128kw || a == KAlg.ecdhEsA128kw) { return 16; }
    if (a == KAlg.a192kw) { return 24; }
    if (a == KAlg.a256kw || a == KAlg.ecdhEsA256kw) { return 32; }
    return 0;
}

static bool isEcdh(KAlg a) {
    return a == KAlg.ecdhEs || a == KAlg.ecdhEsA128kw || a == KAlg.ecdhEsA256kw;
}

/* by a public key: anyone can make such a token */
static bool isPublicKeyAlg(KAlg a) {
    return a == KAlg.rsaOaep256 || isEcdh(a);
}

/* ---- the content: AES-GCM, or AES-CBC + HMAC (RFC 7518 5.2) ---- */

/* the CBC-HS tag: the first half of HMAC(macKey, aad || iv || ct || AL) */
static String cbcTag(Enc e, u8[] macKey, u8[] aad, u8[] iv, u8[] ct) {
    String m;
    m.append(aad);
    m.append(iv);
    m.append(ct);
    u64 bits = (u64)aad.len * 8;
    for (i64 i = 7; i >= 0; i--) { m.appendByte((u8)(bits >> (8 * i))); }
    u8 mac[64];
    i64 n = 32;
    if (e == Enc.a128cbcHs256) {
        crypto.hmacSha256(macKey, m[0:], mac[0:32]);
    } else if (e == Enc.a192cbcHs384) {
        n = 48;
        crypto.hmacSha384(macKey, m[0:], mac[0:48]);
    } else {
        n = 64;
        crypto.hmacSha512(macKey, m[0:], mac[0:64]);
    }
    m.free();
    return str.from(mac[0:n / 2]);
}

/* plain encrypted with cek: *iv, *ct and *tag (replaced) */
static void contentEncrypt(Enc e, u8[] cek, u8[] aad, u8[] plain, String *iv, String *ct, String *tag) {
    iv.free();
    ct.free();
    tag.free();
    if (isGcm(e)) {
        u8 nonce[12];
        crypto.random(nonce[0:12]);
        *iv = str.from(nonce[0:12]);
        String sealed = crypto.seal(crypto.Aead.aesGcm, cek, nonce[0:12], plain, aad);
        *ct = str.from(sealed[0:sealed.len - 16]);
        *tag = str.from(sealed[sealed.len - 16:]);
        sealed.free();
        return;
    }
    i64 half = cek.len / 2;
    u8 nonce[16];
    crypto.random(nonce[0:16]);
    *iv = str.from(nonce[0:16]);
    *ct = crypto.aesCbcEncrypt(cek[half:], nonce[0:16], plain);
    *tag = cbcTag(e, cek[0:half], aad, nonce[0:16], ct.ptr[0:ct.len]);
}

/* ct decrypted with cek into *plain: false when it doesn't authenticate
 * (the MAC is checked first, in constant time) */
static bool contentDecrypt(Enc e, u8[] cek, u8[] aad, u8[] iv, u8[] ct, u8[] tag, String *plain) {
    plain.clear();
    if (cek.len != cekSize(e)) { return false; }
    if (isGcm(e)) {
        if (iv.len != 12 || tag.len != 16) { return false; }
        String sealed = str.from(ct);
        sealed.append(tag);
        bool ok = crypto.open(crypto.Aead.aesGcm, cek, iv, sealed[0:], plain, aad);
        sealed.free();
        return ok;
    }
    i64 half = cek.len / 2;
    if (iv.len != 16 || tag.len != half) { return false; }
    String want = cbcTag(e, cek[0:half], aad, iv, ct);
    bool ok = crypto.equal(want[0:], tag);
    want.free();
    if (!ok) { return false; }
    return crypto.aesCbcDecrypt(cek[half:], iv, ct, plain);
}

/* ---- ECDH-ES's key: Concat KDF (NIST SP 800-56A, RFC 7518 4.6.2) ---- */

static void putLen(String *s, i64 n) {
    s.appendByte((u8)(n >> 24));
    s.appendByte((u8)(n >> 16));
    s.appendByte((u8)(n >> 8));
    s.appendByte((u8)n);
}

/* size bytes of key from the shared secret z: algId is "enc" for
 * ECDH-ES, "alg" for ECDH-ES+A*KW; apu and apv (the header's, decoded) */
static String concatKdf(u8[] z, i64 size, u8[] algId, u8[] apu, u8[] apv) {
    String other;
    putLen(&other, algId.len);
    other.append(algId);
    putLen(&other, apu.len);
    other.append(apu);
    putLen(&other, apv.len);
    other.append(apv);
    putLen(&other, size * 8);
    String out;
    u8 h[32];
    for (i64 round = 1; out.len < size; round++) {
        String in;
        putLen(&in, round);
        in.append(z);
        in.append(other[0:]);
        crypto.sha256(in[0:], h[0:32]);
        mem.set(in.ptr, 0, in.len);
        in.free();
        i64 take = size - out.len < 32 ? size - out.len : 32;
        out.append(h[0:take]);
    }
    mem.set(h, 0, 32);
    other.free();
    return out;
}

/* ---- encrypting ---- */

/* What makes encrypted tokens: one key management, one content
 * encryption, one key */
pub struct Encrypter {
    private KAlg alg;
    private Enc enc;
    private String kid;
    private String key;             /* dir: the key; A*KW: the kek (copies) */
    private crypto.Key *recipient;  /* RSA-OAEP-256, ECDH-ES: theirs, still yours */
};

static Encrypter *encrypterNew(KAlg a, Enc e, u8[] key, crypto.Key *recipient, u8[] kid) {
    Encrypter *x = mem.allocZero(sizeof(Encrypter));
    x.alg = a;
    x.enc = e;
    x.key = str.from(key);
    x.recipient = recipient;
    x.kid = str.from(kid);
    return x;
}

static void needSize(u8[] key, i64 n, u8 *what) {
    if (key.len != n) { throw(ERR_KEY, "jwt: %s is %d bytes, not %d", what, n, key.len); }
}

/* dir: the content encrypted with key itself (shared; its size is the
 * enc's: 16, 24 or 32 bytes for A128GCM..., 32, 48, 64 for
 * A128CBC-HS256...) */
pub Encrypter *dir(Enc enc, u8[] key, u8[] kid = "") {
    needSize(key, cekSize(enc), "a dir key for that enc");
    return encrypterNew(KAlg.dir, enc, key, null, kid);
}

/* A128KW, A192KW, A256KW: a new content key each token, wrapped with kek
 * (shared: 16, 24 or 32 bytes) */
pub Encrypter *a128kw(Enc enc, u8[] kek, u8[] kid = "") {
    needSize(kek, 16, "an A128KW key");
    return encrypterNew(KAlg.a128kw, enc, kek, null, kid);
}

pub Encrypter *a192kw(Enc enc, u8[] kek, u8[] kid = "") {
    needSize(kek, 24, "an A192KW key");
    return encrypterNew(KAlg.a192kw, enc, kek, null, kid);
}

pub Encrypter *a256kw(Enc enc, u8[] kek, u8[] kid = "") {
    needSize(kek, 32, "an A256KW key");
    return encrypterNew(KAlg.a256kw, enc, kek, null, kid);
}

/* RSA-OAEP-256: a new content key each token, encrypted to key (the
 * recipient's RSA key; public is enough, and it stays yours) */
pub Encrypter *rsaOaep256(Enc enc, crypto.Key *key, u8[] kid = "") {
    if (!key || key.kind() != crypto.KeyKind.rsa) { throw(ERR_KEY, "jwt: RSA-OAEP-256 needs an RSA key"); }
    return encrypterNew(KAlg.rsaOaep256, enc, "", key, kid);
}

static bool isEcKey(crypto.Key *key) {
    if (!key) { return false; }
    crypto.KeyKind k = key.kind();
    return k == crypto.KeyKind.ec256 || k == crypto.KeyKind.ec384 || k == crypto.KeyKind.ec521;
}

static Encrypter *ecdhEncrypter(KAlg a, Enc enc, crypto.Key *key, u8[] kid) {
    if (!isEcKey(key)) { throw(ERR_KEY, "jwt: %s needs an EC key (P-256, P-384, P-521)", kalgName(a)); }
    return encrypterNew(a, enc, "", key, kid);
}

/* ECDH-ES: the content key agreed with key (the recipient's EC key,
 * P-256, P-384 or P-521) and a new ephemeral key each token; with
 * +A128KW / +A256KW the agreed key wraps a new content key */
pub Encrypter *ecdhEs(Enc enc, crypto.Key *key, u8[] kid = "") {
    return ecdhEncrypter(KAlg.ecdhEs, enc, key, kid);
}

pub Encrypter *ecdhEsA128kw(Enc enc, crypto.Key *key, u8[] kid = "") {
    return ecdhEncrypter(KAlg.ecdhEsA128kw, enc, key, kid);
}

pub Encrypter *ecdhEsA256kw(Enc enc, crypto.Key *key, u8[] kid = "") {
    return ecdhEncrypter(KAlg.ecdhEsA256kw, enc, key, kid);
}

static u8 *crvName(crypto.KeyKind k) {
    if (k == crypto.KeyKind.ec384) { return "P-384"; }
    if (k == crypto.KeyKind.ec521) { return "P-521"; }
    return "P-256";
}

/* A token of plain, cty "JWT" when nested */
static String jweSeal(Encrypter *x, u8[] plain, bool nested) {
    String head, cek, ek;
    head.append("{\"alg\":\"");
    head.append(cstrView(kalgName(x.alg)));
    head.append("\",\"enc\":\"");
    head.append(cstrView(encName(x.enc)));
    head.append("\"");
    if (x.kid.len) {
        head.append(",\"kid\":");
        json.quoteTo(&head, x.kid[0:]);
    }
    if (nested) { head.append(",\"cty\":\"JWT\""); }
    i64 size = cekSize(x.enc);
    if (x.alg == KAlg.dir) {
        cek = str.from(x.key[0:]);
    } else if (isEcdh(x.alg)) {
        crypto.Key *eph = crypto.generateKey(x.recipient.kind());
        String px, py;
        eph.ecPoint(&px, &py);
        String bx = base64.encodeUrl(px[0:]), by = base64.encodeUrl(py[0:]);
        head.append(",\"epk\":{\"kty\":\"EC\",\"crv\":\"");
        head.append(cstrView(crvName(eph.kind())));
        head.append("\",\"x\":\"");
        head.append(bx[0:]);
        head.append("\",\"y\":\"");
        head.append(by[0:]);
        head.append("\"}");
        px.free(); py.free(); bx.free(); by.free();
        String z = eph.ecdh(x.recipient);
        eph.free();
        if (x.alg == KAlg.ecdhEs) {
            cek = concatKdf(z[0:], size, cstrView(encName(x.enc)), "", "");
        } else {
            String kek = concatKdf(z[0:], kekSize(x.alg), cstrView(kalgName(x.alg)), "", "");
            u8 raw[64];
            crypto.random(raw[0:size]);
            cek = str.from(raw[0:size]);
            ek = crypto.aesKeyWrap(kek[0:], cek[0:]);
            mem.set(kek.ptr, 0, kek.len);
            kek.free();
        }
        mem.set(z.ptr, 0, z.len);
        z.free();
    } else {
        u8 raw[64];
        crypto.random(raw[0:size]);
        cek = str.from(raw[0:size]);
        mem.set(raw, 0, 64);
        if (x.alg == KAlg.rsaOaep256) {
            ek = x.recipient.encryptOaep(crypto.Hash.sha256, cek[0:]);
        } else {
            ek = crypto.aesKeyWrap(x.key[0:], cek[0:]);
        }
    }
    head.append("}");
    String token = base64.encodeUrl(head[0:]);
    head.free();
    String iv, ct, tag;
    contentEncrypt(x.enc, cek[0:], token[0:], plain, &iv, &ct, &tag);
    mem.set(cek.ptr, 0, cek.len);
    cek.free();
    String parts[4];
    parts[0] = base64.encodeUrl(ek[0:]);
    parts[1] = base64.encodeUrl(iv[0:]);
    parts[2] = base64.encodeUrl(ct[0:]);
    parts[3] = base64.encodeUrl(tag[0:]);
    for (i64 i = 0; i < 4; i++) {
        token.append(".");
        token.append(parts[i][0:]);
        parts[i].free();
    }
    ek.free(); iv.free(); ct.free(); tag.free();
    return token;
}

/* An encrypted token of claims (a @json struct), a new String (yours).
 * Unsigned: with RSA-OAEP-256 or ECDH-ES a Verifier only takes it with
 * allowUnsignedJwe; encryptToken a signed one instead. */
pub String Encrypter.encrypt<T>(T claims) {
    String payload = json.encode(reflect.of(claims));
    String token = jweSeal(self, payload[0:], false);
    payload.free();
    return token;
}

/* An encrypted token holding jws, a signed token ("cty": "JWT"): signed,
 * then encrypted, as RFC 7519 11.2 has it */
pub String Encrypter.encryptToken(u8[] jws) {
    return jweSeal(self, jws, true);
}

pub void Encrypter.free() {
    if (!self) { return; }
    mem.set(self.key.ptr, 0, self.key.len);
    self.key.free();
    self.kid.free();
    mem.free(self);
}

/* ---- decrypting, through the Verifier ---- */

static void jweTrust(Verifier *v, KAlg a, u8[] secret, crypto.Key *key, u8[] kid) {
    VKey *k = vkeyNew(Alg.hs256, kid, secret, key, false);
    k.jwe = true;
    k.kalg = a;
    v.keys.push(k);
}

/* Decrypt dir tokens with key (16 to 64 bytes: the enc's size) */
pub void Verifier.dir(u8[] key, u8[] kid = "") {
    if (key.len != 16 && key.len != 24 && key.len != 32 && key.len != 48 && key.len != 64) {
        throw(ERR_KEY, "jwt: a dir key is 16, 24, 32, 48 or 64 bytes");
    }
    jweTrust(self, KAlg.dir, key, null, kid);
}

/* Decrypt A128KW, A192KW, A256KW tokens with kek (16, 24, 32 bytes) */
pub void Verifier.a128kw(u8[] kek, u8[] kid = "") {
    needSize(kek, 16, "an A128KW key");
    jweTrust(self, KAlg.a128kw, kek, null, kid);
}

pub void Verifier.a192kw(u8[] kek, u8[] kid = "") {
    needSize(kek, 24, "an A192KW key");
    jweTrust(self, KAlg.a192kw, kek, null, kid);
}

pub void Verifier.a256kw(u8[] kek, u8[] kid = "") {
    needSize(kek, 32, "an A256KW key");
    jweTrust(self, KAlg.a256kw, kek, null, kid);
}

/* Decrypt RSA-OAEP-256 tokens with key, a private RSA key (still yours) */
pub void Verifier.rsaOaep256(crypto.Key *key, u8[] kid = "") {
    if (!key || key.kind() != crypto.KeyKind.rsa) { throw(ERR_KEY, "jwt: RSA-OAEP-256 needs an RSA key"); }
    jweTrust(self, KAlg.rsaOaep256, "", key, kid);
}

/* Decrypt ECDH-ES (+A128KW, +A256KW) tokens with key, a private EC key
 * (still yours); the token's ephemeral key must be on its curve */
pub void Verifier.ecdhEs(crypto.Key *key, u8[] kid = "") {
    if (!isEcKey(key)) { throw(ERR_KEY, "jwt: ECDH-ES needs an EC key"); }
    jweTrust(self, KAlg.ecdhEs, "", key, kid);
}

pub void Verifier.ecdhEsA128kw(crypto.Key *key, u8[] kid = "") {
    if (!isEcKey(key)) { throw(ERR_KEY, "jwt: ECDH-ES+A128KW needs an EC key"); }
    jweTrust(self, KAlg.ecdhEsA128kw, "", key, kid);
}

pub void Verifier.ecdhEsA256kw(crypto.Key *key, u8[] kid = "") {
    if (!isEcKey(key)) { throw(ERR_KEY, "jwt: ECDH-ES+A256KW needs an EC key"); }
    jweTrust(self, KAlg.ecdhEsA256kw, "", key, kid);
}

/* The five parts of a compact JWE */
struct JweParts {
    u8[] head64;
    String head, ek, iv, ct, tag;
};

static void jwePartsFree(JweParts *p) {
    p.head.free();
    p.ek.free();
    p.iv.free();
    p.ct.free();
    p.tag.free();
}

/* token split at its four dots and decoded; throws ERR_MALFORMED */
static void splitJwe(u8[] token, JweParts *p) {
    i64 at[4];
    i64 n = 0;
    for (i64 i = 0; i < token.len; i++) {
        if (token[i] == '.') {
            if (n == 4) { throw(ERR_MALFORMED, "jwt: a JWE has five parts"); }
            at[n++] = i;
        }
    }
    if (n != 4) { throw(ERR_MALFORMED, "jwt: a JWE has five parts"); }
    p.head64 = token[0:at[0]];
    u8[] ek64 = token[at[0] + 1:at[1]];
    u8[] iv64 = token[at[1] + 1:at[2]];
    u8[] ct64 = token[at[2] + 1:at[3]];
    u8[] tag64 = token[at[3] + 1:];
    if (!p.head64.len || !iv64.len || !tag64.len) {
        throw(ERR_MALFORMED, "jwt: a JWE's header, iv and tag can't be empty");
    }
    if (!b64url(p.head64, &p.head) || !b64url(ek64, &p.ek) || !b64url(iv64, &p.iv) ||
        !b64url(ct64, &p.ct) || !b64url(tag64, &p.tag)) {
        jwePartsFree(p);
        throw(ERR_MALFORMED, "jwt: a part that isn't unpadded base64url");
    }
}

/* the header's epk (an EC JWK) as a key on key's curve; throws ERR_KEY */
static crypto.Key *epkOf(json.Value *h, crypto.Key *key) {
    json.Value *epk = json.objectGet(h, "epk");
    if (!epk || !json.isObject(epk)) { throw(ERR_MALFORMED, "jwt: ECDH-ES needs an epk header"); }
    bool bad = false;
    if (!str.equals(member(epk, "kty", &bad), "EC")) { throw(ERR_KEY, "jwt: epk is an EC key"); }
    String x, y;
    crypto.Key *e = null;
    if (jwkBytes(epk, "x", &x) && jwkBytes(epk, "y", &y)) {
        try {
            e = crypto.ecPublicKey(x[0:], y[0:]);
        } catch {
            e = null;
        }
    }
    x.free();
    y.free();
    if (!e) { throw(ERR_KEY, "jwt: epk isn't a point on a curve"); }
    u8[] crv = member(epk, "crv", &bad);
    if (e.kind() != key.kind() || !str.equals(crv, cstrView(crvName(key.kind())))) {
        e.free();
        throw(ERR_KEY, "jwt: epk is on another curve than the key");
    }
    return e;
}

/* a header member in base64url, decoded ("" when absent) */
static void headerBytes(json.Value *h, u8[] name, String *out) {
    bool bad = false;
    u8[] text = member(h, name, &bad);
    if (bad || (text.len && !b64url(text, out))) {
        throw(ERR_MALFORMED, "jwt: %.*s isn't base64url", name.len, name.ptr);
    }
}

/* the content key from k for this token into *cek: false when k's key
 * doesn't open it */
static bool cekOf(VKey *k, Enc e, json.Value *h, JweParts *p, String *cek) {
    cek.clear();
    i64 size = cekSize(e);
    if (k.kalg == KAlg.dir) {
        if (p.ek.len || k.secret.len != size) { return false; }
        cek.append(k.secret[0:]);
        return true;
    }
    if (k.kalg == KAlg.rsaOaep256) {
        return k.key.decryptOaep(crypto.Hash.sha256, p.ek[0:], cek) && cek.len == size;
    }
    if (!isEcdh(k.kalg)) {
        return crypto.aesKeyUnwrap(k.secret[0:], p.ek[0:], cek) && cek.len == size;
    }
    crypto.Key *eph = epkOf(h, k.key);
    String z = k.key.ecdh(eph);
    eph.free();
    String apu, apv;
    headerBytes(h, "apu", &apu);
    headerBytes(h, "apv", &apv);
    bool ok = true;
    if (k.kalg == KAlg.ecdhEs) {
        ok = p.ek.len == 0;
        String d = concatKdf(z[0:], size, cstrView(encName(e)), apu[0:], apv[0:]);
        cek.append(d[0:]);
        d.free();
    } else {
        String kek = concatKdf(z[0:], kekSize(k.kalg), cstrView(kalgName(k.kalg)), apu[0:], apv[0:]);
        ok = crypto.aesKeyUnwrap(kek[0:], p.ek[0:], cek) && cek.len == size;
        mem.set(kek.ptr, 0, kek.len);
        kek.free();
    }
    mem.set(z.ptr, 0, z.len);
    z.free();
    apu.free();
    apv.free();
    return ok;
}

/* token, a JWE, decrypted and its claims verified into *out (a Parts
 * whose body is the claims); throws ERR_* */
static void verifyJwe(Verifier *v, u8[] token, Parts *out) {
    JweParts p;
    splitJwe(token, &p);
    json.Value *h = null;
    String plain;
    bool publicKey = false;
    try {
        h = object(p.head[0:]);
        if (!h) { throw(ERR_MALFORMED, "jwt: the header isn't a JSON object"); }
        json.Value *crit = json.objectGet(h, "crit");
        if (crit) { checkCrit(v, h, crit); }
        if (json.objectGet(h, "zip")) { throw(ERR_ALG, "jwt: compressed JWE (zip) isn't accepted"); }
        bool bad = false;
        u8[] algText = member(h, "alg", &bad);
        u8[] encText = member(h, "enc", &bad);
        u8[] kid = member(h, "kid", &bad);
        if (bad) { throw(ERR_MALFORMED, "jwt: alg, enc and kid are strings"); }
        KAlg a;
        Enc e;
        if (!kalgOf(algText, &a)) { throw(ERR_ALG, "jwt: alg \"%.*s\" isn't accepted", algText.len, algText.ptr); }
        if (!encOf(encText, &e)) { throw(ERR_ALG, "jwt: enc \"%.*s\" isn't accepted", encText.len, encText.ptr); }
        publicKey = isPublicKeyAlg(a);
        /* the keys to try: kid first, else every one of the alg */
        bool found = false, kidSeen = false, opened = false;
        String cek;
        for (i64 i = 0; i < v.keys.len && !opened; i++) {
            VKey *k = v.keys.get(i);
            if (!k.jwe) { continue; }
            if (kid.len && !str.equals(k.kid[0:], kid)) { continue; }
            if (kid.len) { kidSeen = true; }
            if (k.kalg != a) { continue; }
            found = true;
            if (cekOf(k, e, h, &p, &cek)) {
                opened = contentDecrypt(e, cek[0:], p.head64, p.iv[0:], p.ct[0:], p.tag[0:], &plain);
            }
        }
        mem.set(cek.ptr, 0, cek.len);
        cek.free();
        if (kid.len && !kidSeen) { throw(ERR_KEY, "jwt: no key with kid \"%.*s\"", kid.len, kid.ptr); }
        if (!found) { throw(ERR_ALG, "jwt: no %s key is configured", kalgName(a)); }
        /* a wrong key and an altered token look the same */
        if (!opened) { throw(ERR_SIGNATURE, "jwt: the token can't be decrypted"); }
    } catch (Error err) {
        if (h) { json.release(h); }
        plain.free();
        jwePartsFree(&p);
        throw(err);
    }
    bool bad = false;
    u8[] cty = member(h, "cty", &bad);
    bool nested = str.equalsFold(cty, "JWT");
    json.release(h);
    jwePartsFree(&p);
    if (nested) {
        /* a signed token inside, verified with the signing keys */
        try {
            if (str.find(plain[0:], ".") < 0 || countDots(plain[0:]) != 2) {
                throw(ERR_MALFORMED, "jwt: a nested token is a signed one (JWS)");
            }
            verifyParts(v, plain[0:], out);
        } catch (Error err) {
            plain.free();
            throw(err);
        }
        plain.free();
        return;
    }
    if (publicKey && !v.allowUnsignedJwe) {
        plain.free();
        throw(ERR_SIGNATURE, "jwt: a JWE made with a public key must hold a signed token (cty JWT)");
    }
    json.Value *c = object(plain[0:]);
    if (!c) {
        plain.free();
        throw(ERR_MALFORMED, "jwt: the payload isn't a JSON object");
    }
    try {
        checkClaims(v, c);
    } catch (Error err) {
        json.release(c);
        plain.free();
        throw(err);
    }
    json.release(c);
    out.body = plain;
}

static i64 countDots(u8[] s) {
    i64 n = 0;
    for (i64 i = 0; i < s.len; i++) {
        if (s[i] == '.') { n++; }
    }
    return n;
}

/* The public key with kid in a JWK Set (JSON text), whatever its "use"
 * and "alg": to encrypt to its owner (RSA-OAEP-256, ECDH-ES). Yours to
 * free. Throws ERR_KEY when there is none, or it isn't EC (P-256, P-384,
 * P-521), RSA or Ed25519. */
pub crypto.Key *jwksKey(u8[] text, u8[] kid) {
    json.Value *j = object(text);
    if (!j) { throw(ERR_KEY, "jwt: a JWKS is a JSON object"); }
    json.Value *keys = json.objectGet(j, "keys");
    crypto.Key *found = null;
    for (i64 i = 0; keys && json.isArray(keys) && i < json.len(keys) && !found; i++) {
        json.Value *k = json.arrayGet(keys, i);
        bool bad = false;
        if (!k || !json.isObject(k) || !str.equals(member(k, "kid", &bad), kid)) { continue; }
        u8[] kty = member(k, "kty", &bad);
        String p1, p2;
        try {
            if (str.equals(kty, "EC") && jwkBytes(k, "x", &p1) && jwkBytes(k, "y", &p2)) {
                found = crypto.ecPublicKey(p1[0:], p2[0:]);
            } else if (str.equals(kty, "RSA") && jwkBytes(k, "n", &p1) && jwkBytes(k, "e", &p2)) {
                found = crypto.rsaPublicKey(p1[0:], p2[0:]);
            } else if (str.equals(kty, "OKP") && str.equals(member(k, "crv", &bad), "Ed25519") &&
                       jwkBytes(k, "x", &p1)) {
                found = crypto.ed25519PublicKey(p1[0:]);
            }
        } catch {
            found = null;
        }
        p1.free();
        p2.free();
    }
    json.release(j);
    if (!found) { throw(ERR_KEY, "jwt: no usable key with kid \"%.*s\" in the JWKS", kid.len, kid.ptr); }
    return found;
}
