module jwt;
import crypto, encoding.base64, fs, json, libc, net, net.http, reflect, str, testing, vec;

@json struct Claims {
    String sub;
    String iss;
    i64 exp;
};

/* the claims the openssl tokens (testdata/gen.py) carry */
@json struct Ext {
    String sub;
    String iss;
    vec.Vec<String> aud;
    i64 iat;
    i64 exp;
};

const i64 NOW = 1800000000;
#define SECRET "a secret of thirty-two bytes...."

String file(u8 *name) {
    ad String path = str.format("testdata/%s", name);
    String text = fs.readAll(path[0:]);
    if (!text.len) { printf("can't read %.*s (tests run in the package directory)\n", path.len, path.ptr); }
    return text;
}

/* the token in a testdata file, without its line break */
String tokenFile(u8 *name) {
    ad String text = file(name);
    return str.from(str.trimEnd(text[0:]));
}

/* a token of these parts, signed or not: for what no Signer makes */
String craft(u8[] head, u8[] body, u8[] sig) {
    String out = base64.encodeUrl(head);
    String b = base64.encodeUrl(body);
    String s = base64.encodeUrl(sig);
    out.append(".");
    out.append(b[0:]);
    out.append(".");
    out.append(s[0:]);
    b.free();
    s.free();
    return out;
}

/* a token craft()ed and HS256-signed with secret */
String craftHs256(u8[] head, u8[] body, u8[] secret) {
    String h = base64.encodeUrl(head);
    String b = base64.encodeUrl(body);
    h.append(".");
    h.append(b[0:]);
    u8 mac[32];
    crypto.hmacSha256(secret, h[0:], mac[0:]);
    String s = base64.encodeUrl(mac[0:]);
    h.append(".");
    h.append(s[0:]);
    b.free();
    s.free();
    return h;
}

/* the code verify throws for token, 0 when it passes */
i64 code(Verifier *v, u8[] token) {
    try {
        Claims c = v.verify<Claims>(token);
        json.free(reflect.of(c));
    } catch (Error e) {
        return e.code;
    }
    return 0;
}

Claims claims(u8 *sub, i64 exp) {
    Claims c;
    c.sub = str.from(cstrView(sub));
    c.iss = str.from("me");
    c.exp = exp;
    return c;
}

/* RFC 7515, appendix A.1: an HS256 token and its key */
void testRfc7515Hs256(testing.T *t) {
    u8[] token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
                 ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
                 ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    String key;
    base64.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", &key);
    ad Verifier *v = verifier();
    v.hs256(key[0:]);
    v.now = 1300819380 - 10;
    Claims c = v.verify<Claims>(token);
    t.equal(c.iss, "joe");
    t.equal(c.exp, 1300819380);
    json.free(reflect.of(c));
    v.now = 1300819380 + 61;
    t.equal(code(v, token), ERR_EXPIRED);
    key.free();
}

/* a key of the kind alg i signs with: 0-2 HS, then ES256, ES384,
 * ES512, RS256-512, PS256-512, EdDSA */
crypto.Key *keyFor(i64 i, crypto.Key *rsa) {
    if (i == 3) { return crypto.generateKey(); }
    if (i == 4) { return crypto.generateKey(crypto.KeyKind.ec384); }
    if (i == 5) { return crypto.generateKey(crypto.KeyKind.ec521); }
    if (i == 12) { return crypto.generateKey(crypto.KeyKind.ed25519); }
    return rsa;
}

Signer *signerFor(i64 i, crypto.Key *k) {
    if (i == 0) { return hs256(SECRET); }
    if (i == 1) { return hs384(SECRET); }
    if (i == 2) { return hs512(SECRET); }
    if (i == 3) { return es256(k); }
    if (i == 4) { return es384(k); }
    if (i == 5) { return es512(k); }
    if (i == 6) { return rs256(k); }
    if (i == 7) { return rs384(k); }
    if (i == 8) { return rs512(k); }
    if (i == 9) { return ps256(k); }
    if (i == 10) { return ps384(k); }
    if (i == 11) { return ps512(k); }
    return eddsa(k);
}

void trustFor(Verifier *v, i64 i, crypto.Key *k, u8[] secret) {
    if (i == 0) { v.hs256(secret); }
    if (i == 1) { v.hs384(secret); }
    if (i == 2) { v.hs512(secret); }
    if (i == 3) { v.es256(k); }
    if (i == 4) { v.es384(k); }
    if (i == 5) { v.es512(k); }
    if (i == 6) { v.rs256(k); }
    if (i == 7) { v.rs384(k); }
    if (i == 8) { v.rs512(k); }
    if (i == 9) { v.ps256(k); }
    if (i == 10) { v.ps384(k); }
    if (i == 11) { v.ps512(k); }
    if (i == 12) { v.eddsa(k); }
}

/* every algorithm signs and verifies, and refuses another key */
void testRoundTrips(testing.T *t) {
    ad String rsaPem = file("rsa-key.pem");
    crypto.Key *rsa = crypto.privateKey(rsaPem[0:]);
    crypto.Key *rsa2 = crypto.generateRsaKey();
    u8 *names[13] = {"HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512",
                     "PS256", "PS384", "PS512", "EdDSA"};
    i64 sigLen[13] = {32, 48, 64, 64, 96, 132, 256, 256, 256, 256, 256, 256, 64};
    ad Claims c = claims("7", NOW + 60);
    for (i64 i = 0; i < 13; i++) {
        crypto.Key *k = keyFor(i, rsa);
        crypto.Key *k2 = i >= 6 && i <= 11 ? rsa2 : keyFor(i, rsa);
        Signer *s = signerFor(i, k);
        ad Verifier *v = verifier();
        v.now = NOW;
        trustFor(v, i, k, SECRET);
        ad String tok = s.sign(c);
        ad Header h = header(tok[0:]);
        t.equal(h.alg, cstrView(names[i]));
        Parts p;
        split(tok[0:], &p);
        t.check(p.sig.len == sigLen[i], "%s: a %d-byte signature (%d)", names[i], sigLen[i], p.sig.len);
        partsFree(&p);
        Claims back = v.verify<Claims>(tok[0:]);
        t.check(str.equals(back.sub[0:], "7") && back.exp == NOW + 60, "%s: the claims come back", names[i]);
        json.free(reflect.of(back));
        /* the same alg, another key */
        ad Verifier *other = verifier();
        other.now = NOW;
        trustFor(other, i, k2, "another secret, also 32 bytes...");
        t.check(code(other, tok[0:]) == ERR_SIGNATURE, "%s: another key refuses it", names[i]);
        json.free(reflect.of(h));
        s.free();
        if (k != rsa) { k.free(); }
        if (k2 != rsa && k2 != rsa2) { k2.free(); }
    }
    /* PS is randomised, EdDSA and ES deterministic */
    Signer *ps = ps256(rsa);
    ad String p1 = ps.sign(c);
    ad String p2 = ps.sign(c);
    t.check(!str.equals(p1[0:], p2[0:]), "two PS256 tokens of the same claims differ");
    ps.free();
    /* a Signer refuses a key of another kind */
    crypto.Key *ed = crypto.generateKey(crypto.KeyKind.ed25519);
    crypto.Key *ec = crypto.generateKey();
    bool threw = false;
    try { Signer *x = es384(ec); x.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "es384 with a P-256 key throws ERR_KEY");
    threw = false;
    try { Signer *x = ps256(ed); x.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "ps256 with an Ed25519 key throws ERR_KEY");
    threw = false;
    try { Signer *x = eddsa(rsa); x.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "eddsa with an RSA key throws ERR_KEY");
    ed.free();
    ec.free();
    rsa.free();
    rsa2.free();
}

/* RFC 8037, appendix A.4: an EdDSA JWS (its payload isn't JSON, so it
 * is checked as a signature) with the key of A.1 */
void testRfc8037(testing.T *t) {
    String x;
    base64.decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", &x);
    crypto.Key *k = crypto.ed25519PublicKey(x[0:]);
    u8[] token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
                 ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    Parts p;
    split(token, &p);
    t.equal(p.body, "Example of Ed25519 signing");
    t.check(k.verify(token[0:p.head64.len + 1 + p.body64.len], p.sig[0:]), "RFC 8037 A.4 verifies");
    VKey vk;
    vk.alg = Alg.eddsa;
    vk.key = k;
    t.check(sigHolds(&vk, &p, token[0:p.head64.len + 1 + p.body64.len]), "and through the Verifier's check");
    partsFree(&p);
    k.free();
    x.free();
}

/* tokens openssl signed (testdata/gen.py) verify with keys from PEM and
 * from the JWKS */
void testOpensslTokens(testing.T *t) {
    ad String rsaPem = file("rsa-pub.pem");
    ad String ecPem = file("ec-pub.pem");
    ad String ec384Pem = file("ec384-pub.pem");
    ad String ec521Pem = file("ec521-pub.pem");
    ad String edPem = file("ed-pub.pem");
    ad String jwksText = file("jwks.json");
    crypto.Key *rsa = crypto.publicKey(rsaPem[0:]);
    crypto.Key *ec = crypto.publicKey(ecPem[0:]);
    crypto.Key *ec384k = crypto.publicKey(ec384Pem[0:]);
    crypto.Key *ec521k = crypto.publicKey(ec521Pem[0:]);
    crypto.Key *ed = crypto.publicKey(edPem[0:]);
    ad Verifier *v = verifier();
    v.rs256(rsa, "rsa1");
    v.rs384(rsa);
    v.rs512(rsa);
    v.es256(ec, "ec1");
    v.es384(ec384k, "ec384");
    v.es512(ec521k, "ec521");
    v.ps256(rsa, "pss1");
    v.eddsa(ed, "ed1");
    v.issuer = "https://issuer.example";
    v.audience = "api";
    ad Verifier *j = verifier();
    j.jwks(jwksText[0:]);
    u8 *files[8] = {"rs256.jwt", "rs384.jwt", "rs512.jwt", "es256.jwt", "es384.jwt", "es512.jwt", "ps256.jwt",
                    "eddsa.jwt"};
    for (i64 i = 0; i < 8; i++) {
        ad String tok = tokenFile(files[i]);
        Ext e = v.verify<Ext>(tok[0:]);
        t.check(str.equals(e.sub[0:], "ext") && e.aud.len == 2 && e.exp == 4102444800, "%s: claims", files[i]);
        json.free(reflect.of(e));
        /* the JWKS has RS256 (rsa1), ES256/384/512, PS256 and EdDSA keys,
         * no RS384 or RS512 */
        i64 got = code(j, tok[0:]);
        t.check(i == 1 || i == 2 ? got == ERR_ALG : got == 0, "%s with the JWKS: %x", files[i], got);
    }
    /* ES256 is r||s: the DER form openssl makes is refused */
    ad String der = tokenFile("es256-der.jwt");
    t.equal(code(v, der[0:]), ERR_SIGNATURE);
    rsa.free();
    ec.free();
    ec384k.free();
    ec521k.free();
    ed.free();
}

/* altered tokens fail */
void testTampered(testing.T *t) {
    ad Signer *s = hs256(SECRET);
    ad Verifier *v = verifier();
    v.hs256(SECRET);
    v.now = NOW;
    ad Claims c = claims("1", NOW + 60);
    ad String tok = s.sign(c);
    i64 dot1 = str.find(tok[0:], ".");
    i64 dot2 = dot1 + 1 + str.find(tok[dot1 + 1:], ".");

    /* another payload, the same header and signature */
    ad Claims admin = claims("0", NOW + 60);
    ad String other = s.sign(admin);
    i64 o1 = str.find(other[0:], ".");
    i64 o2 = o1 + 1 + str.find(other[o1 + 1:], ".");
    String forged = str.from(tok[0:dot1 + 1]);
    forged.append(other[o1 + 1:o2]);
    forged.append(tok[dot2:]);
    t.equal(code(v, forged[0:]), ERR_SIGNATURE);
    forged.free();

    /* a changed signature */
    String bad = str.from(tok[0:]);
    bad.ptr[bad.len - 2] = bad.ptr[bad.len - 2] == 'A' ? 'B' : 'A';
    t.equal(code(v, bad[0:]), ERR_SIGNATURE);
    bad.free();

    /* no signature */
    String bare = str.from(tok[0:dot2 + 1]);
    t.equal(code(v, bare[0:]), ERR_SIGNATURE);
    bare.free();
    t.equal(code(v, tok[0:]), 0);
}

/* alg: "none", one with no key configured, and HS256 with the RSA public
 * key as its secret (the old algorithm-confusion attack) */
void testAlg(testing.T *t) {
    ad Verifier *v = verifier();
    v.hs256(SECRET);
    v.now = NOW;
    ad String none = craft("{\"alg\":\"none\"}", "{\"sub\":\"0\",\"exp\":1900000000}", "");
    t.equal(code(v, none[0:]), ERR_ALG);
    ad String none2 = craft("{\"alg\":\"none\"}", "{\"sub\":\"0\",\"exp\":1900000000}", "x");
    t.equal(code(v, none2[0:]), ERR_ALG);
    ad String lower = craftHs256("{\"alg\":\"hs256\"}", "{\"sub\":\"0\",\"exp\":1900000000}", SECRET);
    t.equal(code(v, lower[0:]), ERR_ALG);
    ad String hs512 = craftHs256("{\"alg\":\"HS512\"}", "{\"sub\":\"0\",\"exp\":1900000000}", SECRET);
    t.equal(code(v, hs512[0:]), ERR_ALG);

    ad String pubPem = file("rsa-pub.pem");
    crypto.Key *rsa = crypto.publicKey(pubPem[0:]);
    ad Verifier *r = verifier();
    r.rs256(rsa);
    r.now = NOW;
    ad String confused = craftHs256("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"0\",\"exp\":1900000000}",
                                    pubPem[0:]);
    t.equal(code(r, confused[0:]), ERR_ALG);
    rsa.free();

    /* a Signer or Verifier refuses a key of the wrong kind */
    crypto.Key *ec = crypto.generateKey();
    bool threw = false;
    try { Signer *s = rs256(ec); s.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "rs256 with a P-256 key throws ERR_KEY");
    threw = false;
    try { v.es256(null); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "es256 with no key throws ERR_KEY");
    threw = false;
    try { Signer *s = hs256(""); s.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "an empty secret throws ERR_KEY");
    ec.free();
}

/* kid: a token with one uses only that key; without, every key of its alg */
void testKid(testing.T *t) {
    ad Signer *a = hs256("the first secret of 32 bytes....", "a");
    ad Signer *b = hs256("the second secret of 32 bytes...", "b");
    ad Signer *c = hs256("the third secret, 32 bytes......", "c");
    ad Signer *plain = hs256("the second secret of 32 bytes...");
    ad Verifier *v = verifier();
    v.hs256("the first secret of 32 bytes....", "a");
    v.hs256("the second secret of 32 bytes...", "b");
    v.now = NOW;
    ad Claims cl = claims("k", NOW + 60);
    ad String ta = a.sign(cl);
    ad String tb = b.sign(cl);
    ad String tc = c.sign(cl);
    ad String tp = plain.sign(cl);
    ad Header h = header(tb[0:]);
    t.equal(h.kid, "b");
    t.equal(code(v, ta[0:]), 0);
    t.equal(code(v, tb[0:]), 0);
    t.equal(code(v, tc[0:]), ERR_KEY);
    t.equal(code(v, tp[0:]), 0);
    /* kid a, but b's signature */
    ad String swapped = craftHs256("{\"alg\":\"HS256\",\"kid\":\"a\"}", "{\"sub\":\"k\",\"exp\":1900000000}",
                                   "the second secret of 32 bytes...");
    t.equal(code(v, swapped[0:]), ERR_SIGNATURE);
    json.free(reflect.of(h));
}

/* exp, nbf, iat, iss, aud and the leeway */
void testClaims(testing.T *t) {
    ad Verifier *v = verifier();
    v.hs256(SECRET);
    v.now = NOW;
    ad String expired = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1799999900}", SECRET);
    t.equal(code(v, expired[0:]), ERR_EXPIRED);
    ad String leeway = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1799999950}", SECRET);
    t.equal(code(v, leeway[0:]), 0);
    v.leewaySec = 0;
    t.equal(code(v, leeway[0:]), ERR_EXPIRED);
    ad String atNow = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1800000000}", SECRET);
    t.equal(code(v, atNow[0:]), ERR_EXPIRED);
    v.leewaySec = 60;
    ad String early = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"nbf\":1800000100}", SECRET);
    t.equal(code(v, early[0:]), ERR_NOT_YET);
    ad String nbfOk = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"nbf\":1800000030}", SECRET);
    t.equal(code(v, nbfOk[0:]), 0);
    ad String future = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"iat\":1800000100}", SECRET);
    t.equal(code(v, future[0:]), ERR_NOT_YET);
    ad String noExp = craftHs256("{\"alg\":\"HS256\"}", "{\"sub\":\"x\"}", SECRET);
    t.equal(code(v, noExp[0:]), ERR_CLAIM);
    v.requireExp = false;
    t.equal(code(v, noExp[0:]), 0);
    v.requireExp = true;
    ad String fracExp = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000.5}", SECRET);
    t.check(v.valid(fracExp[0:]), "a fractional exp is a NumericDate");
    t.equal(code(v, fracExp[0:]), ERR_CLAIM);     /* but not for Claims' i64 exp */
    ad String textExp = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":\"1900000000\"}", SECRET);
    t.equal(code(v, textExp[0:]), ERR_CLAIM);

    v.issuer = "me";
    ad String iss = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"iss\":\"me\"}", SECRET);
    ad String issOther = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"iss\":\"you\"}", SECRET);
    t.equal(code(v, iss[0:]), 0);
    t.equal(code(v, issOther[0:]), ERR_CLAIM);
    t.equal(code(v, noExp[0:]), ERR_CLAIM);
    v.issuer = "";

    v.audience = "api";
    ad String audOne = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"aud\":\"api\"}", SECRET);
    ad String audMany = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"aud\":[\"web\",\"api\"]}", SECRET);
    ad String audNot = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"aud\":[\"web\"]}", SECRET);
    ad String audNone = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, audOne[0:]), 0);
    t.equal(code(v, audMany[0:]), 0);
    t.equal(code(v, audNot[0:]), ERR_CLAIM);
    t.equal(code(v, audNone[0:]), ERR_CLAIM);
    v.audience = "";

    /* claims that don't fit T */
    ad String wrongType = craftHs256("{\"alg\":\"HS256\"}", "{\"exp\":1900000000,\"sub\":42}", SECRET);
    t.equal(code(v, wrongType[0:]), ERR_CLAIM);
    t.check(v.valid(wrongType[0:]), "valid() doesn't look at T");
    t.check(!v.valid(expired[0:]), "valid() is false for an expired token");
}

/* what isn't a token */
void testMalformed(testing.T *t) {
    ad Verifier *v = verifier();
    v.hs256(SECRET);
    v.now = NOW;
    u8 *bad[7] = {"", "abc", "a.b", "a.b.c.d", "..", "eyJhbGciOiJIUzI1NiJ9=.e30.AA", "eyJhbGciOiJIUzI1NiJ9.e3 0.AA"};
    for (i64 i = 0; i < 7; i++) {
        t.check(code(v, cstrView(bad[i])) == ERR_MALFORMED, "`%s` is malformed", bad[i]);
    }
    ad String notJson = craftHs256("not json", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, notJson[0:]), ERR_MALFORMED);
    ad String arrayHead = craftHs256("[1]", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, arrayHead[0:]), ERR_MALFORMED);
    ad String body = craftHs256("{\"alg\":\"HS256\"}", "[\"exp\"]", SECRET);
    t.equal(code(v, body[0:]), ERR_MALFORMED);
    ad String crit = craftHs256("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, crit[0:]), ERR_MALFORMED);
    ad String algNum = craftHs256("{\"alg\":5}", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, algNum[0:]), ERR_MALFORMED);
    bool threw = false;
    try { Header h = header("x.y"); json.free(reflect.of(h)); } catch (Error e) { threw = e.code == ERR_MALFORMED; }
    t.check(threw, "header() of a malformed token throws ERR_MALFORMED");
}

/* decodeUnverified reads any token's claims, signed or not */
void testUnverified(testing.T *t) {
    ad String tok = craft("{\"alg\":\"none\"}", "{\"sub\":\"who\",\"exp\":5}", "");
    Claims c = decodeUnverified<Claims>(tok[0:]);
    t.equal(c.sub, "who");
    t.equal(c.exp, 5);
    json.free(reflect.of(c));
}

/* a JWKS as text: the keys it can use, and one with none */
void testJwksText(testing.T *t) {
    ad Verifier *v = verifier();
    ad String text = file("jwks.json");
    v.jwks(text[0:]);
    /* rsa1, ec1, ec384, ec521, ed1, pss1; skipped: oct, a bad P-384 point,
     * use enc, an RSA key that says HS256, a P-384 key that says ES256 */
    t.equal(v.keys.len, 6);
    bool threw = false;
    ad Verifier *w = verifier();
    try { w.jwks("{\"keys\":[{\"kty\":\"oct\",\"k\":\"AA\"}]}"); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a JWKS with no usable key throws ERR_KEY");
    threw = false;
    try { w.jwks("[]"); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a JWKS that isn't an object throws ERR_KEY");
    threw = false;
    try { w.jwks("{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\"}]}"); }
    catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a JWK with a bad point is skipped");
}

/* ---- a JWKS over HTTP ---- */

extern "c" i32 pthread_create(void *t, void *attr, void *start, void *arg);
extern "c" i32 pthread_join(void *t, void **ret);
extern "c" i32 usleep(u32 us);

String gJwks;               /* what /jwks answers */
i64 gFetches = 0;
i32 gPort = 0;
libc.pthread_mutex_t gLock;

void jwksHandler(http.Writer *w, http.Request *r) {
    libc.pthread_mutex_lock(&gLock);
    gFetches++;
    String body = str.from(gJwks[0:]);
    libc.pthread_mutex_unlock(&gLock);
    w.header("Content-Type", "application/json");
    w.text(200, "%.*s", body.len, body.ptr);
    body.free();
}

void *serveJwks(void *unused) {
    http.Mux mux;
    mux.handle("GET /jwks", &jwksHandler);
    http.Options o;
    o.threads = 1;
    o.bindaddr = "127.0.0.1";
    o.noSignals = true;
    http.listen(gPort, &mux, null, &o);
    mux.free();
    return null;
}

void setJwks(u8[] text) {
    libc.pthread_mutex_lock(&gLock);
    gJwks.free();
    gJwks = str.from(text);
    libc.pthread_mutex_unlock(&gLock);
}

/* the public JWK of a P-256 key, with kid */
String ecJwk(crypto.Key *k, u8 *kid) {
    /* x and y: the last 64 bytes of the public key's DER (SPKI) */
    ad String pem = k.publicPem();
    u8[] body = pem[0:];
    i64 a = str.find(body, "\n") + 1;
    i64 b = str.find(body, "-----END");
    String der;
    base64.decode(body[a:b], &der);
    ad String x = base64.encodeUrl(der[der.len - 64:der.len - 32]);
    ad String y = base64.encodeUrl(der[der.len - 32:]);
    der.free();
    return str.format("{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"%s\",\"x\":\"%.*s\",\"y\":\"%.*s\"}",
                      kid, x.len, x.ptr, y.len, y.ptr);
}

struct Load {
    Verifier *v;
    u8[] good, unknown;
    i64 ok, bad;
};

void *hammer(void *arg) {
    Load *l = arg;
    for (i64 i = 0; i < 200; i++) {
        if (l.v.valid(l.good)) { l.ok++; }
        if (l.v.valid(l.unknown)) { l.bad++; }
    }
    return null;
}

void testJwksUrl(testing.T *t) {
    libc.pthread_mutex_init(&gLock);
    i32 fd = net.listen(0, "127.0.0.1", 1);
    gPort = net.localPort(fd);
    libc.close(fd);
    crypto.Key *k1 = crypto.generateKey();
    crypto.Key *k2 = crypto.generateKey();
    ad String j1 = ecJwk(k1, "one");
    ad String j2 = ecJwk(k2, "two");
    ad String set1 = str.format("{\"keys\":[%.*s]}", j1.len, j1.ptr);
    ad String set2 = str.format("{\"keys\":[%.*s,%.*s]}", j1.len, j1.ptr, j2.len, j2.ptr);
    setJwks(set1[0:]);
    void *th;
    pthread_create(&th, null, &serveJwks, null);
    ad String url = str.format("http://127.0.0.1:%d/jwks", gPort);

    /* wait for the server */
    ad Verifier *v = verifier();
    bool up = false;
    for (i64 i = 0; i < 200 && !up; i++) {
        try {
            v.jwksUrl(url[0:]);
            up = true;
        } catch {
            usleep(10000);
        }
    }
    t.check(up, "jwksUrl fetched the set");
    v.now = NOW;

    ad Signer *s1 = es256(k1, "one");
    ad Signer *s2 = es256(k2, "two");
    ad Signer *s3 = es256(k2, "three");
    ad Claims c = claims("u", NOW + 60);
    ad String t1 = s1.sign(c);
    ad String t2 = s2.sign(c);
    ad String t3 = s3.sign(c);
    t.equal(code(v, t1[0:]), 0);

    /* "two" isn't there yet; then the set changes, and a token with an
     * unknown kid fetches it again, at most every jwksRetrySec */
    i64 before = gFetches;
    t.equal(code(v, t2[0:]), ERR_KEY);
    t.equal(gFetches, before);                /* fetched less than 60 s ago */
    setJwks(set2[0:]);
    v.jwksRetrySec = 0;
    t.equal(code(v, t2[0:]), 0);
    t.equal(gFetches, before + 1);
    t.equal(code(v, t3[0:]), ERR_KEY);        /* fetched again: still no "three" */
    t.equal(code(v, t1[0:]), 0);

    /* threads verify while unknown kids replace the set under them */
    Load loads[4];
    void *ths[4];
    for (i64 i = 0; i < 4; i++) {
        loads[i].v = v;
        loads[i].good = t1[0:];
        loads[i].unknown = t3[0:];
        loads[i].ok = 0;
        loads[i].bad = 0;
        pthread_create(&ths[i], null, &hammer, &loads[i]);
    }
    for (i64 i = 0; i < 4; i++) {
        pthread_join(ths[i], null);
        t.check(loads[i].ok == 200 && loads[i].bad == 0, "thread %d: %d good, %d bad", i, loads[i].ok, loads[i].bad);
    }

    /* a URL that answers 404, and one with nobody there */
    ad Verifier *w = verifier();
    ad String missing = str.format("http://127.0.0.1:%d/nothing", gPort);
    bool threw = false;
    try { w.jwksUrl(missing[0:]); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a JWKS URL answering 404 throws ERR_KEY");
    http.shutdown();
    pthread_join(th, null);
    threw = false;
    try { w.jwksUrl(url[0:]); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a JWKS URL nobody answers throws ERR_KEY");
    /* the keys fetched stay when a fetch fails */
    t.equal(code(v, t3[0:]), ERR_KEY);
    t.equal(code(v, t2[0:]), 0);
    k1.free();
    k2.free();
    gJwks.free();
}

/* crit (RFC 7515 4.1.11): extensions the Verifier was told it understands */
void testCrit(testing.T *t) {
    ad Signer *s = hs256(SECRET);
    s.header("tenant", "\"acme\"", true);
    s.header("hint", "{\"x\":1}");
    ad Claims c = claims("c", NOW + 60);
    ad String tok = s.sign(c);
    ad Verifier *v = verifier();
    v.hs256(SECRET);
    v.now = NOW;
    t.equal(code(v, tok[0:]), ERR_MALFORMED);           /* tenant not understood */
    v.understand("tenant");
    t.equal(code(v, tok[0:]), 0);
    ad String tenant = headerValue(tok[0:], "tenant");
    ad String hint = headerValue(tok[0:], "hint");
    ad String none = headerValue(tok[0:], "nothing");
    t.equal(tenant, "\"acme\"");
    t.equal(hint, "{\"x\": 1}");                 /* as json.toStr writes it */
    t.equal(none, "");
    ad String critText = headerValue(tok[0:], "crit");
    t.equal(critText, "[\"tenant\"]");

    /* crit's rules, on tokens made by hand */
    ad String empty = craftHs256("{\"alg\":\"HS256\",\"crit\":[]}", "{\"exp\":1900000000}", SECRET);
    ad String notList = craftHs256("{\"alg\":\"HS256\",\"crit\":\"tenant\",\"tenant\":1}", "{\"exp\":1900000000}", SECRET);
    ad String specName = craftHs256("{\"alg\":\"HS256\",\"crit\":[\"kid\"],\"kid\":\"a\"}", "{\"exp\":1900000000}", SECRET);
    ad String absent = craftHs256("{\"alg\":\"HS256\",\"crit\":[\"tenant\"]}", "{\"exp\":1900000000}", SECRET);
    ad String b64 = craftHs256("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}", "{\"exp\":1900000000}", SECRET);
    ad String fine = craftHs256("{\"alg\":\"HS256\",\"crit\":[\"tenant\"],\"tenant\":1}", "{\"exp\":1900000000}", SECRET);
    t.equal(code(v, empty[0:]), ERR_MALFORMED);
    t.equal(code(v, notList[0:]), ERR_MALFORMED);
    t.equal(code(v, specName[0:]), ERR_MALFORMED);
    t.equal(code(v, absent[0:]), ERR_MALFORMED);
    t.equal(code(v, b64[0:]), ERR_MALFORMED);
    t.equal(code(v, fine[0:]), 0);

    /* what header() and understand() refuse */
    bool threw = false;
    try { s.header("alg", "\"none\""); } catch (Error e) { threw = e.code == ERR_MALFORMED; }
    t.check(threw, "header(\"alg\") throws");
    threw = false;
    try { s.header("x", "not json"); } catch (Error e) { threw = e.code == ERR_MALFORMED; }
    t.check(threw, "a value that isn't JSON throws");
    threw = false;
    try { v.understand("b64"); } catch (Error e) { threw = e.code == ERR_MALFORMED; }
    t.check(threw, "understand(\"b64\") throws");
}
