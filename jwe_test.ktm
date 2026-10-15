module jwt;
import crypto, encoding.base64, encoding.hex, json, reflect, str, testing;

/* JWE: RFC 7516 A.3 and RFC 7518 C, tokens Python's cryptography made
 * (testdata/gen_jwe.py), every alg with every enc both ways, nested
 * signed tokens, what is refused */

/* the claims of the JWE fixtures */
@json struct Py {
    String sub;
    String iss;
    i64 exp;
};

/* the code verify throws for token (claims as Py), 0 when it passes */
i64 jweCode(Verifier *v, u8[] token) {
    try {
        Py c = v.verify<Py>(token);
        json.free(reflect.of(c));
    } catch (Error e) {
        return e.code;
    }
    return 0;
}

String fixture(u8 *name) {
    ad String text = file(name);
    return str.from(str.trimEnd(text[0:]));
}

/* RFC 7516 appendix A.3: A128KW and A128CBC-HS256, "Live long and
 * prosper." (not claims: decrypted through the parts) */
void testRfc7516A3(testing.T *t) {
    u8[] token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
                 ".6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
                 ".AxY8DCtDaGlsbGljb3RoZQ"
                 ".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
                 ".U0m_YmjN04DJvceFICbCVQ";
    String kek;
    base64.decode("GawgguFyGrWKav7AX4VKUg", &kek);
    JweParts p;
    splitJwe(token, &p);
    VKey k;
    k.jwe = true;
    k.kalg = KAlg.a128kw;
    k.secret = kek;
    String cek, plain;
    t.check(cekOf(&k, Enc.a128cbcHs256, null, &p, &cek), "the content key unwraps");
    t.check(contentDecrypt(Enc.a128cbcHs256, cek[0:], p.head64, p.iv[0:], p.ct[0:], p.tag[0:], &plain),
            "the content decrypts");
    t.equal(plain, "Live long and prosper.");
    /* one bit of the tag: nothing */
    p.tag.ptr[0] ^= 1;
    t.check(!contentDecrypt(Enc.a128cbcHs256, cek[0:], p.head64, p.iv[0:], p.ct[0:], p.tag[0:], &plain) &&
            plain.len == 0, "an altered tag: nothing decrypted");
    jwePartsFree(&p);
    cek.free();
    plain.free();
    kek.free();
}

/* the private P-256 key with this d, x, y (base64url), through SEC1 PEM */
crypto.Key *ecPrivate(u8[] d, u8[] x, u8[] y) {
    String der, b;
    hex.decode("30770201010420", &der);
    base64.decode(d, &b);
    der.append(b[0:]);
    b.free();
    String mid;
    hex.decode("a00a06082a8648ce3d030107a14403420004", &mid);
    der.append(mid[0:]);
    mid.free();
    base64.decode(x, &b);
    der.append(b[0:]);
    b.free();
    base64.decode(y, &b);
    der.append(b[0:]);
    b.free();
    ad String body = base64.encode(der[0:]);
    der.free();
    ad String pem = str.format("-----BEGIN EC PRIVATE KEY-----\n%.*s\n-----END EC PRIVATE KEY-----\n", body.len,
                               body.ptr);
    return crypto.privateKey(pem[0:]);
}

/* RFC 7518 appendix C: ECDH-ES's key from Alice's ephemeral key and Bob's,
 * apu "Alice", apv "Bob", for A128GCM */
void testRfc7518C(testing.T *t) {
    crypto.Key *alice = ecPrivate("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
                                  "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                                  "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");
    String bx, by;
    base64.decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", &bx);
    base64.decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", &by);
    crypto.Key *bob = crypto.ecPublicKey(bx[0:], by[0:]);
    ad String z = alice.ecdh(bob);
    ad String k = concatKdf(z[0:], 16, "A128GCM", "Alice", "Bob");
    ad String k64 = base64.encodeUrl(k[0:]);
    t.equal(k64, "VqqN6vgjbSBcIijNcacQGg");
    alice.free();
    bob.free();
    bx.free();
    by.free();
}

/* tokens Python's cryptography made decrypt here */
void testPythonTokens(testing.T *t) {
    ad String rsaPem = file("rsa-key.pem");
    ad String ecPem = file("ec-key.pem");
    ad String ec384Pem = file("ec384-key.pem");
    ad String rsaPub = file("rsa-pub.pem");
    crypto.Key *rsa = crypto.privateKey(rsaPem[0:]);
    crypto.Key *ec = crypto.privateKey(ecPem[0:]);
    crypto.Key *e384 = crypto.privateKey(ec384Pem[0:]);
    crypto.Key *rsaSign = crypto.publicKey(rsaPub[0:]);
    u8 kek[32], d128[16];
    for (i64 i = 0; i < 32; i++) { kek[i] = (u8)i; }
    for (i64 i = 0; i < 16; i++) { d128[i] = (u8)(100 + i); }
    ad Verifier *v = verifier();
    v.allowUnsignedJwe = true;
    v.rsaOaep256(rsa);
    v.ecdhEsA128kw(ec, "e1");
    v.ecdhEs(e384);
    v.a256kw(kek[0:32]);
    v.dir(d128[0:16]);
    v.rs256(rsaSign, "rsa1");
    u8 *files[5] = {"jwe-rsa-oaep-256.A256GCM.txt", "jwe-ECDH-ES+A128KW.A128CBC-HS256.txt",
                    "jwe-ECDH-ES.A256GCM.p384.apu.txt", "jwe-A256KW.A256CBC-HS512.txt", "jwe-dir.A128GCM.txt"};
    for (i64 i = 0; i < 5; i++) {
        ad String tok = fixture(files[i]);
        Py c = v.verify<Py>(tok[0:]);
        t.check(str.equals(c.sub[0:], "py") && c.exp == 4102444800, "%s", files[i]);
        json.free(reflect.of(c));
    }
    /* the nested one: openssl's RS256 token inside */
    ad String nested = fixture("jwe-nested.rsa-oaep-256.A128GCM.txt");
    v.issuer = "https://issuer.example";
    Ext e = v.verify<Ext>(nested[0:]);
    t.check(str.equals(e.sub[0:], "ext"), "nested: the signed token's claims");
    json.free(reflect.of(e));
    ad Header h = header(nested[0:]);
    t.equal(h.alg, "RSA-OAEP-256");
    t.equal(h.enc, "A128GCM");
    t.equal(h.cty, "JWT");
    json.free(reflect.of(h));
    rsa.free();
    ec.free();
    e384.free();
    rsaSign.free();
}

/* an Encrypter and the Verifier keys for alg a, enc e */
Encrypter *encFor(i64 a, Enc e, Verifier *v, crypto.Key *rsa, crypto.Key *ec) {
    u8 key[64];
    for (i64 i = 0; i < 64; i++) { key[i] = (u8)(7 * i + 3); }
    i64 n = cekSize(e);
    if (a == 0) { v.dir(key[0:n]); return dir(e, key[0:n]); }
    if (a == 1) { v.a128kw(key[0:16]); return a128kw(e, key[0:16]); }
    if (a == 2) { v.a192kw(key[0:24]); return a192kw(e, key[0:24]); }
    if (a == 3) { v.a256kw(key[0:32]); return a256kw(e, key[0:32]); }
    if (a == 4) { v.rsaOaep256(rsa); return rsaOaep256(e, rsa); }
    if (a == 5) { v.ecdhEs(ec); return ecdhEs(e, ec); }
    if (a == 6) { v.ecdhEsA128kw(ec); return ecdhEsA128kw(e, ec); }
    v.ecdhEsA256kw(ec);
    return ecdhEsA256kw(e, ec);
}

/* every alg with every enc: claims, and a signed token inside */
void testJweRoundTrips(testing.T *t) {
    ad String rsaPem = file("rsa-key.pem");
    crypto.Key *rsa = crypto.privateKey(rsaPem[0:]);
    crypto.Key *ec = crypto.generateKey();
    ad Signer *signer = hs256(SECRET);
    ad Claims c = claims("j", NOW + 60);
    ad String jws = signer.sign(c);
    for (i64 a = 0; a < 8; a++) {
        for (i64 ei = 0; ei <= (i64)Enc.a256cbcHs512; ei++) {
            Enc e = (Enc)ei;
            ad Verifier *v = verifier();
            v.now = NOW;
            v.hs256(SECRET);
            Encrypter *x = encFor(a, e, v, rsa, ec);
            ad String tok = x.encrypt(c);
            ad String nested = x.encryptToken(jws[0:]);
            t.check(countDots(tok[0:]) == 4, "five parts");
            i64 got = code(v, tok[0:]);
            /* claims alone: only by a shared key */
            t.check(a < 4 ? got == 0 : got == ERR_SIGNATURE, "%s %s: unsigned claims (%x)",
                    kalgName((KAlg)a), encName(e), got);
            v.allowUnsignedJwe = true;
            t.check(code(v, tok[0:]) == 0, "%s %s: with allowUnsignedJwe", kalgName((KAlg)a), encName(e));
            v.allowUnsignedJwe = false;
            Claims back = v.verify<Claims>(nested[0:]);
            t.check(str.equals(back.sub[0:], "j"), "%s %s: nested", kalgName((KAlg)a), encName(e));
            json.free(reflect.of(back));
            x.free();
        }
    }
    rsa.free();
    ec.free();
}

/* each of the five parts altered: refused */
void testJweTampered(testing.T *t) {
    u8 key[32];
    for (i64 i = 0; i < 32; i++) { key[i] = (u8)i; }
    ad Encrypter *x = a256kw(Enc.a256gcm, key[0:32]);
    ad Verifier *v = verifier();
    v.a256kw(key[0:32]);
    v.now = NOW;
    ad Claims c = claims("t", NOW + 60);
    ad String tok = x.encrypt(c);
    t.equal(code(v, tok[0:]), 0);
    i64 at[4];
    i64 n = 0;
    for (i64 i = 0; i < tok.len; i++) {
        if (tok.ptr[i] == '.') { at[n++] = i; }
    }
    /* a character in the middle of each part, changed */
    i64 mids[5] = {at[0] / 2, (at[0] + at[1]) / 2, (at[1] + at[2]) / 2, (at[2] + at[3]) / 2, (at[3] + tok.len) / 2};
    u8 *names[5] = {"header", "encrypted key", "iv", "ciphertext", "tag"};
    for (i64 i = 0; i < 5; i++) {
        String bad = str.from(tok[0:]);
        bad.ptr[mids[i]] = bad.ptr[mids[i]] == 'A' ? 'B' : 'A';
        i64 got = code(v, bad[0:]);
        t.check(got == ERR_SIGNATURE || got == ERR_MALFORMED, "the %s altered: refused (%x)", names[i], got);
        bad.free();
    }
    /* the header swapped for another valid one: the AAD differs */
    ad String head2 = base64.encodeUrl("{\"alg\":\"A256KW\",\"enc\":\"A256GCM\",\"x\":1}");
    String swapped = str.from(head2[0:]);
    swapped.append(tok[at[0]:]);
    t.equal(code(v, swapped[0:]), ERR_SIGNATURE);
    swapped.free();
    /* another key */
    u8 other[32];
    for (i64 i = 0; i < 32; i++) { other[i] = (u8)(i + 1); }
    ad Verifier *w = verifier();
    w.a256kw(other[0:32]);
    w.now = NOW;
    t.equal(code(w, tok[0:]), ERR_SIGNATURE);
}

/* what is refused, and why */
void testJweRefused(testing.T *t) {
    u8 key[32];
    for (i64 i = 0; i < 32; i++) { key[i] = (u8)i; }
    ad Verifier *v = verifier();
    v.a256kw(key[0:32], "k1");
    v.now = NOW;
    /* zip, an unknown enc, an unknown alg, RSA1_5 */
    ad String zip = base64.encodeUrl("{\"alg\":\"A256KW\",\"enc\":\"A256GCM\",\"zip\":\"DEF\"}");
    ad String enc = base64.encodeUrl("{\"alg\":\"A256KW\",\"enc\":\"A128GCMKW\"}");
    ad String rsa15 = base64.encodeUrl("{\"alg\":\"RSA1_5\",\"enc\":\"A256GCM\"}");
    ad String nokey = base64.encodeUrl("{\"alg\":\"A128KW\",\"enc\":\"A256GCM\"}");
    ad String kid = base64.encodeUrl("{\"alg\":\"A256KW\",\"enc\":\"A256GCM\",\"kid\":\"zz\"}");
    u8 *tail = ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";
    ad String t1 = str.format("%.*s%s", zip.len, zip.ptr, tail);
    ad String t2 = str.format("%.*s%s", enc.len, enc.ptr, tail);
    ad String t3 = str.format("%.*s%s", rsa15.len, rsa15.ptr, tail);
    ad String t4 = str.format("%.*s%s", nokey.len, nokey.ptr, tail);
    ad String t5 = str.format("%.*s%s", kid.len, kid.ptr, tail);
    t.equal(code(v, t1[0:]), ERR_ALG);
    t.equal(code(v, t2[0:]), ERR_ALG);
    t.equal(code(v, t3[0:]), ERR_ALG);
    t.equal(code(v, t4[0:]), ERR_ALG);
    t.equal(code(v, t5[0:]), ERR_KEY);
    t.equal(code(v, "a.b.c.d"), ERR_MALFORMED);
    t.equal(code(v, "a.b.c.d.e.f"), ERR_MALFORMED);

    /* an epk on another curve than the key */
    crypto.Key *p256 = crypto.generateKey();
    crypto.Key *p384 = crypto.generateKey(crypto.KeyKind.ec384);
    ad Encrypter *x = ecdhEs(Enc.a128gcm, p384);
    ad Verifier *w = verifier();
    w.ecdhEs(p256);
    w.allowUnsignedJwe = true;
    w.now = NOW;
    ad Claims c = claims("e", NOW + 60);
    ad String tok = x.encrypt(c);
    t.equal(code(w, tok[0:]), ERR_KEY);

    /* claims inside are checked as a signed token's */
    ad Encrypter *y = a256kw(Enc.a128gcm, key[0:32]);
    ad Claims old = claims("o", NOW - 3600);
    ad String expired = y.encrypt(old);
    t.equal(code(v, expired[0:]), ERR_EXPIRED);
    /* a nested token signed with a key the Verifier doesn't trust */
    ad Signer *s = hs256("not the verifier's secret, 32 b.");
    ad String jws = s.sign(c);
    ad String nested = y.encryptToken(jws[0:]);
    v.hs256(SECRET);
    t.equal(code(v, nested[0:]), ERR_SIGNATURE);
    /* a nested "token" that isn't a JWS */
    ad String notJws = y.encryptToken("{\"sub\":\"x\"}");
    t.equal(code(v, notJws[0:]), ERR_MALFORMED);

    /* wrong sizes and kinds */
    bool threw = false;
    try { Encrypter *z = dir(Enc.a256gcm, key[0:16]); z.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "a dir key of the wrong size throws ERR_KEY");
    threw = false;
    try { Encrypter *z = rsaOaep256(Enc.a256gcm, p256); z.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "RSA-OAEP-256 with an EC key throws ERR_KEY");
    threw = false;
    try { v.a128kw(key[0:32]); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "an A128KW key of 32 bytes throws ERR_KEY");
    p256.free();
    p384.free();
}

/* jwksKey: the recipient's key from their JWKS, use "enc" too */
void testJwksKey(testing.T *t) {
    ad String text = file("jwks.json");
    crypto.Key *enc1 = jwksKey(text[0:], "enc1");        /* RSA, "use": "enc" */
    crypto.Key *e384 = jwksKey(text[0:], "ec384");
    crypto.Key *ed = jwksKey(text[0:], "ed1");
    t.check(enc1.kind() == crypto.KeyKind.rsa && e384.kind() == crypto.KeyKind.ec384 &&
            ed.kind() == crypto.KeyKind.ed25519, "keys of three kinds");
    /* encrypt to it; the private key decrypts */
    ad String rsaPem = file("rsa-key.pem");
    crypto.Key *priv = crypto.privateKey(rsaPem[0:]);
    ad Encrypter *x = rsaOaep256(Enc.a256gcm, enc1);
    ad Verifier *v = verifier();
    v.rsaOaep256(priv);
    v.hs256(SECRET);
    v.now = NOW;
    ad Signer *s = hs256(SECRET);
    ad Claims c = claims("k", NOW + 60);
    ad String jws = s.sign(c);
    ad String tok = x.encryptToken(jws[0:]);
    t.equal(code(v, tok[0:]), 0);
    bool threw = false;
    try { crypto.Key *k = jwksKey(text[0:], "nope"); k.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "an unknown kid throws ERR_KEY");
    threw = false;
    try { crypto.Key *k = jwksKey(text[0:], "sym"); k.free(); } catch (Error e) { threw = e.code == ERR_KEY; }
    t.check(threw, "an oct key throws ERR_KEY");
    enc1.free();
    e384.free();
    ed.free();
    priv.free();
}
