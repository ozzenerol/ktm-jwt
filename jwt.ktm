module jwt;
import crypto, date, encoding.base64, json, libc, mem, net.http, reflect, str, vec;
import _ = net.https;           /* https:// JWKS URLs (a blank import: for what it does) */

/* JSON Web Tokens (RFC 7519) signed as JWS compact tokens (RFC 7515):
 * HS256/384/512, ES256 and RS256/384/512, verified with the claims a
 * token carries checked (exp, nbf, iat, iss, aud), keys from a JWK Set
 * (RFC 7517) given as text or fetched from a URL.
 *
 *   @json struct Claims { String sub; i64 exp; };
 *
 *   ad jwt.Signer *s = jwt.hs256("a secret of 32 bytes or more....");
 *   Claims c;
 *   c.sub = str.from("42");
 *   c.exp = date.unixNow() + 3600;
 *   String token = s.sign(c);
 *
 *   ad jwt.Verifier *v = jwt.verifier();
 *   v.hs256("a secret of 32 bytes or more....");
 *   Claims back = v.verify<Claims>(token);   // throws jwt.ERR_* */

pub const i64 ERR_MALFORMED = 0x6A770001;  /* not a token: its parts, base64url or JSON */
pub const i64 ERR_SIGNATURE = 0x6A770002;  /* the signature doesn't match: forged or altered */
pub const i64 ERR_EXPIRED   = 0x6A770003;  /* exp has passed */
pub const i64 ERR_NOT_YET   = 0x6A770004;  /* nbf (or iat) is still to come */
pub const i64 ERR_CLAIM     = 0x6A770005;  /* iss, aud, a missing exp, or claims that don't fit T */
pub const i64 ERR_ALG       = 0x6A770006;  /* an alg that isn't configured: "none", or not the key's */
pub const i64 ERR_KEY       = 0x6A770007;  /* no key for the token's kid, a bad key, a JWKS that can't be had */

/* A token's header, as it says (not verified) */
@json pub struct Header {
    String alg;
    String typ;
    String kid;
};

enum Alg { hs256, hs384, hs512, es256, rs256, rs384, rs512, es384, es512, ps256, ps384, ps512, eddsa };

static u8 *algName(Alg a) {
    if (a == Alg.hs256) { return "HS256"; }
    if (a == Alg.hs384) { return "HS384"; }
    if (a == Alg.hs512) { return "HS512"; }
    if (a == Alg.es256) { return "ES256"; }
    if (a == Alg.es384) { return "ES384"; }
    if (a == Alg.es512) { return "ES512"; }
    if (a == Alg.rs256) { return "RS256"; }
    if (a == Alg.rs384) { return "RS384"; }
    if (a == Alg.rs512) { return "RS512"; }
    if (a == Alg.ps256) { return "PS256"; }
    if (a == Alg.ps384) { return "PS384"; }
    if (a == Alg.ps512) { return "PS512"; }
    return "EdDSA";
}

/* The Alg of a header's "alg", false for any other ("none" too) */
static bool algOf(u8[] name, Alg *out) {
    for (i64 i = 0; i <= (i64)Alg.eddsa; i++) {
        if (str.equals(name, cstrView(algName((Alg)i)))) {
            *out = (Alg)i;
            return true;
        }
    }
    return false;
}

static u8[] cstrView(u8 *s) {
    i64 n = 0;
    while (s[n]) { n++; }
    return s[0:n];
}

static bool isHmac(Alg a) {
    return a == Alg.hs256 || a == Alg.hs384 || a == Alg.hs512;
}

static bool isPss(Alg a) {
    return a == Alg.ps256 || a == Alg.ps384 || a == Alg.ps512;
}

static crypto.Hash hashOf(Alg a) {
    if (a == Alg.hs384 || a == Alg.rs384 || a == Alg.es384 || a == Alg.ps384) { return crypto.Hash.sha384; }
    if (a == Alg.hs512 || a == Alg.rs512 || a == Alg.es512 || a == Alg.ps512) { return crypto.Hash.sha512; }
    return crypto.Hash.sha256;
}

/* The kind of key an algorithm signs with */
static crypto.KeyKind kindOf(Alg a) {
    if (a == Alg.es256) { return crypto.KeyKind.ec256; }
    if (a == Alg.es384) { return crypto.KeyKind.ec384; }
    if (a == Alg.es512) { return crypto.KeyKind.ec521; }
    if (a == Alg.eddsa) { return crypto.KeyKind.ed25519; }
    return crypto.KeyKind.rsa;
}

/* An ES signature's size: r||s, twice the curve's coordinate size */
static i64 ecSigSize(Alg a) {
    if (a == Alg.es384) { return 96; }
    if (a == Alg.es512) { return 132; }
    return 64;
}

/* the HMAC of data with secret, for alg a */
static String hmac(Alg a, u8[] secret, u8[] data) {
    u8 out[64];
    i64 n = 32;
    if (a == Alg.hs384) {
        n = 48;
        crypto.hmacSha384(secret, data, out[0:48]);
    } else if (a == Alg.hs512) {
        n = 64;
        crypto.hmacSha512(secret, data, out[0:64]);
    } else {
        crypto.hmacSha256(secret, data, out[0:32]);
    }
    return str.from(out[0:n]);
}

/* ---- signing ---- */

/* What signs tokens: one algorithm, one key */
pub struct Signer {
    private Alg alg;
    private String kid;
    private String secret;          /* HS: a copy */
    private crypto.Key *key;        /* ES, RS: the caller's */
    private String extra;           /* header(): ,"name":value ... */
    private String crit;            /* the critical ones: "name","name" */
};

/* Header names the JOSE specs define (RFC 7515, 7516, 7518, 7797): not
 * for header(), and never listed in crit */
static bool registeredHeader(u8[] name) {
    u8 *names[21] = {"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
                     "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "b64"};
    for (i64 i = 0; i < 21; i++) {
        if (str.equals(name, cstrView(names[i]))) { return true; }
    }
    return false;
}

static Signer *signerNew(Alg a, u8[] secret, crypto.Key *key, u8[] kid) {
    Signer *s = mem.allocZero(sizeof(Signer));
    s.alg = a;
    s.kid = str.from(kid);
    s.secret = str.from(secret);
    s.key = key;
    return s;
}

static void needSecret(u8[] secret) {
    if (!secret.len) { throw(ERR_KEY, "jwt: an HMAC secret can't be empty"); }
}

/* HS256: an HMAC-SHA256 with secret (copied; 32 random bytes or more) */
pub Signer *hs256(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    return signerNew(Alg.hs256, secret, null, kid);
}

pub Signer *hs384(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    return signerNew(Alg.hs384, secret, null, kid);
}

pub Signer *hs512(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    return signerNew(Alg.hs512, secret, null, kid);
}

static u8 *kindName(crypto.KeyKind k) {
    if (k == crypto.KeyKind.rsa) { return "an RSA"; }
    if (k == crypto.KeyKind.ec384) { return "a P-384"; }
    if (k == crypto.KeyKind.ec521) { return "a P-521"; }
    if (k == crypto.KeyKind.ed25519) { return "an Ed25519"; }
    return "a P-256";
}

/* key is the kind alg a signs with */
static void needKey(crypto.Key *key, Alg a) {
    crypto.KeyKind kind = kindOf(a);
    if (!key || key.kind() != kind) { throw(ERR_KEY, "jwt: %s needs %s key", algName(a), kindName(kind)); }
}

static Signer *keySigner(Alg a, crypto.Key *key, u8[] kid) {
    needKey(key, a);
    return signerNew(a, "", key, kid);
}

/* ES256: ECDSA P-256 with key, a private one; it stays yours (keep it
 * while the Signer is used). ES384 (P-384) and ES512 (P-521) alike. */
pub Signer *es256(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.es256, key, kid); }
pub Signer *es384(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.es384, key, kid); }
pub Signer *es512(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.es512, key, kid); }

/* RS256: RSA PKCS#1 v1.5 over SHA-256 with key, a private RSA one; it
 * stays yours. RS384 and RS512 alike. */
pub Signer *rs256(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.rs256, key, kid); }
pub Signer *rs384(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.rs384, key, kid); }
pub Signer *rs512(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.rs512, key, kid); }

/* PS256: RSA-PSS over SHA-256 with key, a private RSA one (randomised:
 * two tokens of the same claims differ). PS384 and PS512 alike. */
pub Signer *ps256(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.ps256, key, kid); }
pub Signer *ps384(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.ps384, key, kid); }
pub Signer *ps512(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.ps512, key, kid); }

/* EdDSA: Ed25519 (RFC 8037) with key, a private Ed25519 one */
pub Signer *eddsa(crypto.Key *key, u8[] kid = "") { return keySigner(Alg.eddsa, key, kid); }

/* A token of payload (JSON text), a new String */
static String signJson(Signer *s, u8[] payload) {
    String head;
    head.append("{\"alg\":\"");
    head.append(cstrView(algName(s.alg)));
    head.append("\",\"typ\":\"JWT\"");
    if (s.kid.len) {
        head.append(",\"kid\":");
        json.quoteTo(&head, s.kid[0:]);
    }
    head.append(s.extra[0:]);
    if (s.crit.len) {
        head.append(",\"crit\":[");
        head.append(s.crit[0:]);
        head.append("]");
    }
    head.append("}");
    String token = base64.encodeUrl(head[0:]);
    head.free();
    String body = base64.encodeUrl(payload);
    token.append(".");
    token.append(body[0:]);
    body.free();
    String sig;
    if (isHmac(s.alg)) {
        sig = hmac(s.alg, s.secret[0:], token[0:]);
    } else if (s.alg == Alg.eddsa) {
        sig = s.key.sign(token[0:]);
    } else if (isPss(s.alg)) {
        sig = s.key.signPss(hashOf(s.alg), token[0:]);
    } else {
        sig = s.key.signWith(hashOf(s.alg), token[0:]);
    }
    String sig64 = base64.encodeUrl(sig[0:]);
    sig.free();
    token.append(".");
    token.append(sig64[0:]);
    sig64.free();
    return token;
}

/* A signed token of claims (a @json struct), a new String (yours) */
pub String Signer.sign<T>(T claims) {
    String payload = json.encode(reflect.of(claims));
    String token = signJson(self, payload[0:]);
    payload.free();
    return token;
}

/* One more header member: name (not one the specs define) with value,
 * JSON text ("1", "\"text\"", "{...}"); critical lists it in "crit",
 * so a verifier that doesn't understand it refuses the token (RFC 7515
 * 4.1.11). Throws ERR_MALFORMED for a defined name or a value that isn't
 * JSON. */
pub void Signer.header(u8[] name, u8[] value, bool critical = false) {
    if (!name.len || registeredHeader(name)) {
        throw(ERR_MALFORMED, "jwt: \"%.*s\" isn't a header of its own to add", name.len, name.ptr);
    }
    json.Value *j = json.parse(value);
    bool ok = j && json.ok(j);
    if (j) { json.release(j); }
    if (!ok) { throw(ERR_MALFORMED, "jwt: the value of header %.*s isn't JSON", name.len, name.ptr); }
    self.extra.append(",");
    json.quoteTo(&self.extra, name);
    self.extra.append(":");
    self.extra.append(value);
    if (critical) {
        if (self.crit.len) { self.crit.append(","); }
        json.quoteTo(&self.crit, name);
    }
}

pub void Signer.free() {
    if (!self) { return; }
    self.kid.free();
    self.extra.free();
    self.crit.free();
    for (i64 i = 0; i < self.secret.len; i++) { self.secret.ptr[i] = 0; }
    self.secret.free();
    mem.free(self);
}

/* ---- a token's parts ---- */

struct Parts {
    u8[] head64, body64, sig64;     /* views of the token */
    String head, body, sig;         /* decoded */
};

static void partsFree(Parts *p) {
    p.head.free();
    p.body.free();
    p.sig.free();
}

/* text in base64url, unpadded (JWS allows nothing else) into *out */
static bool b64url(u8[] text, String *out) {
    for (i64 i = 0; i < text.len; i++) {
        u8 c = text[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_';
        if (!ok) { return false; }
    }
    return base64.decode(text, out);
}

/* token split and decoded into *p; throws ERR_MALFORMED */
static void split(u8[] token, Parts *p) {
    i64 a = str.find(token, ".");
    i64 b = a < 0 ? -1 : str.find(token[a + 1:], ".");
    if (a < 0 || b < 0 || str.find(token[a + 1 + b + 1:], ".") >= 0) {
        throw(ERR_MALFORMED, "jwt: a token has three parts separated by dots");
    }
    p.head64 = token[0:a];
    p.body64 = token[a + 1:a + 1 + b];
    p.sig64 = token[a + 1 + b + 1:];
    if (!p.head64.len || !p.body64.len) {
        throw(ERR_MALFORMED, "jwt: a token's header and payload can't be empty");
    }
    if (!b64url(p.head64, &p.head) || !b64url(p.body64, &p.body) || !b64url(p.sig64, &p.sig)) {
        partsFree(p);
        throw(ERR_MALFORMED, "jwt: a part that isn't unpadded base64url");
    }
}

/* the parsed JSON object of text, or null */
static json.Value *object(u8[] text) {
    json.Value *j = json.parse(text);
    if (!j) { return null; }
    if (!json.ok(j) || !json.isObject(j)) {
        json.release(j);
        return null;
    }
    return j;
}

/* a string member of obj ("" when it has none); *bad when it is there
 * but isn't a string */
static u8[] member(json.Value *obj, u8[] key, bool *bad) {
    json.Value *m = json.objectGet(obj, key);
    if (!m) { return ""; }
    if (!json.isString(m)) {
        *bad = true;
        return "";
    }
    return m.str;
}

/* ---- verifying ---- */

/* A key a Verifier checks signatures with */
struct VKey {
    Alg alg;
    String kid;
    String secret;          /* HS: a copy */
    crypto.Key *key;        /* ES, RS */
    bool owned;             /* key is ours (from a JWK) */
};

static void vkeyFree(VKey *k) {
    k.kid.free();
    for (i64 i = 0; i < k.secret.len; i++) { k.secret.ptr[i] = 0; }
    k.secret.free();
    if (k.owned && k.key) { k.key.free(); }
    mem.free(k);
}

/* The keys of one JWKS fetch: verifies in other threads may still use
 * the set a fetch replaces, so it is freed when the last one is done */
struct KeySet {
    vec.Vec<VKey *> keys;
    i64 refs;
};

static void setRelease(KeySet *s) {
    for (i64 i = 0; i < s.keys.len; i++) { vkeyFree(s.keys.get(i)); }
    s.keys.free();
    mem.free(s);
}

/* What verifies tokens: the keys it trusts and the claims it checks.
 * Configure it once, then share it: verify can run in many threads at
 * once. */
pub struct Verifier {
    u8[] issuer;        /* "iss" must be this ("" : not checked); the text must outlive the Verifier */
    u8[] audience;      /* "aud" (a string or an array) must hold this ("" : not checked) */
    i64 leewaySec;      /* clock difference allowed for exp, nbf and iat (verifier(): 60) */
    bool requireExp;    /* a token without exp is refused (verifier(): true) */
    i64 now;            /* the time in Unix seconds (0: the clock); for tests */
    i64 jwksRetrySec;   /* an unknown kid refetches the JWKS at most this often (verifier(): 60) */
    private vec.Vec<VKey *> keys;   /* given: hs256(), jwks(), ... */
    private String url;             /* jwksUrl() */
    private i64 refreshMs;
    private KeySet *remote;         /* its keys */
    private i64 fetchedMs;          /* when they were fetched (date.monoMs) */
    private bool fetching;
    private libc.pthread_mutex_t lock;
    private vec.Vec<String> understood;    /* understand(): crit names it takes */
};

/* A Verifier that trusts no key yet, with the defaults: 60 s leeway,
 * exp required */
pub Verifier *verifier() {
    Verifier *v = mem.allocZero(sizeof(Verifier));
    v.leewaySec = 60;
    v.requireExp = true;
    v.jwksRetrySec = 60;
    v.keys = vec.new<VKey *>();
    v.understood = vec.new<String>();
    libc.pthread_mutex_init(&v.lock);
    return v;
}

static VKey *vkeyNew(Alg a, u8[] kid, u8[] secret, crypto.Key *key, bool owned) {
    VKey *k = mem.allocZero(sizeof(VKey));
    k.alg = a;
    k.kid = str.from(kid);
    k.secret = str.from(secret);
    k.key = key;
    k.owned = owned;
    return k;
}

/* Trust HS256 tokens made with secret (copied) */
pub void Verifier.hs256(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    self.keys.push(vkeyNew(Alg.hs256, kid, secret, null, false));
}

pub void Verifier.hs384(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    self.keys.push(vkeyNew(Alg.hs384, kid, secret, null, false));
}

pub void Verifier.hs512(u8[] secret, u8[] kid = "") {
    needSecret(secret);
    self.keys.push(vkeyNew(Alg.hs512, kid, secret, null, false));
}

static void keyTrust(Verifier *v, Alg a, crypto.Key *key, u8[] kid) {
    needKey(key, a);
    v.keys.push(vkeyNew(a, kid, "", key, false));
}

/* Trust ES256 tokens signed by key's private key (key, public or
 * private, stays yours: keep it while the Verifier is used); the others
 * alike, each for its kind of key */
pub void Verifier.es256(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.es256, key, kid); }
pub void Verifier.es384(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.es384, key, kid); }
pub void Verifier.es512(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.es512, key, kid); }
pub void Verifier.rs256(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.rs256, key, kid); }
pub void Verifier.rs384(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.rs384, key, kid); }
pub void Verifier.rs512(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.rs512, key, kid); }
pub void Verifier.ps256(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.ps256, key, kid); }
pub void Verifier.ps384(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.ps384, key, kid); }
pub void Verifier.ps512(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.ps512, key, kid); }
pub void Verifier.eddsa(crypto.Key *key, u8[] kid = "") { keyTrust(self, Alg.eddsa, key, kid); }

/* the bytes of a JWK member in base64url, false when missing or bad */
static bool jwkBytes(json.Value *k, u8[] name, String *out) {
    bool bad = false;
    u8[] text = member(k, name, &bad);
    return !bad && text.len && b64url(text, out);
}

/* The key of one JWK, null for one that can't be used here (another
 * kty or curve, use "enc", an alg not supported) */
static VKey *jwkKey(json.Value *k) {
    bool bad = false;
    u8[] kty = member(k, "kty", &bad);
    u8[] use = member(k, "use", &bad);
    u8[] alg = member(k, "alg", &bad);
    u8[] kid = member(k, "kid", &bad);
    if (bad || (use.len && !str.equals(use, "sig"))) { return null; }
    Alg a;
    if (alg.len && !algOf(alg, &a)) { return null; }
    /* an HMAC secret is never a JWK of a public key: no "alg": "HS256"
     * on an RSA or EC key (an empty secret anyone could sign with) */
    if (alg.len && isHmac(a)) { return null; }
    crypto.Key *key = null;
    String p1, p2;
    bool b2 = false;
    u8[] crv = member(k, "crv", &b2);
    try {
        if (str.equals(kty, "EC")) {
            /* the curve says the algorithm; "alg", when there, must agree */
            Alg ca;
            if (str.equals(crv, "P-256")) { ca = Alg.es256; }
            else if (str.equals(crv, "P-384")) { ca = Alg.es384; }
            else if (str.equals(crv, "P-521")) { ca = Alg.es512; }
            else { return null; }
            if (alg.len && a != ca) { return null; }
            a = ca;
            if (jwkBytes(k, "x", &p1) && jwkBytes(k, "y", &p2)) { key = crypto.ecPublicKey(p1[0:], p2[0:]); }
            if (key && key.kind() != kindOf(a)) {      /* x and y of another curve's size */
                key.free();
                key = null;
            }
        } else if (str.equals(kty, "RSA")) {
            if (!alg.len) { a = Alg.rs256; }    /* RS256 when the JWK doesn't say */
            if (kindOf(a) != crypto.KeyKind.rsa) { return null; }
            if (jwkBytes(k, "n", &p1) && jwkBytes(k, "e", &p2)) { key = crypto.rsaPublicKey(p1[0:], p2[0:]); }
        } else if (str.equals(kty, "OKP")) {
            /* RFC 8037: Ed25519 only (no Ed448, no X25519 for signing) */
            if (!str.equals(crv, "Ed25519") || (alg.len && a != Alg.eddsa)) { return null; }
            a = Alg.eddsa;
            if (jwkBytes(k, "x", &p1)) { key = crypto.ed25519PublicKey(p1[0:]); }
        }
    } catch {
        key = null;
    }
    p1.free();
    p2.free();
    if (!key) { return null; }
    return vkeyNew(a, kid, "", key, true);
}

/* The usable keys of a JWK Set (JSON text) into *out; throws ERR_KEY
 * when it isn't one or has none */
static void jwksParse(u8[] text, vec.Vec<VKey *> *out) {
    json.Value *j = object(text);
    if (!j) { throw(ERR_KEY, "jwt: a JWKS is a JSON object"); }
    json.Value *keys = json.objectGet(j, "keys");
    if (!keys || !json.isArray(keys)) {
        json.release(j);
        throw(ERR_KEY, "jwt: a JWKS has a \"keys\" array");
    }
    i64 n = json.len(keys), got = 0;
    for (i64 i = 0; i < n; i++) {
        json.Value *k = json.arrayGet(keys, i);
        if (!k || !json.isObject(k)) { continue; }
        VKey *vk = jwkKey(k);
        if (vk) {
            out.push(vk);
            got++;
        }
    }
    json.release(j);
    if (!got) { throw(ERR_KEY, "jwt: the JWKS has no key this package can use (EC P-256, RSA)"); }
}

/* Trust the keys of a JWK Set, JSON text: EC P-256 (ES256) and RSA
 * (its "alg", RS256 when it has none); others are skipped. Throws
 * ERR_KEY when it has none of them. */
pub void Verifier.jwks(u8[] text) {
    jwksParse(text, &self.keys);
}

/* the keys at v.url, null (and *why) when they can't be had */
static KeySet *jwksGet(Verifier *v, String *why) {
    KeySet *s = mem.allocZero(sizeof(KeySet));
    s.keys = vec.new<VKey *>();
    try {
        http.ClientOptions o;
        o.timeoutMs = 10000;
        o.maxBodyBytes = 1 << 20;
        /* fetched seldom: no connection kept open for the next time */
        http.Headers h;
        defer h.free();
        h.add("Connection", "close");
        ad http.Response r = http.request("GET", v.url[0:], "", &h, &o);
        if (r.status != 200) { throw(ERR_KEY, "jwt: the JWKS at %.*s answered %d", v.url.len, v.url.ptr, r.status); }
        jwksParse(r.body[0:], &s.keys);
    } catch (Error e) {
        *why = str.format("%s", e.message);
        setRelease(s);
        return null;
    }
    return s;
}

/* Trust the keys of the JWK Set at url (https:// or http://), fetched
 * now (ERR_KEY when that fails) and again every refreshSec, or when a
 * token names a kid the set doesn't have (at most every jwksRetrySec).
 * A fetch inside verify waits for the answer: in a loop coroutine (a
 * net.http handler) only the coroutine waits, elsewhere the thread. */
pub void Verifier.jwksUrl(u8[] url, i64 refreshSec = 3600) {
    self.url.free();
    self.url = str.from(url);
    self.refreshMs = refreshSec * 1000;
    String why;
    KeySet *s = jwksGet(self, &why);
    if (!s) {
        ad String msg = why;
        throw(ERR_KEY, "%.*s", msg.len, msg.ptr);
    }
    libc.pthread_mutex_lock(&self.lock);
    KeySet *old = self.remote;
    s.refs = 1;
    self.remote = s;
    self.fetchedMs = date.monoMs();
    libc.pthread_mutex_unlock(&self.lock);
    if (old) { releaseSet(self, old); }
}

/* one user of s fewer: the last frees it */
static void releaseSet(Verifier *v, KeySet *s) {
    libc.pthread_mutex_lock(&v.lock);
    bool last = --s.refs == 0;
    libc.pthread_mutex_unlock(&v.lock);
    if (last) { setRelease(s); }
}

/* the fetched keys, held (releaseSet when done); fetched again first
 * when they are old, or when force and the last fetch is long enough
 * ago. null without jwksUrl. */
static KeySet *remoteKeys(Verifier *v, bool force) {
    if (!v.url.len) { return null; }
    i64 now = date.monoMs();
    libc.pthread_mutex_lock(&v.lock);
    bool due = (v.refreshMs > 0 && now - v.fetchedMs >= v.refreshMs) ||
               (force && now - v.fetchedMs >= v.jwksRetrySec * 1000);
    bool fetch = due && !v.fetching;
    if (fetch) { v.fetching = true; }
    libc.pthread_mutex_unlock(&v.lock);
    if (fetch) {
        String why;
        KeySet *s = jwksGet(v, &why);       /* no lock held: it may wait */
        why.free();
        libc.pthread_mutex_lock(&v.lock);
        v.fetching = false;
        v.fetchedMs = date.monoMs();        /* a failure waits as long */
        KeySet *old = null;
        if (s) {
            s.refs = 1;
            old = v.remote;
            v.remote = s;
        }
        libc.pthread_mutex_unlock(&v.lock);
        if (old) { releaseSet(v, old); }
    }
    libc.pthread_mutex_lock(&v.lock);
    KeySet *s = v.remote;
    if (s) { s.refs++; }
    libc.pthread_mutex_unlock(&v.lock);
    return s;
}

/* does key k's signature over p hold? */
static bool sigHolds(VKey *k, Parts *p, u8[] signedPart) {
    if (isHmac(k.alg)) {
        String mac = hmac(k.alg, k.secret[0:], signedPart);
        bool ok = crypto.equal(mac[0:], p.sig[0:]);
        mac.free();
        return ok;
    }
    if (k.alg == Alg.eddsa) { return k.key.verify(signedPart, p.sig[0:]); }
    if (isPss(k.alg)) { return k.key.verifyPss(hashOf(k.alg), signedPart, p.sig[0:]); }
    /* ES is r||s, 64, 96 or 132 bytes: never the DER form */
    if (kindOf(k.alg) != crypto.KeyKind.rsa && p.sig.len != ecSigSize(k.alg)) { return false; }
    return k.key.verifyWith(hashOf(k.alg), signedPart, p.sig[0:]);
}

/* a key of keys for the token: with its kid when it has one, else one
 * whose alg matches; *found when there was a key to try at all, *kidSeen
 * when one had the kid */
static bool tryKeys(vec.Vec<VKey *> *keys, Alg a, u8[] kid, Parts *p, u8[] signedPart,
                    bool *found, bool *kidSeen) {
    for (i64 i = 0; i < keys.len; i++) {
        VKey *k = keys.get(i);
        if (kid.len && !str.equals(k.kid[0:], kid)) { continue; }
        if (kid.len) { *kidSeen = true; }
        if (k.alg != a) { continue; }
        *found = true;
        if (sigHolds(k, p, signedPart)) { return true; }
    }
    return false;
}

/* the signature checked against the trusted keys; throws ERR_ALG,
 * ERR_KEY or ERR_SIGNATURE */
static void checkSignature(Verifier *v, Alg a, u8[] kid, Parts *p, u8[] signedPart) {
    bool found = false, kidSeen = false;
    if (tryKeys(&v.keys, a, kid, p, signedPart, &found, &kidSeen)) { return; }
    for (i64 round = 0; round < 2; round++) {
        /* the second round: the kid wasn't there, fetch again */
        if (round == 1 && !(kid.len && !kidSeen)) { break; }
        KeySet *s = remoteKeys(v, round == 1);
        if (!s) { break; }
        bool ok = tryKeys(&s.keys, a, kid, p, signedPart, &found, &kidSeen);
        releaseSet(v, s);
        if (ok) { return; }
    }
    if (kid.len && !kidSeen) {
        throw(ERR_KEY, "jwt: no key with kid \"%.*s\"", kid.len, kid.ptr);
    }
    if (!found) {
        throw(ERR_ALG, "jwt: no %s key is configured%s", algName(a), kid.len ? " with that kid" : "");
    }
    throw(ERR_SIGNATURE, "jwt: the signature doesn't match");
}

/* a NumericDate claim into *t: false when absent; throws when it isn't
 * a number */
static bool numClaim(json.Value *obj, u8[] name, i64 *t) {
    json.Value *m = json.objectGet(obj, name);
    if (!m) { return false; }
    if (json.isInt(m)) {
        *t = m.intVal;
    } else if (json.isFloat(m)) {
        *t = (i64)m.floatVal;
    } else {
        throw(ERR_CLAIM, "jwt: \"%.*s\" is not a number", name.len, name.ptr);
    }
    return true;
}

/* exp, nbf, iat, iss and aud checked; throws ERR_EXPIRED, ERR_NOT_YET
 * or ERR_CLAIM */
static void checkClaims(Verifier *v, json.Value *c) {
    i64 now = v.now ? v.now : date.unixNow();
    i64 t = 0;
    if (numClaim(c, "exp", &t)) {
        if (now >= t + v.leewaySec) { throw(ERR_EXPIRED, "jwt: the token expired %d s ago", now - t); }
    } else if (v.requireExp) {
        throw(ERR_CLAIM, "jwt: the token has no exp");
    }
    if (numClaim(c, "nbf", &t) && now + v.leewaySec < t) {
        throw(ERR_NOT_YET, "jwt: the token is good from %d, in %d s", t, t - now);
    }
    if (numClaim(c, "iat", &t) && now + v.leewaySec < t) {
        throw(ERR_NOT_YET, "jwt: the token was issued in the future (iat %d)", t);
    }
    if (v.issuer.len) {
        bool bad = false;
        u8[] iss = member(c, "iss", &bad);
        if (bad || !str.equals(iss, v.issuer)) {
            throw(ERR_CLAIM, "jwt: iss is \"%.*s\", not \"%.*s\"", iss.len, iss.ptr, v.issuer.len, v.issuer.ptr);
        }
    }
    if (v.audience.len) {
        json.Value *aud = json.objectGet(c, "aud");
        bool ok = false;
        if (aud && json.isString(aud)) {
            ok = str.equals(aud.str, v.audience);
        } else if (aud && json.isArray(aud)) {
            for (i64 i = 0; i < json.len(aud) && !ok; i++) {
                json.Value *a = json.arrayGet(aud, i);
                ok = a && json.isString(a) && str.equals(a.str, v.audience);
            }
        }
        if (!ok) { throw(ERR_CLAIM, "jwt: aud doesn't hold \"%.*s\"", v.audience.len, v.audience.ptr); }
    }
}

/* Header extensions the application handles, as a token's "crit" lists
 * them (RFC 7515 4.1.11): a token whose crit names one not understood is
 * refused (ERR_MALFORMED). Read their values with jwt.headerValue. Not
 * for the names the specs define, "b64" (RFC 7797, unencoded payloads)
 * among them. */
pub void Verifier.understand(u8[] name) {
    if (!name.len || registeredHeader(name)) {
        throw(ERR_MALFORMED, "jwt: \"%.*s\" is a header this package handles itself", name.len, name.ptr);
    }
    self.understood.push(str.from(name));
}

/* a token's crit: a list of names, each understood, none the specs
 * define, each in the header; throws ERR_MALFORMED */
static void checkCrit(Verifier *v, json.Value *h, json.Value *crit) {
    if (!json.isArray(crit) || json.len(crit) == 0) {
        throw(ERR_MALFORMED, "jwt: crit is a list of header names");
    }
    for (i64 i = 0; i < json.len(crit); i++) {
        json.Value *c = json.arrayGet(crit, i);
        if (!c || !json.isString(c)) { throw(ERR_MALFORMED, "jwt: crit is a list of header names"); }
        if (registeredHeader(c.str)) {
            throw(ERR_MALFORMED, "jwt: crit can't list %.*s, a header the specs define", c.str.len, c.str.ptr);
        }
        bool known = false;
        for (i64 k = 0; k < v.understood.len && !known; k++) {
            String *u = v.understood.at(k);
            known = str.equals(u.ptr[0:u.len], c.str);
        }
        if (!known) {
            throw(ERR_MALFORMED, "jwt: the token needs header %.*s understood (crit)", c.str.len, c.str.ptr);
        }
        if (!json.objectGet(h, c.str)) {
            throw(ERR_MALFORMED, "jwt: crit lists %.*s, which the header hasn't", c.str.len, c.str.ptr);
        }
    }
}

/* token verified: its alg, signature and claims; *p holds its parts
 * (partsFree), throws ERR_* */
static void verifyParts(Verifier *v, u8[] token, Parts *p) {
    split(token, p);
    json.Value *h = null, *c = null;
    try {
        h = object(p.head[0:]);
        if (!h) { throw(ERR_MALFORMED, "jwt: the header isn't a JSON object"); }
        json.Value *crit = json.objectGet(h, "crit");
        if (crit) { checkCrit(v, h, crit); }
        bool bad = false;
        u8[] algText = member(h, "alg", &bad);
        u8[] kid = member(h, "kid", &bad);
        if (bad) { throw(ERR_MALFORMED, "jwt: alg and kid are strings"); }
        Alg a;
        if (!algOf(algText, &a)) {
            throw(ERR_ALG, "jwt: alg \"%.*s\" isn't accepted", algText.len, algText.ptr);
        }
        checkSignature(v, a, kid, p, token[0:p.head64.len + 1 + p.body64.len]);
        c = object(p.body[0:]);
        if (!c) { throw(ERR_MALFORMED, "jwt: the payload isn't a JSON object"); }
        checkClaims(v, c);
    } catch (Error e) {
        if (h) { json.release(h); }
        if (c) { json.release(c); }
        partsFree(p);
        throw(e);
    }
    json.release(h);
    json.release(c);
}

/* The claims of token, a @json struct, once it is verified: alg is one
 * a trusted key has, the signature holds, and exp, nbf, iat, iss and
 * aud are as the Verifier wants. Throws ERR_MALFORMED, ERR_ALG, ERR_KEY,
 * ERR_SIGNATURE, ERR_EXPIRED, ERR_NOT_YET or ERR_CLAIM (claims that
 * don't fit T too). */
pub T Verifier.verify<T>(u8[] token) {
    Parts p;
    verifyParts(self, token, &p);
    T out;
    try {
        out = json.decode<T>(p.body[0:]);
    } catch (Error e) {
        partsFree(&p);
        throw(ERR_CLAIM, "jwt: the claims don't fit: %s", e.message);
    }
    partsFree(&p);
    return out;
}

/* Is token good? verify without the claims; false (no throw) when not */
pub bool Verifier.valid(u8[] token) {
    Parts p;
    try {
        verifyParts(self, token, &p);
    } catch {
        return false;
    }
    partsFree(&p);
    return true;
}

/* A token's header, NOT verified: to choose a key or to log. Throws
 * ERR_MALFORMED. Free it with json.free(reflect.of(h)). */
pub Header header(u8[] token) {
    Parts p;
    split(token, &p);
    Header h;
    try {
        h = json.decode<Header>(p.head[0:]);
    } catch (Error e) {
        partsFree(&p);
        throw(ERR_MALFORMED, "jwt: the header: %s", e.message);
    }
    partsFree(&p);
    return h;
}

/* The JSON text of a header member of token, as json.toStr writes it
 * ("" when it has none), NOT verified: read it after verify, as for a
 * crit extension. Throws ERR_MALFORMED. A new String (yours). */
pub String headerValue(u8[] token, u8[] name) {
    Parts p;
    split(token, &p);
    json.Value *h = object(p.head[0:]);
    partsFree(&p);
    if (!h) { throw(ERR_MALFORMED, "jwt: the header isn't a JSON object"); }
    json.Value *m = json.objectGet(h, name);
    String out = m ? json.toStr(m) : str.from("");
    json.release(h);
    return out;
}

/* A token's claims, NOT verified: for debugging only, never to trust */
pub T decodeUnverified<T>(u8[] token) {
    Parts p;
    split(token, &p);
    T out;
    try {
        out = json.decode<T>(p.body[0:]);
    } catch (Error e) {
        partsFree(&p);
        throw(ERR_MALFORMED, "jwt: the payload: %s", e.message);
    }
    partsFree(&p);
    return out;
}

pub void Verifier.free() {
    if (!self) { return; }
    for (i64 i = 0; i < self.understood.len; i++) { self.understood.at(i).free(); }
    self.understood.free();
    for (i64 i = 0; i < self.keys.len; i++) { vkeyFree(self.keys.get(i)); }
    self.keys.free();
    if (self.remote) { releaseSet(self, self.remote); }
    self.url.free();
    libc.pthread_mutex_destroy(&self.lock);
    mem.free(self);
}
