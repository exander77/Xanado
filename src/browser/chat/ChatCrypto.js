/*Copyright (C) 2024 The Xanado Project
  License MIT. See README.md for details. Author Codex AI */
/* eslint-env browser */

const globalScope = typeof window !== "undefined" ? window : globalThis;
const subtle = globalScope.crypto && globalScope.crypto.subtle;
const TEXT_ENCODER = typeof TextEncoder !== "undefined"
  ? new TextEncoder() : undefined;
const TEXT_DECODER = typeof TextDecoder !== "undefined"
  ? new TextDecoder() : undefined;
const SECURE_CONTEXT = typeof window !== "undefined"
  ? !!window.isSecureContext : true;

const normalizeDigest = digest => {
  if (typeof digest !== "string" || digest.length === 0)
    return "SHA-256";
  const upper = digest.toUpperCase();
  switch (upper.replace(/_/g, "-")) {
  case "SHA256": case "SHA-256": return "SHA-256";
  case "SHA384": case "SHA-384": return "SHA-384";
  case "SHA512": case "SHA-512": return "SHA-512";
  default: return upper;
  }
};

const RSA_IMPORT_PARAMS = {
  name: "RSA-OAEP",
  hash: "SHA-256"
};
const AES_ALGORITHM = "AES-GCM";
const AES_IV_BYTES = 12;
const SYMMETRIC_KEY_BYTES = 32;

const STORAGE_PREFIX = "XANADO_CHAT_PRIV_";
export const CHAT_PASSWORD_CACHE_KEY = "XANADO_LAST_PASS";
const SESSION_WRAP_PREFIX = "XANADO_CHAT_WRAP_";
const BROADCAST_PREFIX = "XANADO_CHAT_CHANNEL_";
const CHAT_CACHE_MODES = {
  SESSION: "session",
  PERSISTENT: "persistent"
};
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_ITERATIONS = 200000;
const PERSISTENT_VERSION = 2;

const decodeBase64 = data => globalScope.atob
  ? globalScope.atob(data)
  : (globalScope.Buffer
     ? globalScope.Buffer.from(data, "base64").toString("binary")
     : "");

const encodeBase64 = binary => globalScope.btoa
  ? globalScope.btoa(binary)
  : (globalScope.Buffer
     ? globalScope.Buffer.from(binary, "binary").toString("base64")
     : "");

const base64ToArrayBuffer = b64 => {
  const binary = decodeBase64(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

const arrayBufferToBase64 = buffer => {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++)
    binary += String.fromCharCode(bytes[i]);
  return encodeBase64(binary);
};

const pemToArrayBuffer = pem => {
  const clean = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return base64ToArrayBuffer(clean);
};

const concatBuffers = (bufA, bufB) => {
  const a = new Uint8Array(bufA);
  const b = new Uint8Array(bufB);
  const combined = new Uint8Array(a.length + b.length);
  combined.set(a, 0);
  combined.set(b, a.length);
  return combined.buffer;
};

const normalizePersistence = mode =>
      (mode === CHAT_CACHE_MODES.SESSION
       ? CHAT_CACHE_MODES.SESSION
       : CHAT_CACHE_MODES.PERSISTENT);

const derivePasswordKey = (password, salt, iterations = PASSWORD_ITERATIONS) => {
  if (!TEXT_ENCODER)
    return Promise.reject(new Error("No encoder"));
  return subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(password),
    { name: "PBKDF2" },
    false,
    [ "deriveKey" ])
  .then(baseKey => subtle.deriveKey({
    name: "PBKDF2",
    salt,
    iterations,
    hash: "SHA-256"
  }, baseKey, {
    name: AES_ALGORITHM,
    length: SYMMETRIC_KEY_BYTES * 8
  }, false, [ "encrypt", "decrypt" ]));
};

/**
 * Manage chat encryption/decryption keys in the browser.
 */
class ChatCrypto {

  constructor(session, options = {}) {
    this.session = session || {};
    this.userKey = this.session && this.session.key;
    this.publicKeyPem = this.session?.encryption?.publicKey;
    this.encryptedPrivateKey = this.session?.encryption?.privateKey;
    this.storageKey = this.userKey ? `${STORAGE_PREFIX}${this.userKey}` : undefined;
    this.wrapStorageKey = this.userKey ? `${SESSION_WRAP_PREFIX}${this.userKey}` : undefined;
    this.persistence = normalizePersistence(options.persistence);
    this.privateKeyPem = undefined;
    this.privateKey = undefined;
    this.wrapMaterial = undefined;
    this.wrapKey = undefined;
    this.wrapRequests = new Map();
    this.supported = !!(subtle && TEXT_ENCODER && TEXT_DECODER);
    this.channel = (typeof BroadcastChannel !== "undefined" && this.userKey)
      ? new BroadcastChannel(`${BROADCAST_PREFIX}${this.userKey}`)
      : undefined;
    if (this.channel)
      this.channel.onmessage = event => this.handleChannelMessage(event);
  }

  isSupported() {
    return this.supported;
  }

  hasMaterial() {
    return !!(this.publicKeyPem && this.encryptedPrivateKey);
  }

  hasUnlockedKey() {
    return !!this.privateKey;
  }

  /**
   * Attempt to read and import a cached private key from localStorage.
   * @return {Promise<boolean>} resolves true if a key was loaded
   */
  loadFromStorage(password) {
    if (!this.isSupported() || !SECURE_CONTEXT || !this.storageKey)
      return Promise.resolve(false);
    const cached = globalScope.localStorage
    && globalScope.localStorage.getItem(this.storageKey);
    if (!cached)
      return Promise.resolve(false);
    let payload;
    try {
      payload = JSON.parse(cached);
    } catch (e) {
      payload = cached;
    }
    const importPem = pem => this.importPrivateKey(pem)
    .then(key => {
      this.privateKey = key;
      this.privateKeyPem = pem;
      return this.persistPrivateKey(pem, password)
      .then(() => true);
    });
    if (typeof payload === "string")
      return importPem(payload)
      .catch(() => {
        this.lock();
        return false;
      });
    if (!payload || typeof payload !== "object"
        || !payload.ciphertext || !payload.iv)
      return Promise.resolve(false);
    const mode = payload.mode || CHAT_CACHE_MODES.SESSION;
    if ((mode === CHAT_CACHE_MODES.PERSISTENT || payload.salt)
        && (typeof password !== "string" || password.length === 0))
      return Promise.resolve(false);
    const decryptor = (mode === CHAT_CACHE_MODES.PERSISTENT || payload.salt)
      ? this.decryptPersistentPayload(payload, password)
      : this.decryptSessionPayload(payload);
    return decryptor
    .then(pem => importPem(pem))
    .catch(e => {
      console.error("Failed to load cached private key", e);
      this.lock();
      return false;
    });
  }

  /**
   * Remove cached keys from both memory and storage.
   */
 lock() {
    if (this.wrapStorageKey && globalScope.sessionStorage)
      globalScope.sessionStorage.removeItem(this.wrapStorageKey);
    this.privateKey = undefined;
    this.privateKeyPem = undefined;
    this.wrapKey = undefined;
    this.wrapMaterial = undefined;
  }

  /**
   * Unlock (and persist) the private key using the supplied password.
   * @param {string} password plaintext password
   * @return {Promise<boolean>} resolves true on success
   */
  unlockWithPassword(password) {
    if (!this.isSupported() || !this.encryptedPrivateKey)
      return Promise.reject(new Error("Encryption not available"));
    if (typeof password !== "string" || password.length === 0)
      return Promise.reject(new Error("Password required"));
    return this.decryptPrivateKeyPem(password)
    .then(pem => this.importPrivateKey(pem)
          .then(key => {
            this.privateKeyPem = pem;
            this.privateKey = key;
            return this.persistPrivateKey(pem, password).then(() => true);
          }));
  }

  /**
   * Encrypt a message for the provided recipients.
   * @param {string} text plaintext message
   * @param {Object<string,string>} recipients map of userKey -> publicKey PEM
   * @return {Promise<object>} encrypted payload
   */
  encrypt(text, recipients) {
    if (!this.isSupported() || !recipients || Object.keys(recipients).length === 0)
      return Promise.reject(new Error("No recipients available"));
    const encoder = TEXT_ENCODER;
    const symmetricKey = globalScope.crypto.getRandomValues(new Uint8Array(SYMMETRIC_KEY_BYTES));
    const iv = globalScope.crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
    return subtle.importKey(
      "raw",
      symmetricKey,
      { name: AES_ALGORITHM },
      false,
      ["encrypt", "decrypt"])
    .then(aesKey => subtle.encrypt(
      { name: AES_ALGORITHM, iv },
      aesKey,
      encoder.encode(text)))
    .then(cipherBuffer => {
      const recipientEntries = {};
      const wrapPromises = Object.entries(recipients)
      .map(([key, pem]) => {
        if (!pem)
          return Promise.resolve();
        return this.importPublicKey(pem)
        .then(pubKey => subtle.encrypt(
          RSA_IMPORT_PARAMS,
          pubKey,
          symmetricKey))
        .then(wrapped => {
          recipientEntries[key] = {
            algorithm: "RSA-OAEP",
            wrappedKey: arrayBufferToBase64(wrapped)
          };
        });
      });
      return Promise.all(wrapPromises)
      .then(() => ({
        encrypted: true,
        algorithm: AES_ALGORITHM,
        version: 1,
        iv: arrayBufferToBase64(iv.buffer),
        ciphertext: arrayBufferToBase64(cipherBuffer),
        recipients: recipientEntries,
        playersOnly: true,
        timestamp: Date.now()
      }));
    });
  }

  /**
   * Decrypt an incoming message.
   * @param {object} message encrypted message payload
   * @return {Promise<string>} plaintext string
   */
  decrypt(message) {
    if (!this.isSupported() || !message.encrypted)
      return Promise.reject(new Error("Not encrypted"));
    if (!this.userKey || !message.recipients || !message.recipients[this.userKey])
      return Promise.reject(new Error("No key for recipient"));
    const entry = message.recipients[this.userKey];
    if (!entry || !entry.wrappedKey)
      return Promise.reject(new Error("Missing wrapped key"));
    const ensureKey = this.privateKey
          ? Promise.resolve(this.privateKey)
          : this.loadFromStorage().then(() => this.privateKey);
    return ensureKey
    .then(key => {
      if (!key)
        throw new Error("locked");
      return subtle.decrypt(
        RSA_IMPORT_PARAMS,
        key,
        base64ToArrayBuffer(entry.wrappedKey));
    })
    .then(symKeyBuffer => subtle.importKey(
      "raw",
      symKeyBuffer,
      { name: AES_ALGORITHM },
      false,
      ["decrypt"]))
    .then(aesKey => {
      const cipher = base64ToArrayBuffer(message.ciphertext);
      const tag = message.tag ? base64ToArrayBuffer(message.tag) : null;
      const payload = tag ? concatBuffers(cipher, tag) : cipher;
      return subtle.decrypt(
        {
          name: AES_ALGORITHM,
          iv: base64ToArrayBuffer(message.iv),
          tagLength: 128
        },
        aesKey,
        payload);
    })
    .then(buffer => TEXT_DECODER.decode(buffer));
  }

  persistPrivateKey(pem, password) {
    if (!this.isSupported() || !SECURE_CONTEXT || !this.storageKey || !pem)
      return Promise.resolve();
    if (!globalScope.localStorage || !globalScope.crypto || !globalScope.crypto.getRandomValues)
      return Promise.resolve();
    if (this.persistence === CHAT_CACHE_MODES.PERSISTENT)
      return this.persistWithPassword(pem, password);
    return this.persistWithSessionWrap(pem);
  }

  persistWithSessionWrap(pem) {
    return this.ensureSessionWrapKey()
    .then(wrapKey => {
      if (!wrapKey)
        return;
      const iv = globalScope.crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
      return subtle.encrypt({
        name: AES_ALGORITHM,
        iv
      }, wrapKey, TEXT_ENCODER.encode(pem))
      .then(cipher => {
        const payload = {
          version: 1,
          mode: CHAT_CACHE_MODES.SESSION,
          iv: arrayBufferToBase64(iv.buffer),
          ciphertext: arrayBufferToBase64(cipher)
        };
        globalScope.localStorage.setItem(this.storageKey, JSON.stringify(payload));
      });
    })
    .catch(e => console.error("Failed to persist chat key", e));
  }

  persistWithPassword(pem, password) {
    if (typeof password !== "string" || password.length === 0)
      return Promise.resolve();
    const salt = globalScope.crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES));
    const iv = globalScope.crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
    return derivePasswordKey(password, salt.buffer)
    .then(key => subtle.encrypt({
      name: AES_ALGORITHM,
      iv
    }, key, TEXT_ENCODER.encode(pem)))
    .then(cipher => {
      const payload = {
        version: PERSISTENT_VERSION,
        mode: CHAT_CACHE_MODES.PERSISTENT,
        salt: arrayBufferToBase64(salt.buffer),
        iterations: PASSWORD_ITERATIONS,
        iv: arrayBufferToBase64(iv.buffer),
        ciphertext: arrayBufferToBase64(cipher)
      };
      globalScope.localStorage.setItem(this.storageKey, JSON.stringify(payload));
    })
    .catch(e => console.error("Failed to persist chat key", e));
  }

  ensureSessionWrapKey() {
    if (!this.isSupported()
        || !this.wrapStorageKey
        || !globalScope.sessionStorage
        || !globalScope.crypto
        || !globalScope.crypto.subtle)
      return Promise.resolve(null);
    let material = globalScope.sessionStorage.getItem(this.wrapStorageKey);
    if (material) {
      this.wrapMaterial = material;
      return this.importWrapKey(material);
    }
    if (this.wrapMaterial)
      return this.importWrapKey(this.wrapMaterial);
    return this.requestWrapMaterial()
    .then(received => {
      if (received) {
        globalScope.sessionStorage.setItem(this.wrapStorageKey, received);
        this.wrapMaterial = received;
        return this.importWrapKey(received);
      }
      const bytes = globalScope.crypto.getRandomValues(
        new Uint8Array(SYMMETRIC_KEY_BYTES));
      material = arrayBufferToBase64(bytes.buffer);
      globalScope.sessionStorage.setItem(this.wrapStorageKey, material);
      this.wrapMaterial = material;
      this.broadcastWrapMaterial();
      return this.importWrapKey(material);
    });
  }

  decryptSessionPayload(payload) {
    return this.ensureSessionWrapKey()
    .then(wrapKey => {
      if (!wrapKey)
        throw new Error("No session key");
      return subtle.decrypt({
        name: AES_ALGORITHM,
        iv: base64ToArrayBuffer(payload.iv)
      }, wrapKey, base64ToArrayBuffer(payload.ciphertext));
    })
    .then(buffer => TEXT_DECODER.decode(buffer));
  }

  decryptPersistentPayload(payload, password) {
    if (typeof password !== "string" || password.length === 0)
      return Promise.reject(new Error("Password required"));
    if (!payload.salt)
      return Promise.reject(new Error("Missing salt"));
    const salt = base64ToArrayBuffer(payload.salt);
    const iterations = payload.iterations || PASSWORD_ITERATIONS;
    return derivePasswordKey(password, salt, iterations)
    .then(key => subtle.decrypt({
      name: AES_ALGORITHM,
      iv: base64ToArrayBuffer(payload.iv)
    }, key, base64ToArrayBuffer(payload.ciphertext)))
    .then(buffer => TEXT_DECODER.decode(buffer));
  }

  importWrapKey(material) {
    if (this.wrapKey && this.wrapMaterial === material)
      return Promise.resolve(this.wrapKey);
    return subtle.importKey(
      "raw",
      base64ToArrayBuffer(material),
      { name: AES_ALGORITHM },
      false,
      ["encrypt", "decrypt"])
    .then(key => {
      this.wrapKey = key;
      this.wrapMaterial = material;
      return key;
    })
    .catch(e => {
      console.error("Failed to import wrap key", e);
      return null;
    });
  }

  requestWrapMaterial() {
    if (!this.channel)
      return Promise.resolve(null);
    const generator = globalScope.crypto && globalScope.crypto.randomUUID
      ? () => globalScope.crypto.randomUUID()
      : () => `${Date.now()}-${Math.random()}`;
    const requestId = generator();
    return new Promise(resolve => {
      const timeout = globalScope.setTimeout(() => {
        this.wrapRequests.delete(requestId);
        resolve(null);
      }, 1000);
      this.wrapRequests.set(requestId, { resolve, timeout });
      this.channel.postMessage({ type: "WRAP_REQUEST", id: requestId });
    });
  }

  broadcastWrapMaterial() {
    if (!this.channel || !this.wrapMaterial)
      return;
    this.channel.postMessage({
      type: "WRAP_ANNOUNCE",
      wrap: this.wrapMaterial
    });
  }

  handleChannelMessage(event) {
    const data = event && event.data;
    if (!data || data.userKey && data.userKey !== this.userKey)
      return;
    switch (data.type) {
    case "WRAP_REQUEST":
      if (this.wrapMaterial)
        this.channel.postMessage({
          type: "WRAP_RESPONSE",
          id: data.id,
          wrap: this.wrapMaterial
        });
      break;
    case "WRAP_RESPONSE": {
      const pending = this.wrapRequests.get(data.id);
      if (pending) {
        globalScope.clearTimeout(pending.timeout);
        this.wrapRequests.delete(data.id);
        pending.resolve(data.wrap || null);
      }
      break;
    }
    case "WRAP_ANNOUNCE":
      if (data.wrap && !this.wrapMaterial) {
        this.wrapMaterial = data.wrap;
        if (this.wrapStorageKey && globalScope.sessionStorage)
          globalScope.sessionStorage.setItem(this.wrapStorageKey, data.wrap);
      }
      break;
    default:
      break;
    }
  }

  importPublicKey(pem) {
    return subtle.importKey(
      "spki",
      pemToArrayBuffer(pem),
      RSA_IMPORT_PARAMS,
      true,
      ["encrypt"]);
  }

  importPrivateKey(pem) {
    return subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(pem),
      RSA_IMPORT_PARAMS,
      true,
      ["decrypt"]);
  }

  decryptPrivateKeyPem(password) {
    const wrap = this.encryptedPrivateKey;
    if (!wrap)
      return Promise.reject(new Error("No encrypted material"));
    if (!SECURE_CONTEXT)
      return Promise.reject(new Error("Unlocking chat keys requires HTTPS (isSecureContext=false)"));
    const keyLengthBits = (wrap.pbkdf2.keylen || SYMMETRIC_KEY_BYTES) * 8;
    const hashName = normalizeDigest(wrap.pbkdf2.digest);
    return subtle.importKey(
      "raw",
      TEXT_ENCODER.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"])
    .then(keyMaterial => subtle.deriveBits({
      name: "PBKDF2",
      salt: base64ToArrayBuffer(wrap.pbkdf2.salt),
      iterations: wrap.pbkdf2.iterations,
      hash: hashName
    }, keyMaterial, keyLengthBits))
    .then(bits => subtle.importKey(
      "raw",
      bits,
      { name: AES_ALGORITHM },
      false,
      ["decrypt"]))
    .then(aesKey => {
      const cipher = base64ToArrayBuffer(wrap.ciphertext);
      const tag = base64ToArrayBuffer(wrap.tag);
      const payload = concatBuffers(cipher, tag);
      return subtle.decrypt({
        name: AES_ALGORITHM,
        iv: base64ToArrayBuffer(wrap.iv),
        tagLength: 128
      }, aesKey, payload);
    })
    .then(buffer => TEXT_DECODER.decode(buffer));
  }
}

export { ChatCrypto }
