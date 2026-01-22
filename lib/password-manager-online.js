"use strict";
/********* External Imports ********/
const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
var subtle = window.crypto.subtle;
/********* Constants ********/
const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters
/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   * You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor() {
    this.data = {
      kvs: {},
      salt: null,
      verifyTag: null,
    };
    this.secrets = {
      aesKey: null,
      domainHmacKey: null,
    };
  }
  /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   * password: string
   * Return Type: void
   */
  static async init(password) {
    let kc = new Keychain();
    let salt = getRandomBytes(16);
    kc.data.salt = encodeBuffer(salt);
    let rawKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    let masterHmacKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"],
    );
    let aesKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("aes-key"),
    );
    kc.secrets.aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"],
    );
    let domainHmacKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("domain-key"),
    );
    kc.secrets.domainHmacKey = await subtle.importKey(
      "raw",
      domainHmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
    let verifyKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("verify-key"),
    );
    let verifyKey = await subtle.importKey(
      "raw",
      verifyKeyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
    let verifyTag = await subtle.sign(
      "HMAC",
      verifyKey,
      stringToBuffer("verify"),
    );
    kc.data.verifyTag = encodeBuffer(verifyTag);
    return kc;
  }
  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   * password: string
   * repr: string
   * trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    let hashBuf = await subtle.digest("SHA-256", stringToBuffer(repr));
    let computedCheck = encodeBuffer(hashBuf);
    if (trustedDataCheck !== undefined && trustedDataCheck !== computedCheck) {
      throw "Integrity check failed";
    }
    let data = JSON.parse(repr);
    let kc = new Keychain();
    kc.data = data;
    let salt = decodeBuffer(data.salt);
    let rawKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    let masterHmacKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"],
    );
    let aesKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("aes-key"),
    );
    kc.secrets.aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"],
    );
    let domainHmacKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("domain-key"),
    );
    kc.secrets.domainHmacKey = await subtle.importKey(
      "raw",
      domainHmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
    let verifyKeyMaterial = await subtle.sign(
      "HMAC",
      masterHmacKey,
      stringToBuffer("verify-key"),
    );
    let verifyKey = await subtle.importKey(
      "raw",
      verifyKeyMaterial,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
    let verifyTag = await subtle.sign(
      "HMAC",
      verifyKey,
      stringToBuffer("verify"),
    );
    let computedVerifyTag = encodeBuffer(verifyTag);
    if (computedVerifyTag !== kc.data.verifyTag) {
      throw "Invalid password";
    }
    return kc;
  }
  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   * arr[0] = JSON encoding of password manager
   * arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity.
   *
   * Return Type: array
   */
  async dump() {
    let ser = JSON.stringify(this.data);
    let hashBuf = await subtle.digest("SHA-256", stringToBuffer(ser));
    let checksum = encodeBuffer(hashBuf);
    return [ser, checksum];
  }
  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null.
   *
   * Arguments:
   * name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    let domainBuf = stringToBuffer(name);
    let hashedBuf = await subtle.sign(
      "HMAC",
      this.secrets.domainHmacKey,
      domainBuf,
    );
    let hashed = encodeBuffer(hashedBuf);
    if (!(hashed in this.data.kvs)) {
      return null;
    }
    let entry = this.data.kvs[hashed];
    let iv = decodeBuffer(entry.iv);
    let ct = decodeBuffer(entry.ct);
    try {
      let decrypted = await subtle.decrypt(
        { name: "AES-GCM", iv: iv, additionalData: domainBuf, tagLength: 128 },
        this.secrets.aesKey,
        ct,
      );
      let padded = new Uint8Array(decrypted);
      let len = padded[0];
      let pwBuf = padded.slice(1, 1 + len);
      return bufferToString(pwBuf.buffer);
    } catch (e) {
      throw "Tampering detected";
    }
  }
  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager.
   *
   * Arguments:
   * name: string
   * value: string
   * Return Type: void
   */
  async set(name, value) {
    if (value.length > MAX_PASSWORD_LENGTH) {
      throw "Password too long";
    }
    let domainBuf = stringToBuffer(name);
    let hashedBuf = await subtle.sign(
      "HMAC",
      this.secrets.domainHmacKey,
      domainBuf,
    );
    let hashed = encodeBuffer(hashedBuf);
    let padded = new Uint8Array(1 + MAX_PASSWORD_LENGTH);
    padded[0] = value.length;
    let pwBuf = stringToBuffer(value);
    padded.set(new Uint8Array(pwBuf), 1);
    let iv = getRandomBytes(12);
    let ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: domainBuf, tagLength: 128 },
      this.secrets.aesKey,
      padded.buffer,
    );
    this.data.kvs[hashed] = {
      iv: encodeBuffer(iv),
      ct: encodeBuffer(ct),
    };
  }
  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise.
   *
   * Arguments:
   * name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    let domainBuf = stringToBuffer(name);
    let hashedBuf = await subtle.sign(
      "HMAC",
      this.secrets.domainHmacKey,
      domainBuf,
    );
    let hashed = encodeBuffer(hashedBuf);
    if (hashed in this.data.kvs) {
      delete this.data.kvs[hashed];
      return true;
    }
    return false;
  }
}
module.exports = { Keychain };
