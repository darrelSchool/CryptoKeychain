module.exports = [
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/crypto [external] (crypto, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("crypto", () => require("crypto"));

module.exports = mod;
}),
"[project]/lib.js [app-ssr] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

const { getRandomValues } = __turbopack_context__.r("[externals]/crypto [external] (crypto, cjs)");
/**
 * Converts a plaintext string into a buffer for use in SubtleCrypto functions.
 * @param {string} str - A plaintext string
 * @returns {Buffer} A buffer representation for use in SubtleCrypto functions
 */ function stringToBuffer(str) {
    return Buffer.from(str);
}
/**
 * Converts a buffer object representing string data back into a string
 * @param {BufferSource} buf - A buffer containing string data
 * @returns {string} The original string
 */ function bufferToString(buf) {
    return Buffer.from(buf).toString();
}
/**
 * Converts a buffer to a Base64 string which can be used as a key in a map and
 * can be easily serialized.
 * @param {BufferSource} buf - A buffer-like object
 * @returns {string} A Base64 string representing the bytes in the buffer
 */ function encodeBuffer(buf) {
    return Buffer.from(buf).toString("base64");
}
/**
 * Converts a Base64 string back into a buffer
 * @param {string} base64 - A Base64 string representing a buffer
 * @returns {Buffer} A Buffer object
 */ function decodeBuffer(base64) {
    return Buffer.from(base64, "base64");
}
/**
 * Generates a buffer of random bytes
 * @param {number} len - The number of random bytes
 * @returns {Uint8Array} A buffer of `len` random bytes
 */ function getRandomBytes(len) {
    return self.crypto.getRandomValues(new Uint8Array(len));
}
module.exports = {
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
};
}),
"[project]/password-manager.js [app-ssr] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

/********* External Imports ********/ const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = __turbopack_context__.r("[project]/lib.js [app-ssr] (ecmascript)");
const { subtle } = window.crypto;
/********* Constants ********/ const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters
/********* Implementation ********/ class Keychain {
    /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   * You may design the constructor with any parameters you would like.
   * Return Type: void
   */ constructor(){
        this.data = {
            kvs: {},
            salt: null,
            verifyTag: null
        };
        this.secrets = {
            aesKey: null,
            domainHmacKey: null
        };
    }
    /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   * password: string
   * Return Type: void
   */ static async init(password) {
        let kc = new Keychain();
        let salt = getRandomBytes(16);
        kc.data.salt = encodeBuffer(salt);
        let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, [
            "deriveKey"
        ]);
        let masterHmacKey = await subtle.deriveKey({
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        }, rawKey, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign",
            "verify"
        ]);
        let aesKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("aes-key"));
        kc.secrets.aesKey = await subtle.importKey("raw", aesKeyMaterial, "AES-GCM", false, [
            "encrypt",
            "decrypt"
        ]);
        let domainHmacKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("domain-key"));
        kc.secrets.domainHmacKey = await subtle.importKey("raw", domainHmacKeyMaterial, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign"
        ]);
        let verifyKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("verify-key"));
        let verifyKey = await subtle.importKey("raw", verifyKeyMaterial, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign"
        ]);
        let verifyTag = await subtle.sign("HMAC", verifyKey, stringToBuffer("verify"));
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
   */ static async load(password, repr, trustedDataCheck) {
        let hashBuf = await subtle.digest("SHA-256", stringToBuffer(repr));
        let computedCheck = encodeBuffer(hashBuf);
        if (trustedDataCheck !== undefined && trustedDataCheck !== computedCheck) {
            throw "Integrity check failed";
        }
        let data = JSON.parse(repr);
        let kc = new Keychain();
        kc.data = data;
        let salt = decodeBuffer(data.salt);
        let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, [
            "deriveKey"
        ]);
        let masterHmacKey = await subtle.deriveKey({
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        }, rawKey, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign",
            "verify"
        ]);
        let aesKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("aes-key"));
        kc.secrets.aesKey = await subtle.importKey("raw", aesKeyMaterial, "AES-GCM", false, [
            "encrypt",
            "decrypt"
        ]);
        let domainHmacKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("domain-key"));
        kc.secrets.domainHmacKey = await subtle.importKey("raw", domainHmacKeyMaterial, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign"
        ]);
        let verifyKeyMaterial = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("verify-key"));
        let verifyKey = await subtle.importKey("raw", verifyKeyMaterial, {
            name: "HMAC",
            hash: "SHA-256",
            length: 256
        }, false, [
            "sign"
        ]);
        let verifyTag = await subtle.sign("HMAC", verifyKey, stringToBuffer("verify"));
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
   */ async dump() {
        let ser = JSON.stringify(this.data);
        let hashBuf = await subtle.digest("SHA-256", stringToBuffer(ser));
        let checksum = encodeBuffer(hashBuf);
        return [
            ser,
            checksum
        ];
    }
    /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null.
   *
   * Arguments:
   * name: string
   * Return Type: Promise<string>
   */ async get(name) {
        let domainBuf = stringToBuffer(name);
        let hashedBuf = await subtle.sign("HMAC", this.secrets.domainHmacKey, domainBuf);
        let hashed = encodeBuffer(hashedBuf);
        if (!(hashed in this.data.kvs)) {
            return null;
        }
        let entry = this.data.kvs[hashed];
        let iv = decodeBuffer(entry.iv);
        let ct = decodeBuffer(entry.ct);
        try {
            let decrypted = await subtle.decrypt({
                name: "AES-GCM",
                iv: iv,
                additionalData: domainBuf,
                tagLength: 128
            }, this.secrets.aesKey, ct);
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
   */ async set(name, value) {
        if (value.length > MAX_PASSWORD_LENGTH) {
            throw "Password too long";
        }
        let domainBuf = stringToBuffer(name);
        let hashedBuf = await subtle.sign("HMAC", this.secrets.domainHmacKey, domainBuf);
        let hashed = encodeBuffer(hashedBuf);
        let padded = new Uint8Array(1 + MAX_PASSWORD_LENGTH);
        padded[0] = value.length;
        let pwBuf = stringToBuffer(value);
        padded.set(new Uint8Array(pwBuf), 1);
        let iv = getRandomBytes(12);
        let ct = await subtle.encrypt({
            name: "AES-GCM",
            iv: iv,
            additionalData: domainBuf,
            tagLength: 128
        }, this.secrets.aesKey, padded.buffer);
        this.data.kvs[hashed] = {
            iv: encodeBuffer(iv),
            ct: encodeBuffer(ct)
        };
    }
    /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise.
   *
   * Arguments:
   * name: string
   * Return Type: Promise<boolean>
   */ async remove(name) {
        let domainBuf = stringToBuffer(name);
        let hashedBuf = await subtle.sign("HMAC", this.secrets.domainHmacKey, domainBuf);
        let hashed = encodeBuffer(hashedBuf);
        if (hashed in this.data.kvs) {
            delete this.data.kvs[hashed];
            return true;
        }
        return false;
    }
}
module.exports = {
    Keychain
};
}),
"[project]/app/page.jsx [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>Page
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
(()=>{
    const e = new Error("Cannot find module 'ui/Field'");
    e.code = 'MODULE_NOT_FOUND';
    throw e;
})();
"use client";
;
;
;
const { Keychain } = __turbopack_context__.r("[project]/password-manager.js [app-ssr] (ecmascript)");
const test = [
    '{"kvs":{"tVFlxWFM1eTTGEpYsVCBlRuJ3higOf7mhuu9BzOxHgA=":{"iv":"fdH26skhEWLslxRt","ct":"R1HHHQKR+lugNVvM36UVOomUP+m2gQNQ3n5KWjE3bVnxZ82QjcGrTWhhAN73U7LTXZxQ96/UJ5XFIaDCRtMvC30TCVxRHscLvDbM8Yk4sQZ5"},"cveydU05Tg/CqPqB4jB9eRuqRW2zedubLv2Wo0+T9aw=":{"iv":"ZwZNo/vh7tCLloU8","ct":"QhRBxA/Y6uxJJsKPCnPl9mu/WxaxNC0QuzDAHrcftk7TasqnvBBWYXjRbrq8nPxSxJ+jq/F6CMwoJ2mBHJ9N83pGJ6wSugZj/6Xeifny5A1J"},"CirRlMqSTV6z11WPKyGBVqgN4JuuTp1OqgMadkwJbM8=":{"iv":"Y3pGjgiDGcAImWrz","ct":"lUnEEP/QECE6RvtfKpBsfcFTZRnBrN0ScBER2PkUC3mXX10GQ2GhxnuiGcymU3M2YyyW1zOy2Ia/ldSfgqA3mnkaX/asTdbXu4uEtoDiIMd+"}},"salt":"lTa5dQBqzQrsJVkXvKA1RA==","verifyTag":"bD1cUUcGwJ699e8g7hrcOqpSFyEYMcp4PZDA8fez50A="}',
    "lIYG+tjo0uXHo5Gp4mtQCxME8imkTDELLuOPOo4ku9M="
];
function Page() {
    var baseKvs = {};
    const [search, setSearch] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])("");
    const [ready, setReady] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [updated, setUpdated] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [kvs, setKvs] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])();
    const [result, setResult] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [addDomain, setAddDomain] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [addPassword, setAddPassword] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])([]);
    const [searchFailed, setSearchFailed] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(false);
    const [masterPass, setMasterPass] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])("");
    const [masterValid, setMasterValid] = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useState"])(true);
    function handleChange(event) {
        setSearch(event.target.value);
    }
    function handleMasterPass(event) {
        setMasterPass(event.target.value);
    }
    function handleAddDomain(event) {
        setAddDomain(event.target.value);
    }
    function handleAddPassword(event) {
        setAddPassword(event.target.value);
    }
    function sleep(ms) {
        return new Promise((resolve)=>setTimeout(resolve, ms));
    }
    function deleteEntry(domain) {
        baseKvs = kvs;
        baseKvs.remove(domain);
        setKvs(baseKvs);
    }
    function addSubmit(event) {
        event.preventDefault();
        baseKvs = kvs;
        console.log(Object.keys(baseKvs.data.kvs).length);
        baseKvs.set(addDomain, addPassword).then(()=>{
            setKvs(baseKvs);
            console.log(Object.keys(baseKvs.data.kvs).length);
            setUpdated(true);
            setAddPassword("");
            setAddDomain("");
            sleep(2000).then(()=>{
                setUpdated(false);
            });
        });
    }
    function searchSubmit(event) {
        event.preventDefault();
        kvs.get(search).then((data)=>{
            if (data == null) {
                setSearchFailed(true);
                setResult([]);
            } else {
                setResult([
                    search,
                    data
                ]);
                setSearchFailed(false);
            }
        });
        console.log(result);
    }
    function auth(event) {
        event.preventDefault();
        try {
            baseKvs = Keychain.load(masterPass, test[0], test[1]).then((data)=>{
                setKvs(data);
                setReady(true);
            });
        } catch  {
            setReady(false);
            setMasterValid(false);
        }
    }
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        const decryptAsync = async ()=>{};
        decryptAsync();
    }, []);
    return ready ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("main", {
        className: "flex flex-row justify-center w-screen pt-16 space-y-8",
        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "w-1/2 space-y-4",
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                    className: "text-3xl font-semibold text-[#4F39F6]",
                    children: "Secure Vault"
                }, void 0, false, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 95,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("form", {
                    action: "",
                    className: "space-y-4",
                    onSubmit: addSubmit,
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                            className: "text-2xl font-medium",
                            children: "Add or update domain"
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 97,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex flex-row space-x-3",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex flex-col space-y-2 w-full",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                            htmlFor: "domain",
                                            children: "Domain:"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 100,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                            type: "text",
                                            value: addDomain,
                                            onChange: handleAddDomain,
                                            placeholder: "Enter new or existing domain",
                                            required: true,
                                            className: "rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 101,
                                            columnNumber: 15
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 99,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex flex-col space-y-2 w-full",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                            htmlFor: "password",
                                            children: "Password:"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 111,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                            type: "password",
                                            value: addPassword,
                                            onChange: handleAddPassword,
                                            placeholder: "Enter password",
                                            required: true,
                                            className: "rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 112,
                                            columnNumber: 15
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 110,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 98,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                            className: "text-white bg-[#4F39F6] px-3 py-3 w-full rounded-md",
                            children: "Add or update domain details"
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 122,
                            columnNumber: 11
                        }, this),
                        updated ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "text-green-400",
                            children: "The domain and password was added successfully"
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 126,
                            columnNumber: 13
                        }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {}, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 130,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 96,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("form", {
                    action: "",
                    onSubmit: searchSubmit,
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                            className: "text-2xl font-medium",
                            children: "Retrieve password"
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 134,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex flex-col space-y-2",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                    htmlFor: "domain",
                                    children: "Enter the domain:"
                                }, void 0, false, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 136,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                                    className: "flex flex-row space-x-3 items-center",
                                    children: [
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                            type: "text",
                                            placeholder: "www.example.com",
                                            required: true,
                                            value: search,
                                            onChange: handleChange,
                                            className: "rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 138,
                                            columnNumber: 15
                                        }, this),
                                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                                            className: "w-fit text-nowrap px-2 py-3 text-white bg-[#4F39F6] rounded-md",
                                            children: "Get password"
                                        }, void 0, false, {
                                            fileName: "[project]/app/page.jsx",
                                            lineNumber: 146,
                                            columnNumber: 15
                                        }, this)
                                    ]
                                }, void 0, true, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 137,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 135,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 133,
                    columnNumber: 9
                }, this),
                searchFailed ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                    className: "text-red-500",
                    children: "No such domain exists in the key value store"
                }, void 0, false, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 153,
                    columnNumber: 11
                }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {}, void 0, false, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 157,
                    columnNumber: 11
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "font-semibold flex flex-row text-xl",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                    className: "w-1/2",
                                    children: "Domain"
                                }, void 0, false, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 161,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                                    className: "w-1/2",
                                    children: "Password"
                                }, void 0, false, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 162,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 160,
                            columnNumber: 11
                        }, this),
                        result.length > 1 ? /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])(Field, {
                            domain: result[0],
                            password: result[1],
                            deleteEntry: deleteEntry
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 165,
                            columnNumber: 13
                        }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("br", {}, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 171,
                            columnNumber: 13
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 159,
                    columnNumber: 9
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/app/page.jsx",
            lineNumber: 94,
            columnNumber: 7
        }, this)
    }, void 0, false, {
        fileName: "[project]/app/page.jsx",
        lineNumber: 93,
        columnNumber: 5
    }, this) : /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("main", {
        className: "flex flex-row items-center justify-center w-screen h-screen ",
        children: /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
            className: "shadow-[#4F39F6] border border-[#4F39F6] rounded-xl shadow-lg py-16 px-12 w-3/12",
            children: [
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("h1", {
                    className: "font-bold text-[#4F39F6] text-2xl text-center pb-16 pt-1",
                    children: "Secure Vault"
                }, void 0, false, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 179,
                    columnNumber: 9
                }, this),
                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("form", {
                    className: "flex flex-col space-y-8",
                    onSubmit: auth,
                    children: [
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("div", {
                            className: "flex flex-col space-y-2",
                            children: [
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("label", {
                                    children: "Master password :"
                                }, void 0, false, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 184,
                                    columnNumber: 13
                                }, this),
                                /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("input", {
                                    type: "password",
                                    className: "border outline-[#4F39F6] focus:border-[#4F39F6] px-2 py-3 rounded-md",
                                    placeholder: "Enter master password",
                                    value: masterPass,
                                    onChange: handleMasterPass
                                }, void 0, false, {
                                    fileName: "[project]/app/page.jsx",
                                    lineNumber: 185,
                                    columnNumber: 13
                                }, this)
                            ]
                        }, void 0, true, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 183,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("p", {
                            className: "text-red-500",
                            children: "Wrong password. Retry."
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 193,
                            columnNumber: 11
                        }, this),
                        /*#__PURE__*/ (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2d$jsx$2d$dev$2d$runtime$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["jsxDEV"])("button", {
                            className: "bg-[#4F39F6] text-white w-full rounded-md py-3",
                            type: "submit",
                            children: "Unlock Vault"
                        }, void 0, false, {
                            fileName: "[project]/app/page.jsx",
                            lineNumber: 194,
                            columnNumber: 11
                        }, this)
                    ]
                }, void 0, true, {
                    fileName: "[project]/app/page.jsx",
                    lineNumber: 182,
                    columnNumber: 9
                }, this)
            ]
        }, void 0, true, {
            fileName: "[project]/app/page.jsx",
            lineNumber: 178,
            columnNumber: 7
        }, this)
    }, void 0, false, {
        fileName: "[project]/app/page.jsx",
        lineNumber: 177,
        columnNumber: 5
    }, this);
}
}),
"[project]/node_modules/next/dist/server/route-modules/app-page/module.compiled.js [app-ssr] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

if ("TURBOPACK compile-time falsy", 0) //TURBOPACK unreachable
;
else {
    if ("TURBOPACK compile-time falsy", 0) //TURBOPACK unreachable
    ;
    else {
        if ("TURBOPACK compile-time truthy", 1) {
            if ("TURBOPACK compile-time truthy", 1) {
                module.exports = __turbopack_context__.r("[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)");
            } else //TURBOPACK unreachable
            ;
        } else //TURBOPACK unreachable
        ;
    }
} //# sourceMappingURL=module.compiled.js.map
}),
"[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react-jsx-dev-runtime.js [app-ssr] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

module.exports = __turbopack_context__.r("[project]/node_modules/next/dist/server/route-modules/app-page/module.compiled.js [app-ssr] (ecmascript)").vendored['react-ssr'].ReactJsxDevRuntime; //# sourceMappingURL=react-jsx-dev-runtime.js.map
}),
"[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)", ((__turbopack_context__, module, exports) => {
"use strict";

module.exports = __turbopack_context__.r("[project]/node_modules/next/dist/server/route-modules/app-page/module.compiled.js [app-ssr] (ecmascript)").vendored['react-ssr'].React; //# sourceMappingURL=react.js.map
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__3cbaaae6._.js.map