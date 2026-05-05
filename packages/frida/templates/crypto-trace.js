// Frida API compatibility (v16 vs v17+)
function findExport(moduleName, funcName) {
    try {
        if (moduleName) {
            var mod = Process.findModuleByName(moduleName);
            if (mod) return mod.findExportByName(funcName);
        }
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            try {
                var addr = mods[i].findExportByName(funcName);
                if (addr) return addr;
            } catch(e) {}
        }
    } catch(e) {}
    return null;
}

/**
 * RAPTOR Frida Template: Cryptographic Operations Tracing
 *
 * Traces crypto operations to identify:
 * - Weak algorithms (MD5, SHA1, DES, RC4)
 * - Hardcoded keys
 * - Predictable IVs
 * - Insecure random number generation
 *
 * Platforms: linux, darwin (macOS/iOS), android, windows
 * Libraries: OpenSSL, BoringSSL, CommonCrypto, CNG, Java crypto
 */

function log(message, level = 'info') {
    send({ level: level, message: message });
}

function sendFinding(title, severity, details) {
    send({
        type: 'finding',
        level: severity,
        title: title,
        details: details,
        timestamp: Date.now()
    });
}

// Platform detection
const platform = Process.platform;
const isIOS = platform === 'darwin' && ObjC.available && ObjC.classes.UIApplication !== undefined;
const isMacOS = platform === 'darwin' && !isIOS;
const isDarwin = platform === 'darwin';
const isAndroid = platform === 'linux' && typeof Java !== 'undefined' && Java.available;
const isLinux = platform === 'linux' && !isAndroid;
const isWindows = platform === 'windows';

log(`Crypto tracer started (platform: ${platform}, iOS: ${isIOS}, macOS: ${isMacOS}, Android: ${isAndroid}, Windows: ${isWindows})`, 'info');

// Helper to hex-dump key material
function hexDump(ptr, len) {
    try {
        const bytes = Memory.readByteArray(ptr, Math.min(len, 32));
        return Array.from(new Uint8Array(bytes))
            .map(function(b) { return b.toString(16).padStart(2, '0'); })
            .join('');
    } catch (e) {
        return '<unreadable>';
    }
}

// ============================================================
// OpenSSL / BoringSSL hooks (all platforms)
// ============================================================
const openssl_funcs = [
    'MD5_Init', 'MD5_Update', 'MD5_Final',
    'SHA1_Init', 'SHA1_Update', 'SHA1_Final',
    'DES_set_key', 'DES_ecb_encrypt',
    'RC4_set_key', 'RC4',
    'AES_set_encrypt_key', 'AES_encrypt',
    'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
    'RAND_bytes'
];

openssl_funcs.forEach(function(func_name) {
    const func_ptr = findExport(null, func_name);
    if (func_ptr) {
        Interceptor.attach(func_ptr, {
            onEnter: function(args) {
                log(`${func_name}() called`, 'info');

                // Warn about weak algorithms
                if (func_name.startsWith('MD5') || func_name.startsWith('SHA1')) {
                    sendFinding(
                        'Weak Hash Algorithm',
                        'warning',
                        `${func_name} uses cryptographically weak algorithm`
                    );
                }

                if (func_name.startsWith('DES') || func_name.startsWith('RC4')) {
                    sendFinding(
                        'Weak Cipher',
                        'error',
                        `${func_name} uses broken/weak encryption`
                    );
                }

                // Log key material
                if (func_name.includes('set_key')) {
                    const key_ptr = args[1] || args[0];
                    const key_hex = hexDump(key_ptr, 16);
                    if (key_hex !== '<unreadable>') {
                        log(`Key material: ${key_hex}...`, 'warning');
                    }
                }
            }
        });
        log(`Hooked ${func_name}`, 'info');
    }
});

// Random number generation (OpenSSL)
const rand_bytes = findExport(null, 'RAND_bytes');
if (rand_bytes) {
    Interceptor.attach(rand_bytes, {
        onEnter: function(args) {
            this.buf = args[0];
            this.num = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 1 && this.num > 0) {
                log(`RAND_bytes generated ${this.num} bytes`, 'info');
            }
        }
    });
}

// BoringSSL-specific functions
const boringssl_funcs = [
    { name: 'CRYPTO_chacha_20', desc: 'ChaCha20 stream cipher' },
    { name: 'EVP_AEAD_CTX_seal', desc: 'AEAD seal (encrypt+auth)' },
    { name: 'EVP_AEAD_CTX_open', desc: 'AEAD open (decrypt+verify)' }
];

boringssl_funcs.forEach(function(entry) {
    const func_ptr = findExport(null, entry.name);
    if (func_ptr) {
        Interceptor.attach(func_ptr, {
            onEnter: function(args) {
                log(`${entry.name}() called — ${entry.desc}`, 'info');
            }
        });
        log(`Hooked ${entry.name} (BoringSSL)`, 'info');
    }
});

// ============================================================
// CommonCrypto (macOS / iOS)
// ============================================================
if (isDarwin) {
    log('Darwin detected - hooking CommonCrypto', 'info');

    // CCCrypt — the main symmetric encryption function
    const CCCrypt = findExport('libSystem.B.dylib', 'CCCrypt');
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                const op = args[0].toInt32(); // 0 = encrypt, 1 = decrypt
                const alg = args[1].toInt32(); // 0=AES128, 1=DES, 2=3DES, 3=CAST, 4=RC4, 5=RC2, 6=Blowfish
                const keyLen = args[4].toInt32();
                const dataLen = args[6].toInt32();

                const algNames = ['AES', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];
                const algName = algNames[alg] || `unknown(${alg})`;
                const opName = op === 0 ? 'encrypt' : 'decrypt';

                log(`CCCrypt: ${opName} ${algName} keyLen=${keyLen} dataLen=${dataLen}`, 'info');

                if (alg === 1 || alg === 4 || alg === 5) { // DES, RC4, RC2
                    sendFinding(
                        'Weak Cipher (CommonCrypto)',
                        'error',
                        `CCCrypt using ${algName} — cryptographically broken`
                    );
                }

                // Dump key
                const keyHex = hexDump(args[3], keyLen);
                if (keyHex !== '<unreadable>') {
                    log(`CCCrypt key (${keyLen}B): ${keyHex}`, 'warning');
                }
            }
        });
        log('Hooked CCCrypt', 'info');
    }

    // CCHmac
    const CCHmac = findExport('libSystem.B.dylib', 'CCHmac');
    if (CCHmac) {
        Interceptor.attach(CCHmac, {
            onEnter: function(args) {
                const alg = args[0].toInt32(); // 1=SHA1, 2=MD5, 3=SHA256, 4=SHA384, 5=SHA512
                const keyLen = args[2].toInt32();
                const dataLen = args[4].toInt32();

                const algNames = { 1: 'SHA1', 2: 'MD5', 3: 'SHA256', 4: 'SHA384', 5: 'SHA512' };
                const algName = algNames[alg] || `unknown(${alg})`;

                log(`CCHmac: ${algName} keyLen=${keyLen} dataLen=${dataLen}`, 'info');

                if (alg === 1 || alg === 2) {
                    sendFinding(
                        'Weak HMAC Algorithm',
                        'warning',
                        `CCHmac using ${algName} — consider SHA256+`
                    );
                }
            }
        });
        log('Hooked CCHmac', 'info');
    }

    // CC_SHA256
    const CC_SHA256 = findExport('libSystem.B.dylib', 'CC_SHA256');
    if (CC_SHA256) {
        Interceptor.attach(CC_SHA256, {
            onEnter: function(args) {
                const len = args[1].toInt32();
                log(`CC_SHA256(${len} bytes)`, 'info');
            }
        });
        log('Hooked CC_SHA256', 'info');
    }

    // CC_MD5
    const CC_MD5 = findExport('libSystem.B.dylib', 'CC_MD5');
    if (CC_MD5) {
        Interceptor.attach(CC_MD5, {
            onEnter: function(args) {
                const len = args[1].toInt32();
                log(`CC_MD5(${len} bytes)`, 'warning');
                sendFinding(
                    'Weak Hash (CommonCrypto)',
                    'warning',
                    `CC_MD5 called with ${len} bytes — MD5 is cryptographically broken`
                );
            }
        });
        log('Hooked CC_MD5', 'info');
    }
}

// ============================================================
// CNG — Windows Cryptography Next Generation (bcrypt.dll)
// ============================================================
if (isWindows) {
    log('Windows detected - hooking CNG (bcrypt.dll)', 'info');

    const bcryptEncrypt = findExport('bcrypt.dll', 'BCryptEncrypt');
    if (bcryptEncrypt) {
        Interceptor.attach(bcryptEncrypt, {
            onEnter: function(args) {
                const inputLen = args[2].toInt32();
                const outputLen = args[6].toInt32();
                log(`BCryptEncrypt(inputLen=${inputLen}, outputLen=${outputLen})`, 'info');
            }
        });
        log('Hooked BCryptEncrypt', 'info');
    }

    const bcryptDecrypt = findExport('bcrypt.dll', 'BCryptDecrypt');
    if (bcryptDecrypt) {
        Interceptor.attach(bcryptDecrypt, {
            onEnter: function(args) {
                const inputLen = args[2].toInt32();
                log(`BCryptDecrypt(inputLen=${inputLen})`, 'info');
            }
        });
        log('Hooked BCryptDecrypt', 'info');
    }

    const bcryptGenSymKey = findExport('bcrypt.dll', 'BCryptGenerateSymmetricKey');
    if (bcryptGenSymKey) {
        Interceptor.attach(bcryptGenSymKey, {
            onEnter: function(args) {
                const secretLen = args[4].toInt32();
                log(`BCryptGenerateSymmetricKey(secretLen=${secretLen})`, 'warning');

                // Dump key secret
                const keyHex = hexDump(args[3], secretLen);
                if (keyHex !== '<unreadable>') {
                    log(`CNG symmetric key material: ${keyHex}`, 'warning');
                }
            }
        });
        log('Hooked BCryptGenerateSymmetricKey', 'info');
    }

    const bcryptHash = findExport('bcrypt.dll', 'BCryptHash');
    if (bcryptHash) {
        Interceptor.attach(bcryptHash, {
            onEnter: function(args) {
                const inputLen = args[3].toInt32();
                log(`BCryptHash(inputLen=${inputLen})`, 'info');
            }
        });
        log('Hooked BCryptHash', 'info');
    }

    // Also hook BCryptOpenAlgorithmProvider to detect algorithm choices
    const bcryptOpenAlg = findExport('bcrypt.dll', 'BCryptOpenAlgorithmProvider');
    if (bcryptOpenAlg) {
        Interceptor.attach(bcryptOpenAlg, {
            onEnter: function(args) {
                try {
                    const algId = Memory.readUtf16String(args[1]);
                    log(`BCryptOpenAlgorithmProvider("${algId}")`, 'info');

                    if (algId === 'MD5' || algId === 'RC4' || algId === 'DES' || algId === 'RC2') {
                        sendFinding(
                            'Weak Algorithm (CNG)',
                            'error',
                            `BCryptOpenAlgorithmProvider using ${algId} — cryptographically weak`
                        );
                    }
                } catch (e) {}
            }
        });
        log('Hooked BCryptOpenAlgorithmProvider', 'info');
    }
}

// ============================================================
// Java crypto (Android / JVM)
// ============================================================
if (isAndroid || (platform === 'linux' && typeof Java !== 'undefined' && Java.available)) {
    Java.perform(function() {
        log('Java crypto hooks installing', 'info');

        // javax.crypto.Cipher
        try {
            const Cipher = Java.use('javax.crypto.Cipher');

            // Cipher.getInstance — detect algorithm selection
            Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
                log(`Cipher.getInstance("${transformation}")`, 'info');

                const tLower = transformation.toLowerCase();
                if (tLower.includes('des') || tLower.includes('rc4') || tLower.includes('rc2')) {
                    sendFinding(
                        'Weak Cipher (Java)',
                        'error',
                        `Cipher.getInstance using ${transformation} — cryptographically weak`
                    );
                }
                if (tLower.includes('ecb')) {
                    sendFinding(
                        'Insecure Mode (Java)',
                        'warning',
                        `Cipher using ECB mode: ${transformation} — no semantic security`
                    );
                }

                return this.getInstance(transformation);
            };

            // Cipher.init
            Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
                const mode = opmode === 1 ? 'ENCRYPT' : opmode === 2 ? 'DECRYPT' : `mode=${opmode}`;
                const algo = key.getAlgorithm();
                log(`Cipher.init(${mode}, key=${algo})`, 'info');

                // Log key bytes
                try {
                    const encoded = key.getEncoded();
                    if (encoded) {
                        const len = encoded.length;
                        log(`Cipher key length: ${len} bytes`, 'warning');
                    }
                } catch (e) {}

                return this.init(opmode, key);
            };

            // Cipher.doFinal
            Cipher.doFinal.overload('[B').implementation = function(input) {
                log(`Cipher.doFinal(${input.length} bytes)`, 'info');
                return this.doFinal(input);
            };
        } catch (e) {
            log('Cipher hook failed: ' + e, 'info');
        }

        // java.security.MessageDigest
        try {
            const MessageDigest = Java.use('java.security.MessageDigest');

            MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
                log(`MessageDigest.getInstance("${algorithm}")`, 'info');

                if (algorithm === 'MD5' || algorithm === 'SHA-1' || algorithm === 'SHA1') {
                    sendFinding(
                        'Weak Hash (Java)',
                        'warning',
                        `MessageDigest using ${algorithm} — cryptographically weak`
                    );
                }

                return this.getInstance(algorithm);
            };

            MessageDigest.update.overload('[B').implementation = function(input) {
                log(`MessageDigest.update(${input.length} bytes)`, 'info');
                return this.update(input);
            };

            MessageDigest.digest.overload().implementation = function() {
                const result = this.digest();
                log(`MessageDigest.digest() => ${result.length} bytes`, 'info');
                return result;
            };

            MessageDigest.digest.overload('[B').implementation = function(input) {
                log(`MessageDigest.digest(${input.length} bytes)`, 'info');
                return this.digest(input);
            };
        } catch (e) {
            log('MessageDigest hook failed: ' + e, 'info');
        }

        // javax.crypto.Mac (HMAC)
        try {
            const Mac = Java.use('javax.crypto.Mac');

            Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
                log(`Mac.getInstance("${algorithm}")`, 'info');
                if (algorithm.toLowerCase().includes('md5')) {
                    sendFinding(
                        'Weak HMAC (Java)',
                        'warning',
                        `Mac using ${algorithm} — MD5-based HMAC is weak`
                    );
                }
                return this.getInstance(algorithm);
            };

            Mac.doFinal.overload('[B').implementation = function(input) {
                log(`Mac.doFinal(${input.length} bytes)`, 'info');
                return this.doFinal(input);
            };
        } catch (e) {
            log('Mac hook failed: ' + e, 'info');
        }
    });
}

log('Crypto tracing hooks installed', 'info');
