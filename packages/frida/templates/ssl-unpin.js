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
 * RAPTOR Frida Template: SSL Certificate Pinning Bypass
 *
 * Bypasses SSL certificate pinning on multiple platforms:
 * - iOS (NSURLSession delegate, CFNetwork, Security framework)
 * - Android (OkHttp, TrustManagerImpl, HttpsURLConnection, WebView)
 * - macOS (NSURLSession delegate, Security framework)
 * - Windows (WinHTTP, Schannel)
 * - Generic (OpenSSL, BoringSSL, GnuTLS)
 */

function log(message, level = 'info') {
    send({
        level: level,
        message: message
    });
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
const isAndroid = platform === 'linux' && typeof Java !== 'undefined' && Java.available;
const isWindows = platform === 'windows';

log(`SSL Unpinning started (platform: ${platform}, iOS: ${isIOS}, macOS: ${isMacOS}, Android: ${isAndroid}, Windows: ${isWindows})`, 'info');

// ============================================================
// iOS SSL Pinning Bypass
// ============================================================
if (isIOS && ObjC.available) {
    log('iOS detected - hooking SSL verification', 'info');

    // NSURLSession delegate bypass — find all classes implementing
    // URLSession:didReceiveChallenge:completionHandler: and override
    const challengeSel = 'URLSession:didReceiveChallenge:completionHandler:';
    const classes = ObjC.enumerateLoadedClassesSync();
    for (const moduleName in classes) {
        const classNames = classes[moduleName];
        classNames.forEach(function(className) {
            try {
                const klass = ObjC.classes[className];
                if (klass && klass['- ' + challengeSel]) {
                    const method = klass['- ' + challengeSel];
                    Interceptor.attach(method.implementation, {
                        onEnter: function(args) {
                            // args[4] = completionHandler block
                            // Call completionHandler with UseCredential disposition (0) and server trust credential
                            const challenge = ObjC.Object(args[3]);
                            const protectionSpace = challenge.protectionSpace();
                            const serverTrust = protectionSpace.serverTrust();
                            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);

                            const completionHandler = new ObjC.Block(args[4]);
                            completionHandler.implementation = function() {
                                // NSURLSessionAuthChallengeUseCredential = 0
                                completionHandler.invoke(0, credential);
                            };

                            log(`SSL bypass: ${className} ${challengeSel}`, 'warning');
                            sendFinding(
                                'SSL Pinning Bypassed (iOS)',
                                'warning',
                                `Delegate ${className} challenge handler overridden`
                            );
                        }
                    });
                    log(`Hooked ${className} ${challengeSel}`, 'info');
                }
            } catch (e) {
                // Class doesn't implement the selector or not accessible
            }
        });
    }

    // Disable SecTrustEvaluate / SecTrustEvaluateWithError
    const secTrustEval = findExport('Security', 'SecTrustEvaluateWithError');
    if (secTrustEval) {
        Interceptor.replace(secTrustEval, new NativeCallback(function(trust, error) {
            log('SecTrustEvaluateWithError bypassed', 'info');
            return 1; // true = trusted
        }, 'bool', ['pointer', 'pointer']));
    }

    // Legacy SSLSetSessionOption bypass
    const SSLSetSessionOption = findExport('Security', 'SSLSetSessionOption');
    if (SSLSetSessionOption) {
        Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
            return 0; // Success
        }, 'int', ['pointer', 'int', 'int']));
        log('SSLSetSessionOption bypassed', 'info');
    }
}

// ============================================================
// macOS SSL Pinning Bypass (NSURLSession delegate, same pattern as iOS)
// ============================================================
if (isMacOS && ObjC.available) {
    log('macOS detected - hooking SSL verification', 'info');

    const challengeSel = 'URLSession:didReceiveChallenge:completionHandler:';
    const classes = ObjC.enumerateLoadedClassesSync();
    for (const moduleName in classes) {
        const classNames = classes[moduleName];
        classNames.forEach(function(className) {
            try {
                const klass = ObjC.classes[className];
                if (klass && klass['- ' + challengeSel]) {
                    const method = klass['- ' + challengeSel];
                    Interceptor.attach(method.implementation, {
                        onEnter: function(args) {
                            const challenge = ObjC.Object(args[3]);
                            const protectionSpace = challenge.protectionSpace();
                            const serverTrust = protectionSpace.serverTrust();
                            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);

                            const completionHandler = new ObjC.Block(args[4]);
                            completionHandler.implementation = function() {
                                completionHandler.invoke(0, credential);
                            };

                            log(`SSL bypass (macOS): ${className} ${challengeSel}`, 'warning');
                            sendFinding(
                                'SSL Pinning Bypassed (macOS)',
                                'warning',
                                `Delegate ${className} challenge handler overridden`
                            );
                        }
                    });
                    log(`Hooked (macOS) ${className} ${challengeSel}`, 'info');
                }
            } catch (e) {}
        });
    }

    // SecTrustEvaluateWithError on macOS
    const secTrustEval = findExport('Security', 'SecTrustEvaluateWithError');
    if (secTrustEval) {
        Interceptor.replace(secTrustEval, new NativeCallback(function(trust, error) {
            log('SecTrustEvaluateWithError bypassed (macOS)', 'info');
            return 1;
        }, 'bool', ['pointer', 'pointer']));
    }
}

// ============================================================
// Android SSL Pinning Bypass
// ============================================================
if (isAndroid && Java.available) {
    Java.perform(function() {
        log('Android detected - hooking SSL verification', 'info');

        // TrustManagerImpl.checkServerTrusted (platform-level)
        try {
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
                log('TrustManagerImpl.checkServerTrusted() bypassed', 'warning');
                sendFinding(
                    'SSL Pinning Bypassed',
                    'warning',
                    'TrustManagerImpl certificate validation bypassed'
                );
                return;
            };

            // Also override the extended version if present
            try {
                TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String').implementation = function(chain, authType, host) {
                    log('TrustManagerImpl.checkServerTrusted(host) bypassed', 'warning');
                    return Java.use('java.util.ArrayList').$new();
                };
            } catch (e) {}
        } catch (e) {
            log('TrustManagerImpl not found: ' + e, 'info');
        }

        // OkHttp3 CertificatePinner
        try {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                log('OkHttp3 CertificatePinner.check() bypassed', 'warning');
                sendFinding(
                    'SSL Pinning Bypassed',
                    'warning',
                    'OkHttp3 certificate pinning bypassed'
                );
            };

            // Also override check(String, Function0) if present (OkHttp 4.x)
            try {
                CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function() {
                    log('OkHttp4 CertificatePinner.check$okhttp() bypassed', 'warning');
                };
            } catch (e) {}
        } catch (e) {
            log('OkHttp3 not found: ' + e, 'info');
        }

        // HttpsURLConnection — override SSLSocketFactory
        try {
            const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

            const TrustAllManager = Java.registerClass({
                name: 'com.raptor.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            const trustManagers = [TrustAllManager.$new()];

            HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(factory) {
                const ctx = SSLContext.getInstance('TLS');
                ctx.init(null, trustManagers, null);
                this.setDefaultSSLSocketFactory(ctx.getSocketFactory());
                log('HttpsURLConnection.setDefaultSSLSocketFactory() bypassed', 'warning');
            };

            // Also hook setSSLSocketFactory on instances
            HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
                const ctx = SSLContext.getInstance('TLS');
                ctx.init(null, trustManagers, null);
                this.setSSLSocketFactory(ctx.getSocketFactory());
                log('HttpsURLConnection.setSSLSocketFactory() bypassed', 'warning');
            };
        } catch (e) {
            log('HttpsURLConnection hook failed: ' + e, 'info');
        }

        // SSLContext.init — universal TrustManager override
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');

            const TrustManager = Java.registerClass({
                name: 'com.raptor.SSLTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            const TrustManagers = [TrustManager.$new()];
            const SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                log('SSLContext.init() bypassed with custom TrustManager', 'warning');
            };
        } catch (e) {
            log('SSLContext TrustManager bypass failed: ' + e, 'info');
        }

        // WebView SSL Error bypass
        try {
            const WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                log('WebView SSL error bypassed', 'warning');
                handler.proceed();
                sendFinding(
                    'SSL Error Ignored',
                    'warning',
                    'WebView SSL error handler bypassed'
                );
            };
        } catch (e) {
            log('WebViewClient not found: ' + e, 'info');
        }
    });
}

// ============================================================
// Windows — WinHTTP, Schannel
// ============================================================
if (isWindows) {
    log('Windows detected - hooking SSL verification', 'info');

    // WinHTTP — WinHttpSetOption with SECURITY_FLAGS
    const winHttpSetOption = findExport('winhttp.dll', 'WinHttpSetOption');
    if (winHttpSetOption) {
        Interceptor.attach(winHttpSetOption, {
            onEnter: function(args) {
                const option = args[1].toInt32();
                // WINHTTP_OPTION_SECURITY_FLAGS = 31
                if (option === 31) {
                    // Set all ignore flags: ignore unknown CA, wrong usage, wrong CN, date invalid
                    // 0x00003300 = SECURITY_FLAG_IGNORE_ALL
                    const flags = 0x00000100 | 0x00000200 | 0x00001000 | 0x00002000;
                    Memory.writeU32(args[2], flags);
                    log('WinHttpSetOption SECURITY_FLAGS overridden to ignore cert errors', 'warning');
                    sendFinding(
                        'SSL Pinning Bypassed (WinHTTP)',
                        'warning',
                        'WinHttpSetOption SECURITY_FLAGS set to ignore all cert errors'
                    );
                }
            }
        });
    }

    // Schannel — hook the SSPI InitializeSecurityContextW to allow cert bypass
    // and CertVerifyCertificateChainPolicy
    const certVerifyPolicy = findExport('crypt32.dll', 'CertVerifyCertificateChainPolicy');
    if (certVerifyPolicy) {
        Interceptor.attach(certVerifyPolicy, {
            onLeave: function(retval) {
                // Force success: pPolicyStatus->dwError = 0
                // The 3rd arg (pPolicyStatus) is at args[2] from onEnter
                // We override retval to TRUE and zero the error
                retval.replace(1); // TRUE = success
                log('CertVerifyCertificateChainPolicy bypassed', 'warning');
                sendFinding(
                    'SSL Pinning Bypassed (Schannel)',
                    'warning',
                    'CertVerifyCertificateChainPolicy forced to succeed'
                );
            }
        });
    }

    // WinInet — InternetSetOptionW for cert ignoring
    const internetSetOptionW = findExport('wininet.dll', 'InternetSetOptionW');
    if (internetSetOptionW) {
        Interceptor.attach(internetSetOptionW, {
            onEnter: function(args) {
                const option = args[1].toInt32();
                // INTERNET_OPTION_SECURITY_FLAGS = 31
                if (option === 31) {
                    const flags = 0x00003300;
                    Memory.writeU32(args[2], flags);
                    log('InternetSetOptionW SECURITY_FLAGS overridden', 'warning');
                }
            }
        });
    }
}

// ============================================================
// Generic SSL/TLS library bypasses (all platforms)
// ============================================================

// OpenSSL — SSL_CTX_set_verify callback override
const SSL_CTX_set_verify = findExport(null, 'SSL_CTX_set_verify');
if (SSL_CTX_set_verify) {
    Interceptor.replace(SSL_CTX_set_verify, new NativeCallback(function(ssl_ctx, mode, callback) {
        // Set mode to SSL_VERIFY_NONE (0) — disables all verification
        log('OpenSSL SSL_CTX_set_verify() overridden to VERIFY_NONE', 'warning');
        sendFinding(
            'SSL Verification Disabled (OpenSSL)',
            'warning',
            'OpenSSL certificate verification callback overridden with VERIFY_NONE'
        );
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}

const SSL_get_verify_result = findExport(null, 'SSL_get_verify_result');
if (SSL_get_verify_result) {
    Interceptor.replace(SSL_get_verify_result, new NativeCallback(function(ssl) {
        log('OpenSSL SSL_get_verify_result() bypassed', 'info');
        return 0; // X509_V_OK
    }, 'int', ['pointer']));
}

// Also hook SSL_set_verify for per-connection overrides
const SSL_set_verify = findExport(null, 'SSL_set_verify');
if (SSL_set_verify) {
    Interceptor.replace(SSL_set_verify, new NativeCallback(function(ssl, mode, callback) {
        log('OpenSSL SSL_set_verify() overridden to VERIFY_NONE', 'warning');
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}

// BoringSSL (used by Chrome/Android)
const SSL_set_custom_verify = findExport(null, 'SSL_set_custom_verify');
if (SSL_set_custom_verify) {
    Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
        log('BoringSSL SSL_set_custom_verify() bypassed', 'warning');
        return;
    }, 'void', ['pointer', 'int', 'pointer']));
}

// GnuTLS
const gnutls_certificate_verify_peers2 = findExport(null, 'gnutls_certificate_verify_peers2');
if (gnutls_certificate_verify_peers2) {
    Interceptor.replace(gnutls_certificate_verify_peers2, new NativeCallback(function(session, status) {
        log('GnuTLS certificate verification bypassed', 'warning');
        Memory.writeU32(status, 0); // No errors
        return 0; // Success
    }, 'int', ['pointer', 'pointer']));
}

log('SSL Unpinning hooks installed', 'info');
sendFinding(
    'SSL Unpinning Active',
    'info',
    'All SSL/TLS certificate validation hooks have been installed'
);
