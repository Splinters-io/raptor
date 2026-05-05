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
 * RAPTOR Frida Template: API Tracing
 *
 * Traces common API calls for security analysis:
 * - File operations
 * - Network operations
 * - Process/system calls
 * - Crypto operations
 *
 * Platforms: linux, darwin (macOS), ios, android, windows
 */

// Helper to send findings back to Python
function sendFinding(title, severity, details) {
    send({
        type: 'finding',
        level: severity,
        title: title,
        details: details,
        timestamp: Date.now()
    });
}

// Helper to log messages
function log(message, level = 'info') {
    send({
        level: level,
        message: message
    });
}

// Platform detection
const platform = Process.platform;
const isIOS = platform === 'darwin' && typeof ObjC !== 'undefined' && ObjC.available && ObjC.classes.UIApplication !== undefined;
const isMacOS = platform === 'darwin' && !isIOS;
const isAndroid = platform === 'linux' && typeof Java !== 'undefined' && Java.available;
const isLinux = platform === 'linux' && !isAndroid;
const isWindows = platform === 'windows';

log(`API Tracing started (platform: ${platform}, iOS: ${isIOS}, macOS: ${isMacOS}, Android: ${isAndroid}, Linux: ${isLinux}, Windows: ${isWindows})`, 'info');

// ============================================================
// POSIX (Linux + macOS + iOS) — file, network, process, memory
// ============================================================
if (platform === 'darwin' || platform === 'linux') {
    // File operations — fopen
    const fopen = findExport(null, 'fopen');
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                if (args[0].isNull()) return;
                var path, mode;
                try { path = Memory.readUtf8String(args[0]); } catch(e) { return; }
                try { mode = Memory.readUtf8String(args[1]); } catch(e) { mode = '?'; }
                log(`fopen("${path}", "${mode}")`, 'info');

                if (path && (path.includes('passwd') || path.includes('shadow'))) {
                    sendFinding(
                        'Sensitive File Access',
                        'warning',
                        `Attempt to open sensitive file: ${path}`
                    );
                }
            }
        });
    }

    // Network — connect
    const connect = findExport(null, 'connect');
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                log('connect() called', 'info');
            }
        });
    }

    // Process execution — system()
    const system = findExport(null, 'system');
    if (system) {
        Interceptor.attach(system, {
            onEnter: function(args) {
                const cmd = Memory.readUtf8String(args[0]);
                log(`system("${cmd}")`, 'warning');
                sendFinding(
                    'Command Execution',
                    'warning',
                    `system() called with: ${cmd}`
                );
            }
        });
    }

    // Memory allocation (large allocation detection)
    const malloc = findExport(null, 'malloc');
    if (malloc) {
        Interceptor.attach(malloc, {
            onEnter: function(args) {
                const size = args[0].toInt32();
                if (size > 10 * 1024 * 1024) {  // > 10MB
                    log(`Large malloc: ${size} bytes`, 'warning');
                }
            }
        });
    }
}

// ============================================================
// Windows — ntdll, ws2_32, kernel32, advapi32
// ============================================================
if (isWindows) {
    // --- ntdll native file I/O ---
    const ntCreateFile = findExport('ntdll.dll', 'NtCreateFile');
    if (ntCreateFile) {
        Interceptor.attach(ntCreateFile, {
            onEnter: function(args) {
                // args[2] = POBJECT_ATTRIBUTES containing file name
                try {
                    const objAttr = args[2];
                    const objectName = objAttr.add(Process.pointerSize * 2).readPointer(); // UNICODE_STRING*
                    const buffer = objectName.add(4).readPointer(); // Buffer field after Length/MaxLength
                    const name = buffer.readUtf16String();
                    log(`NtCreateFile("${name}")`, 'info');
                } catch (e) {
                    log('NtCreateFile() called', 'info');
                }
            }
        });
    }

    const ntWriteFile = findExport('ntdll.dll', 'NtWriteFile');
    if (ntWriteFile) {
        Interceptor.attach(ntWriteFile, {
            onEnter: function(args) {
                const length = args[6].toInt32();
                log(`NtWriteFile(handle, ${length} bytes)`, 'info');
            }
        });
    }

    const ntReadFile = findExport('ntdll.dll', 'NtReadFile');
    if (ntReadFile) {
        Interceptor.attach(ntReadFile, {
            onEnter: function(args) {
                const length = args[6].toInt32();
                log(`NtReadFile(handle, ${length} bytes)`, 'info');
            }
        });
    }

    // --- ws2_32 network ---
    const wsConnect = findExport('ws2_32.dll', 'connect');
    if (wsConnect) {
        Interceptor.attach(wsConnect, {
            onEnter: function(args) {
                log('ws2_32!connect() called', 'info');
            }
        });
    }

    const wsSend = findExport('ws2_32.dll', 'send');
    if (wsSend) {
        Interceptor.attach(wsSend, {
            onEnter: function(args) {
                const len = args[2].toInt32();
                log(`ws2_32!send(${len} bytes)`, 'info');
            }
        });
    }

    const wsRecv = findExport('ws2_32.dll', 'recv');
    if (wsRecv) {
        Interceptor.attach(wsRecv, {
            onEnter: function(args) {
                const len = args[2].toInt32();
                log(`ws2_32!recv(buf, ${len})`, 'info');
            }
        });
    }

    const wsaStartup = findExport('ws2_32.dll', 'WSAStartup');
    if (wsaStartup) {
        Interceptor.attach(wsaStartup, {
            onEnter: function(args) {
                const version = args[0].toInt32();
                log(`WSAStartup(version=${version})`, 'info');
            }
        });
    }

    // --- kernel32 process/module ---
    const createProcessW = findExport('kernel32.dll', 'CreateProcessW');
    if (createProcessW) {
        Interceptor.attach(createProcessW, {
            onEnter: function(args) {
                const appName = args[0].isNull() ? '' : Memory.readUtf16String(args[0]);
                const cmdLine = args[1].isNull() ? '' : Memory.readUtf16String(args[1]);
                log(`CreateProcessW: ${appName} ${cmdLine}`, 'warning');
                sendFinding(
                    'Process Creation',
                    'warning',
                    `CreateProcessW called: ${appName} ${cmdLine}`
                );
            }
        });
    }

    const loadLibraryW = findExport('kernel32.dll', 'LoadLibraryW');
    if (loadLibraryW) {
        Interceptor.attach(loadLibraryW, {
            onEnter: function(args) {
                const libName = Memory.readUtf16String(args[0]);
                log(`LoadLibraryW("${libName}")`, 'info');
            }
        });
    }

    // --- kernel32 file (legacy) ---
    const createFileW = findExport('kernel32.dll', 'CreateFileW');
    if (createFileW) {
        Interceptor.attach(createFileW, {
            onEnter: function(args) {
                const filename = Memory.readUtf16String(args[0]);
                log(`CreateFileW("${filename}")`, 'info');
            }
        });
    }

    // --- advapi32 registry ---
    const regOpenKeyExW = findExport('advapi32.dll', 'RegOpenKeyExW');
    if (regOpenKeyExW) {
        Interceptor.attach(regOpenKeyExW, {
            onEnter: function(args) {
                const keyName = Memory.readUtf16String(args[1]);
                log(`RegOpenKeyExW("${keyName}")`, 'info');
            }
        });
    }
}

// ============================================================
// Android — Java layer via JNI, Activity lifecycle
// ============================================================
if (isAndroid) {
    Java.perform(function() {
        log('Android Java hooks installing', 'info');

        // Activity lifecycle tracing
        try {
            const Activity = Java.use('android.app.Activity');

            Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
                log(`Activity.onCreate: ${this.getClass().getName()}`, 'info');
                return this.onCreate(bundle);
            };

            Activity.onResume.implementation = function() {
                log(`Activity.onResume: ${this.getClass().getName()}`, 'info');
                return this.onResume();
            };

            Activity.onPause.implementation = function() {
                log(`Activity.onPause: ${this.getClass().getName()}`, 'info');
                return this.onPause();
            };
        } catch (e) {
            log('Activity lifecycle hooks failed: ' + e, 'info');
        }

        // File access via java.io.File
        try {
            const File = Java.use('java.io.File');
            File.$init.overload('java.lang.String').implementation = function(path) {
                log(`new File("${path}")`, 'info');
                if (path.includes('/data/') || path.includes('/sdcard/')) {
                    sendFinding(
                        'Sensitive Path Access',
                        'warning',
                        `File object created for: ${path}`
                    );
                }
                return this.$init(path);
            };
        } catch (e) {
            log('File hook failed: ' + e, 'info');
        }

        // Runtime.exec — command execution
        try {
            const Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                log(`Runtime.exec("${cmd}")`, 'warning');
                sendFinding(
                    'Command Execution',
                    'warning',
                    `Runtime.exec() called with: ${cmd}`
                );
                return this.exec(cmd);
            };
        } catch (e) {
            log('Runtime.exec hook failed: ' + e, 'info');
        }

        // URL connections
        try {
            const URL = Java.use('java.net.URL');
            URL.openConnection.overload().implementation = function() {
                const url = this.toString();
                log(`URL.openConnection("${url}")`, 'info');
                return this.openConnection();
            };
        } catch (e) {
            log('URL hook failed: ' + e, 'info');
        }
    });

    // Native libart JNI hooks
    const artModule = Process.findModuleByName('libart.so');
    if (artModule) {
        const jniGetStringUTFChars = findExport('libart.so', '_ZN3art3JNI20GetStringUTFCharsEP7_JNIEnvP8_jstringPh');
        if (jniGetStringUTFChars) {
            Interceptor.attach(jniGetStringUTFChars, {
                onLeave: function(retval) {
                    try {
                        const str = Memory.readUtf8String(retval);
                        if (str && str.length < 256) {
                            log(`JNI GetStringUTFChars: "${str}"`, 'info');
                        }
                    } catch (e) {}
                }
            });
        }

        const jniFindClass = findExport('libart.so', '_ZN3art3JNI9FindClassEP7_JNIEnvPKc');
        if (jniFindClass) {
            Interceptor.attach(jniFindClass, {
                onEnter: function(args) {
                    try {
                        const className = Memory.readUtf8String(args[1]);
                        log(`JNI FindClass("${className}")`, 'info');
                    } catch (e) {}
                }
            });
        }
    }
}

// ============================================================
// iOS — ObjC classes: NSURLSession, NSFileManager, UIApplication
// ============================================================
if (isIOS) {
    log('iOS ObjC hooks installing', 'info');

    // NSURLSession data tasks
    try {
        const NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            const dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];
            if (dataTask) {
                Interceptor.attach(dataTask.implementation, {
                    onEnter: function(args) {
                        const request = ObjC.Object(args[2]);
                        const url = request.URL().absoluteString().toString();
                        log(`NSURLSession dataTaskWithRequest: ${url}`, 'info');
                    }
                });
            }
        }
    } catch (e) {
        log('NSURLSession hook failed: ' + e, 'info');
    }

    // NSFileManager file operations
    try {
        const NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager) {
            const fileExists = NSFileManager['- fileExistsAtPath:'];
            if (fileExists) {
                Interceptor.attach(fileExists.implementation, {
                    onEnter: function(args) {
                        const path = ObjC.Object(args[2]).toString();
                        log(`NSFileManager fileExistsAtPath: ${path}`, 'info');
                    }
                });
            }

            const contentsAtPath = NSFileManager['- contentsAtPath:'];
            if (contentsAtPath) {
                Interceptor.attach(contentsAtPath.implementation, {
                    onEnter: function(args) {
                        const path = ObjC.Object(args[2]).toString();
                        log(`NSFileManager contentsAtPath: ${path}`, 'info');
                        if (path.includes('Keychain') || path.includes('keychain')) {
                            sendFinding(
                                'Keychain Access',
                                'warning',
                                `NSFileManager reading keychain-related path: ${path}`
                            );
                        }
                    }
                });
            }
        }
    } catch (e) {
        log('NSFileManager hook failed: ' + e, 'info');
    }

    // UIApplication openURL (scheme handling)
    try {
        const UIApplication = ObjC.classes.UIApplication;
        if (UIApplication) {
            const openURL = UIApplication['- openURL:options:completionHandler:'];
            if (openURL) {
                Interceptor.attach(openURL.implementation, {
                    onEnter: function(args) {
                        const url = ObjC.Object(args[2]).absoluteString().toString();
                        log(`UIApplication openURL: ${url}`, 'warning');
                        sendFinding(
                            'URL Scheme Invocation',
                            'info',
                            `App opening URL: ${url}`
                        );
                    }
                });
            }
        }
    } catch (e) {
        log('UIApplication hook failed: ' + e, 'info');
    }
}

// ============================================================
// macOS — Foundation (NSTask, NSFileManager), Security framework
// ============================================================
if (isMacOS) {
    log('macOS ObjC/Framework hooks installing', 'info');

    // NSTask — process execution
    try {
        const NSTask = ObjC.classes.NSTask;
        if (NSTask) {
            const launch = NSTask['- launch'];
            if (launch) {
                Interceptor.attach(launch.implementation, {
                    onEnter: function(args) {
                        const task = ObjC.Object(args[0]);
                        const launchPath = task.launchPath().toString();
                        const arguments_ = task.arguments();
                        const argStr = arguments_ ? arguments_.toString() : '';
                        log(`NSTask launch: ${launchPath} ${argStr}`, 'warning');
                        sendFinding(
                            'Process Execution (macOS)',
                            'warning',
                            `NSTask launched: ${launchPath} ${argStr}`
                        );
                    }
                });
            }
        }
    } catch (e) {
        log('NSTask hook failed: ' + e, 'info');
    }

    // NSFileManager — sensitive file access
    try {
        const NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager) {
            const contentsAtPath = NSFileManager['- contentsAtPath:'];
            if (contentsAtPath) {
                Interceptor.attach(contentsAtPath.implementation, {
                    onEnter: function(args) {
                        const path = ObjC.Object(args[2]).toString();
                        log(`NSFileManager contentsAtPath: ${path}`, 'info');
                        if (path.includes('Keychains') || path.includes('.ssh') || path.includes('.gnupg')) {
                            sendFinding(
                                'Sensitive File Access (macOS)',
                                'warning',
                                `Reading sensitive path: ${path}`
                            );
                        }
                    }
                });
            }
        }
    } catch (e) {
        log('NSFileManager hook failed: ' + e, 'info');
    }

    // Security framework — SecItemCopyMatching (Keychain queries)
    try {
        const secItemCopyMatching = findExport('Security', 'SecItemCopyMatching');
        if (secItemCopyMatching) {
            Interceptor.attach(secItemCopyMatching, {
                onEnter: function(args) {
                    const query = ObjC.Object(args[0]);
                    log(`SecItemCopyMatching: ${query.toString().substring(0, 200)}`, 'warning');
                    sendFinding(
                        'Keychain Query',
                        'warning',
                        'SecItemCopyMatching called — Keychain item retrieval'
                    );
                }
            });
        }
    } catch (e) {
        log('SecItemCopyMatching hook failed: ' + e, 'info');
    }
}

log('API Tracing hooks installed', 'info');
