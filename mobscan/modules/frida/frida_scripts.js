/**
 * Mobscan - Professional Frida Scripts Library
 *
 * Collection of Frida instrumentation scripts for mobile security testing
 */

// ============================================================================
// ROOT/JAILBREAK DETECTION BYPASS
// ============================================================================

function bypassRootDetection() {
    console.log("[+] Attempting to bypass root detection...");

    Java.perform(function() {
        // Bypass su binary check
        var Runtime = Java.use("java.lang.Runtime");
        var exec = Runtime.exec.overload("[Ljava/lang/String;").implementation = function(cmdArray) {
            console.log("[!] Runtime.exec called with: " + cmdArray);
            if (cmdArray && cmdArray.length > 0) {
                var cmd = cmdArray[0];
                if (cmd && cmd.includes("su")) {
                    console.log("[!] Blocking su check");
                    throw new Error("Permission denied");
                }
            }
            return this.exec(cmdArray);
        };

        // Bypass file existence checks
        var File = Java.use("java.io.File");
        var exists = File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var blocked_paths = ["/system/app/Superuser.apk", "/system/bin/su", "/data/local/tmp/su"];

            for (var i = 0; i < blocked_paths.length; i++) {
                if (path.includes(blocked_paths[i])) {
                    console.log("[!] Blocking file check: " + path);
                    return false;
                }
            }
            return this.exists();
        };

        console.log("[+] Root detection bypass hooks installed");
    });
}

// ============================================================================
// SSL PINNING BYPASS
// ============================================================================

function bypassSSLPinning() {
    console.log("[+] Attempting to bypass SSL pinning...");

    Java.perform(function() {
        // Bypass OkHttp certificate pinning
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
            var setCertificatePinner = OkHttpClient.certificatePinner.implementation = function(pinner) {
                console.log("[!] Certificate pinner bypassed");
                return this;
            };
            console.log("[+] OkHttp SSL pinning hook installed");
        } catch(e) {
            console.log("[-] OkHttp not found");
        }

        // Bypass HttpURLConnection verification
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var init = SSLContext.init.overload("[Ljavax/net/ssl/KeyManager;", "[Ljavax/net/ssl/TrustManager;", "Ljava/security/SecureRandom;").implementation = function(keyManagers, trustManagers, secureRandom) {
                console.log("[!] SSLContext.init hooked - bypassing SSL verification");
                return this.init(keyManagers, [Java.use("javax.net.ssl.X509TrustManager").$new({
                    checkClientTrusted: function() {},
                    checkServerTrusted: function() {},
                    getAcceptedIssuers: function() { return []; }
                })], secureRandom);
            };
        } catch(e) {
            console.log("[-] SSLContext hook failed");
        }

        console.log("[+] SSL pinning bypass hooks installed");
    });
}

// ============================================================================
// DEBUGGER DETECTION BYPASS
// ============================================================================

function bypassDebuggerDetection() {
    console.log("[+] Attempting to bypass debugger detection...");

    Java.perform(function() {
        // Bypass Debug.isDebuggerConnected
        var Debug = Java.use("android.os.Debug");
        var isDebuggerConnected = Debug.isDebuggerConnected.implementation = function() {
            console.log("[!] Debug.isDebuggerConnected called");
            return false;
        };

        // Bypass android.util.Log debug check
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentActivityThread = ActivityThread.currentActivityThread();

        console.log("[+] Debugger detection bypass hooks installed");
    });
}

// ============================================================================
// MONITOR CRYPTO OPERATIONS
// ============================================================================

function monitorCryptoOperations() {
    console.log("[+] Installing crypto operation monitors...");

    Java.perform(function() {
        // Monitor Cipher operations
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var init = Cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
                console.log("[*] Cipher.init called");
                console.log("    Mode: " + opmode);
                console.log("    Algorithm: " + this.getAlgorithm());
                return this.init(opmode, key);
            };

            var doFinal = Cipher.doFinal.overload("[B").implementation = function(input) {
                console.log("[*] Cipher.doFinal called");
                console.log("    Input length: " + input.length);
                return this.doFinal(input);
            };

            console.log("[+] Cipher monitoring installed");
        } catch(e) {
            console.log("[-] Cipher monitoring failed");
        }

        // Monitor MessageDigest (hashing)
        try {
            var MessageDigest = Java.use("java.security.MessageDigest");
            var getInstance = MessageDigest.getInstance.implementation = function(algorithm) {
                console.log("[*] MessageDigest.getInstance called");
                console.log("    Algorithm: " + algorithm);
                return this.getInstance(algorithm);
            };

            console.log("[+] MessageDigest monitoring installed");
        } catch(e) {
            console.log("[-] MessageDigest monitoring failed");
        }
    });
}

// ============================================================================
// MONITOR STORAGE OPERATIONS
// ============================================================================

function monitorStorageOperations() {
    console.log("[+] Installing storage operation monitors...");

    Java.perform(function() {
        // Monitor SharedPreferences
        try {
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            var putString = SharedPreferences.Editor.putString.implementation = function(key, value) {
                console.log("[*] SharedPreferences.putString");
                console.log("    Key: " + key);
                console.log("    Value: " + (value ? value.substring(0, 50) : "null"));
                return this.putString(key, value);
            };

            console.log("[+] SharedPreferences monitoring installed");
        } catch(e) {
            console.log("[-] SharedPreferences monitoring failed");
        }

        // Monitor SQLiteDatabase
        try {
            var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
            var execSQL = SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
                console.log("[*] SQLiteDatabase.execSQL");
                console.log("    SQL: " + sql.substring(0, 100));
                return this.execSQL(sql);
            };

            console.log("[+] SQLiteDatabase monitoring installed");
        } catch(e) {
            console.log("[-] SQLiteDatabase monitoring failed");
        }

        // Monitor File operations
        try {
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var write = FileOutputStream.write.overload("[B").implementation = function(data) {
                console.log("[*] FileOutputStream.write");
                console.log("    Bytes written: " + data.length);
                return this.write(data);
            };

            console.log("[+] File operations monitoring installed");
        } catch(e) {
            console.log("[-] File operations monitoring failed");
        }
    });
}

// ============================================================================
// MONITOR NETWORK OPERATIONS
// ============================================================================

function monitorNetworkOperations() {
    console.log("[+] Installing network operation monitors...");

    Java.perform(function() {
        // Monitor HttpURLConnection
        try {
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            var setRequestMethod = HttpURLConnection.setRequestMethod.implementation = function(method) {
                console.log("[*] HttpURLConnection.setRequestMethod");
                console.log("    Method: " + method);
                console.log("    URL: " + this.getURL());
                return this.setRequestMethod(method);
            };

            console.log("[+] HttpURLConnection monitoring installed");
        } catch(e) {
            console.log("[-] HttpURLConnection monitoring failed");
        }

        // Monitor OkHttp requests
        try {
            var RealCall = Java.use("okhttp3.RealCall");
            var execute = RealCall.execute.implementation = function() {
                console.log("[*] OkHttp request executed");
                console.log("    URL: " + this.request().url());
                return this.execute();
            };

            console.log("[+] OkHttp monitoring installed");
        } catch(e) {
            console.log("[-] OkHttp monitoring failed");
        }
    });
}

// ============================================================================
// DUMP APPLICATION CACHE
// ============================================================================

function dumpApplicationCache() {
    console.log("[+] Dumping application cache...");

    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentActivityThread = ActivityThread.currentActivityThread();
        var context = currentActivityThread.getSystemContext();

        var cacheDir = context.getCacheDir();
        console.log("[*] Cache directory: " + cacheDir.getAbsolutePath());

        // List files in cache
        var files = cacheDir.listFiles();
        if (files) {
            for (var i = 0; i < files.length; i++) {
                console.log("    - " + files[i].getName() + " (" + files[i].length() + " bytes)");
            }
        }
    });
}

// ============================================================================
// EXTRACT APPLICATION DATA
// ============================================================================

function extractApplicationData() {
    console.log("[+] Extracting application data...");

    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentActivityThread = ActivityThread.currentActivityThread();
        var context = currentActivityThread.getSystemContext();

        // Get files directory
        var filesDir = context.getFilesDir();
        console.log("[*] Files directory: " + filesDir.getAbsolutePath());

        // Get database directory
        var dbPath = context.getDatabasePath("default");
        console.log("[*] Database directory: " + dbPath.getParent());

        // Get shared preferences
        var sharedPref = context.getSharedPreferences("default", 0);
        var preferences = sharedPref.getAll();
        console.log("[*] Shared Preferences:");
        var iterator = preferences.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            console.log("    " + entry.getKey() + " = " + entry.getValue());
        }
    });
}

// ============================================================================
// HOOK SPECIFIC METHODS
// ============================================================================

function hookMethod(className, methodName, callback) {
    console.log("[+] Hooking method: " + className + "." + methodName);

    Java.perform(function() {
        try {
            var clazz = Java.use(className);
            var method = clazz[methodName];
            if (method) {
                method.implementation = callback;
                console.log("[+] Successfully hooked " + className + "." + methodName);
            } else {
                console.log("[-] Method not found: " + className + "." + methodName);
            }
        } catch(e) {
            console.log("[-] Failed to hook: " + e);
        }
    });
}

// ============================================================================
// MAIN - Export functions
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        bypassRootDetection: bypassRootDetection,
        bypassSSLPinning: bypassSSLPinning,
        bypassDebuggerDetection: bypassDebuggerDetection,
        monitorCryptoOperations: monitorCryptoOperations,
        monitorStorageOperations: monitorStorageOperations,
        monitorNetworkOperations: monitorNetworkOperations,
        dumpApplicationCache: dumpApplicationCache,
        extractApplicationData: extractApplicationData,
        hookMethod: hookMethod
    };
}
