"""
Embedded Frida Scripts for Runtime Instrumentation

Contém scripts Frida pre-compilados para várias técnicas de análise
e bypass em ambientes Android/iOS.
"""

# Frida Scripts para Android
FRIDA_ANDROID_SCRIPTS = {
    "ssl_pinning_bypass": """
        // SSL Pinning Bypass - Certificate Validation Hook
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var TrustManager = Java.use("javax.net.ssl.TrustManager");
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

        TrustManagerImpl.verifyCertificateChain.overload("[Ljava/security/cert/X509Certificate;", "[B").implementation = function(chain, ocspData) {
            console.log("[+] SSL Pinning Bypassed - Certificate validation skipped");
            return;
        };

        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        X509Certificate.verify.overload("java.security.PublicKey").implementation = function(key) {
            console.log("[+] Certificate.verify() - Bypassed");
            return;
        };
    """,

    "root_detection_bypass": """
        // Root Detection Bypass
        var File = Java.use("java.io.File");
        var Runtime = Java.use("java.lang.Runtime");
        var Process = Java.use("java.lang.Process");

        File.exists.implementation = function() {
            var name = this.getPath();
            var dangerous_paths = [
                "/system/app/Superuser.apk",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/adb/su",
                "/system/bin/failsafe/su",
                "/su/bin/su"
            ];

            if(dangerous_paths.indexOf(name) !== -1) {
                console.log("[+] Blocked dangerous path: " + name);
                return false;
            }
            return this.exists();
        };
    """,

    "crypto_monitoring": """
        // Cryptography Monitoring
        var Cipher = Java.use("javax.crypto.Cipher");
        var MessageDigest = Java.use("java.security.MessageDigest");

        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            console.log("[*] Cipher.getInstance() called with: " + transformation);
            return this.getInstance(transformation);
        };

        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[*] Cipher.doFinal() - Input length: " + input.length);
            var result = this.doFinal(input);
            console.log("[*] Cipher.doFinal() - Output length: " + result.length);
            return result;
        };

        MessageDigest.digest.overload("[B").implementation = function(input) {
            var algorithm = this.getAlgorithm();
            console.log("[*] MessageDigest." + algorithm + ".digest() called");
            return this.digest(input);
        };
    """,

    "keystore_interception": """
        // Keystore Interception and Monitoring
        var KeyStore = Java.use("java.security.KeyStore");
        var Key = Java.use("java.security.Key");

        KeyStore.getKey.implementation = function(alias, password) {
            console.log("[*] KeyStore.getKey() - Alias: " + alias);
            var key = this.getKey(alias, password);
            if(key !== null) {
                console.log("[+] Key retrieved: " + alias);
            }
            return key;
        };

        KeyStore.load.implementation = function(stream, password) {
            console.log("[*] KeyStore.load() called");
            if(password !== null) {
                console.log("[+] Keystore password length: " + password.length);
            }
            return this.load(stream, password);
        };
    """,

    "jailbreak_detection_bypass": """
        // Jailbreak Detection Bypass
        var System = Java.use("java.lang.System");
        var Runtime = Java.use("java.lang.Runtime");

        System.getProperty.implementation = function(key) {
            var value = this.getProperty(key);

            // Fake safe system properties
            if(key === "ro.build.fingerprint") {
                console.log("[+] Spoofing fingerprint");
                return "google/marlin/marlin:8.1.0/OPM7.181205.001/5007937:user/release-keys";
            }
            if(key === "ro.debuggable") {
                console.log("[+] Hiding debuggable property");
                return "0";
            }

            return value;
        };
    """,

    "native_function_hook": """
        // Native Function Hooking for NDK Code
        var libc = Module.findExportByName(null, "printf");
        if(libc) {
            Interceptor.attach(libc, {
                onEnter: function(args) {
                    var str = args[0].readUtf8String();
                    console.log("[*] printf(): " + str);
                },
                onLeave: function(retval) {
                    console.log("[*] printf() returned: " + retval);
                }
            });
        }
    """,

    "string_interception": """
        // Intercept Sensitive Strings
        var String = Java.use("java.lang.String");

        String.$init.overload("[C").implementation = function(data) {
            var result = this.$init(data);
            var stringValue = data.toString();

            if(stringValue.indexOf("password") !== -1 ||
               stringValue.indexOf("token") !== -1 ||
               stringValue.indexOf("secret") !== -1 ||
               stringValue.indexOf("key") !== -1) {
                console.log("[!] Sensitive String Created: " + stringValue);
            }
            return result;
        };
    """,

    "http_monitoring": """
        // HTTP Request/Response Monitoring
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.getInputStream.implementation = function() {
            var url = this.getURL().toString();
            console.log("[*] HTTP Request to: " + url);
            console.log("[*] Method: " + this.getRequestMethod());
            console.log("[*] Headers: " + this.getHeaderFields());
            return this.getInputStream();
        };
    """,

    "database_monitoring": """
        // SQLite Database Monitoring
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.rawQuery.implementation = function(sql, args) {
            console.log("[*] SQL Query: " + sql);
            if(sql.toLowerCase().indexOf("password") !== -1 ||
               sql.toLowerCase().indexOf("token") !== -1) {
                console.log("[!] SENSITIVE DATA in SQL Query!");
            }
            return this.rawQuery(sql, args);
        };
    """,

    "shared_preferences_monitor": """
        // SharedPreferences Monitoring
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");

        Editor.putString.implementation = function(key, value) {
            if(key.toLowerCase().indexOf("password") !== -1 ||
               key.toLowerCase().indexOf("token") !== -1 ||
               key.toLowerCase().indexOf("secret") !== -1) {
                console.log("[!] SENSITIVE DATA stored in SharedPreferences: " + key);
            }
            return this.putString(key, value);
        };
    """,

    "debugger_detection": """
        // Debugger Detection Bypass
        var Debug = Java.use("android.os.Debug");

        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] isDebuggerConnected() - Returning false");
            return false;
        };

        Debug.waitingForDebugger.implementation = function() {
            console.log("[+] waitingForDebugger() - Returning false");
            return false;
        };
    """,
}

# Frida Scripts para iOS
FRIDA_IOS_SCRIPTS = {
    "ssl_pinning_bypass": """
        // SSL Pinning Bypass for iOS
        var SecTrustEvaluate = Module.findExportByName(null, "SecTrustEvaluate");

        if(SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onEnter: function(args) {
                    console.log("[*] SecTrustEvaluate called");
                },
                onLeave: function(retval) {
                    console.log("[+] SSL Validation bypassed - Returning success");
                    retval.replace(0); // errSecSuccess
                }
            });
        }
    """,

    "jailbreak_bypass": """
        // Jailbreak Detection Bypass for iOS
        var NSFileManager = ObjC.classes.NSFileManager;
        var NSString = ObjC.classes.NSString;

        var dangerous_files = [
            "/Applications/Cydia.app",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
        ];

        var fileManagerDefaultManager = NSFileManager.defaultManager();
        var fileExists = fileManagerDefaultManager.fileExistsAtPath_;

        fileExists.implementation = function(path) {
            if(dangerous_files.indexOf(path) !== -1) {
                console.log("[+] Blocked jailbreak check for: " + path);
                return false;
            }
            return fileExists.call(this, path);
        };
    """,

    "crypto_monitoring": """
        // iOS Crypto Monitoring
        var CCCrypt = Module.findExportByName(null, "CCCrypt");

        if(CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    console.log("[*] CCCrypt called - Op: " + args[0] + " Algorithm: " + args[1]);
                },
                onLeave: function(retval) {
                    console.log("[*] CCCrypt returned: " + retval);
                }
            });
        }
    """,

    "http_monitoring": """
        // iOS HTTP Monitoring
        var URLSession = ObjC.classes.NSURLSession;
        var URLRequest = ObjC.classes.NSURLRequest;

        var dataTaskWithRequest = URLSession.dataTaskWithRequest_.implementation;

        URLSession.dataTaskWithRequest_.implementation = function(request) {
            var url = request.URL().absoluteString();
            console.log("[*] HTTP Request to: " + url);
            return dataTaskWithRequest.call(this, request);
        };
    """,

    "keychain_monitor": """
        // iOS Keychain Monitoring
        var SecItemAdd = Module.findExportByName(null, "SecItemAdd");

        if(SecItemAdd) {
            Interceptor.attach(SecItemAdd, {
                onEnter: function(args) {
                    console.log("[*] SecItemAdd called - Storing item in Keychain");
                },
                onLeave: function(retval) {
                    console.log("[*] Keychain operation status: " + retval);
                }
            });
        }
    """,
}

# Utility scripts
FRIDA_UTILITY_SCRIPTS = {
    "enumerate_classes": """
        // Enumerate all loaded classes
        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if(className.indexOf("com.example") !== -1) {
                        console.log(className);
                    }
                },
                onComplete: function() {
                    console.log("[+] Class enumeration complete");
                }
            });
        });
    """,

    "enumerate_methods": """
        // Enumerate methods of a class
        Java.perform(function() {
            var TargetClass = Java.use("com.example.ClassName");
            var methods = TargetClass.class.getMethods();

            for(var i = 0; i < methods.length; i++) {
                console.log("[+] " + methods[i].toString());
            }
        });
    """,

    "dump_memory": """
        // Dump specific memory regions
        var memoryData = Memory.readUtf8String(ptr(addr), size);
        console.log("[*] Memory dump: " + memoryData);
    """,
}


class FridaScriptManager:
    """Gerenciador de scripts Frida"""

    def __init__(self):
        self.android_scripts = FRIDA_ANDROID_SCRIPTS
        self.ios_scripts = FRIDA_IOS_SCRIPTS
        self.utility_scripts = FRIDA_UTILITY_SCRIPTS

    def get_script(self, platform: str, script_name: str) -> str:
        """Retorna um script Frida específico"""
        if platform.lower() == "android":
            return self.android_scripts.get(script_name, "")
        elif platform.lower() == "ios":
            return self.ios_scripts.get(script_name, "")
        return ""

    def list_scripts(self, platform: str) -> list:
        """Lista scripts disponíveis"""
        if platform.lower() == "android":
            return list(self.android_scripts.keys())
        elif platform.lower() == "ios":
            return list(self.ios_scripts.keys())
        return []

    def get_all_scripts(self, platform: str) -> dict:
        """Retorna todos os scripts para uma plataforma"""
        if platform.lower() == "android":
            return self.android_scripts
        elif platform.lower() == "ios":
            return self.ios_scripts
        return {}

    def combine_scripts(self, platform: str, script_names: list) -> str:
        """Combina múltiplos scripts em um único payload"""
        combined = """
        console.log("[*] Frida Instrumentation Framework Loaded");
        console.log("[*] Platform: """ + platform + """");

        """

        scripts = self.get_all_scripts(platform)
        for name in script_names:
            if name in scripts:
                combined += f"\n// ========== {name} ==========\n"
                combined += scripts[name]
                combined += "\n\n"

        return combined
