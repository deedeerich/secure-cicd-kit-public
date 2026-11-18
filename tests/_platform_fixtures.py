#!/usr/bin/env python3
"""Generate the PLATFORM fixtures: Android/Kotlin, iOS (Swift and Objective-C), build-aware C/C++,
and a realistic multi-project .NET solution (lane L-SCAN-B, KDEC-026).

EVERY FILE THIS WRITES IS INTENTIONALLY DEFECTIVE. It is generated, never committed, for the same
reason tests/make_fixture.py is: a keystore password or an ATS exception in a committed file reads,
to every scanner pointed at this kit, exactly like the real thing. Nothing here is a real credential.

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.
validate-scanners.yml calls it beside make_fixture.py (fixture/android, fixture/ios,
fixture/cpp-build, fixture/dotnet-solution); the proofs import it and write the same trees into a
throwaway directory. tests/consumer-fixture/full/ is NOT extended by it: that tree's signal contract
is graded by the consumer path, and these trees are proven by their own probes first.

Usage:  python tests/_platform_fixtures.py --out <dir> [--only android,ios,cpp-build,dotnet-solution]

PLATFORM_SIGNALS.json (written beside the trees) is the planted-finding contract: which rule, from
which tool, must fire on which file. The proofs and the validate-scanners legs grade against it.
"""
from __future__ import annotations

import argparse
import json
import os
import textwrap

# Assembled from fragments so no complete password assignment sits in this source file; the
# generated file carries the whole string, which is what the rule under test must see.
_PW = "android" + "123"

BANNER_XML = "<!-- SYNTHETIC SECURITY FIXTURE: INTENTIONALLY VULNERABLE. DO NOT DEPLOY. -->"
BANNER_C = "// SYNTHETIC SECURITY FIXTURE: INTENTIONALLY VULNERABLE. DO NOT DEPLOY."


def _d(s):
    return textwrap.dedent(s).lstrip("\n")


# ---------------------------------------------------------------- Android / Kotlin
ANDROID = {
    "settings.gradle.kts": _d('''
        rootProject.name = "fixture-android"
        include(":app", ":lib")
        '''),
    "app/src/main/AndroidManifest.xml": _d('''
        <?xml version="1.0" encoding="utf-8"?>
        %s
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.fixture">
            <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="33" />
            <application
                android:allowBackup="true"
                android:debuggable="true"
                android:usesCleartextTraffic="true"
                android:networkSecurityConfig="@xml/network_security_config"
                android:label="Fixture">
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <activity android:name=".AdminActivity" android:exported="true" />
                <provider android:name=".DataProvider"
                    android:authorities="com.example.fixture.data" android:exported="true" />
                <service android:name=".SyncService" android:exported="true"
                    android:permission="com.example.fixture.permission.SYNC" />
            </application>
        </manifest>
        ''') % BANNER_XML,
    "app/src/main/res/xml/network_security_config.xml": _d('''
        <?xml version="1.0" encoding="utf-8"?>
        %s
        <network-security-config>
            <base-config cleartextTrafficPermitted="true">
                <trust-anchors>
                    <certificates src="system" />
                    <certificates src="user" />
                </trust-anchors>
            </base-config>
        </network-security-config>
        ''') % BANNER_XML,
    "app/build.gradle": _d('''
        %s
        android {
            compileSdkVersion 33
            defaultConfig {
                applicationId "com.example.fixture"
                minSdkVersion 16
                targetSdkVersion 33
            }
            signingConfigs {
                release {
                    storeFile file("release.keystore")
                    storePassword "%s"
                    keyAlias "fixture"
                    keyPassword "%s"
                }
            }
            buildTypes {
                release {
                    debuggable true
                    signingConfig signingConfigs.release
                }
            }
        }
        ''') % (BANNER_C, _PW, _PW),
    "lib/build.gradle.kts": _d('''
        %s
        android {
            defaultConfig {
                minSdk = 19
            }
            signingConfigs {
                create("release") {
                    storePassword = "%s"
                    keyPassword = "%s"
                }
            }
        }
        ''') % (BANNER_C, _PW, _PW),
    "app/src/main/java/com/example/fixture/MainActivity.kt": _d('''
        %s
        package com.example.fixture

        import android.app.Activity
        import android.os.Bundle
        import android.util.Log
        import android.webkit.WebView
        import java.security.MessageDigest
        import javax.crypto.Cipher

        class MainActivity : Activity() {
            override fun onCreate(savedInstanceState: Bundle?) {
                super.onCreate(savedInstanceState)
                val web = WebView(this)
                web.settings.javaScriptEnabled = true
                web.addJavascriptInterface(Bridge(), "bridge")
                web.loadUrl(intent.getStringExtra("url") ?: "http://example.com")
            }

            fun hash(p: String): ByteArray {
                Log.d("auth", "password=" + p)
                return MessageDigest.getInstance("MD5").digest(p.toByteArray())
            }

            fun encrypt(b: ByteArray): ByteArray {
                val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
                return c.doFinal(b)
            }
        }

        class Bridge
        ''') % BANNER_C,
}

# The clean counterpart: the same shapes, every planted condition removed. A rule that fires here
# is a false positive, and the proofs fail on it.
ANDROID_CLEAN = {
    "app/src/main/AndroidManifest.xml": _d('''
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.clean">
            <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
            <application
                android:allowBackup="false"
                android:usesCleartextTraffic="false"
                android:label="Clean">
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <activity android:name=".Internal" android:exported="false" />
                <service android:name=".Sync" android:exported="true"
                    android:permission="com.example.clean.permission.SYNC" />
            </application>
        </manifest>
        '''),
    "app/src/main/res/xml/network_security_config.xml": _d('''
        <?xml version="1.0" encoding="utf-8"?>
        <network-security-config>
            <base-config cleartextTrafficPermitted="false" />
        </network-security-config>
        '''),
    "app/build.gradle": _d('''
        android {
            defaultConfig {
                minSdkVersion 26
            }
            signingConfigs {
                release {
                    storePassword System.getenv("STORE_PASSWORD")
                    keyPassword System.getenv("KEY_PASSWORD")
                }
            }
        }
        '''),
    "lib/build.gradle.kts": _d('''
        android {
            defaultConfig {
                minSdk = 26
            }
            signingConfigs {
                create("release") {
                    storePassword = System.getenv("STORE_PASSWORD")
                    keyPassword = providers.gradleProperty("keyPassword").get()
                }
            }
        }
        '''),
}

# ---------------------------------------------------------------- iOS: Swift and Objective-C
IOS = {
    "App/Info.plist": _d('''
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        %s
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.example.fixture</string>
            <key>NSAppTransportSecurity</key>
            <dict>
                <key>NSAllowsArbitraryLoads</key>
                <true/>
                <key>NSExceptionDomains</key>
                <dict>
                    <key>api.example.com</key>
                    <dict>
                        <key>NSExceptionAllowsInsecureHTTPLoads</key>
                        <true/>
                        <key>NSExceptionMinimumTLSVersion</key>
                        <string>TLSv1.0</string>
                    </dict>
                </dict>
            </dict>
        </dict>
        </plist>
        ''') % BANNER_XML,
    "App/KeychainStore.swift": _d('''
        %s
        import Foundation
        import Security
        import CommonCrypto
        import UIKit

        class KeychainStore {
            func save(password: String) {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: "user",
                    kSecValueData as String: password.data(using: .utf8)!,
                    kSecAttrAccessible as String: kSecAttrAccessibleAlways
                ]
                SecItemAdd(query as CFDictionary, nil)
                UserDefaults.standard.set(password, forKey: "password")
            }

            func digest(_ data: Data) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
                data.withUnsafeBytes { _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &out) }
                return out
            }

            func load() {
                let web = UIWebView()
                web.loadRequest(URLRequest(url: URL(string: "http://api.example.com/login")!))
            }
        }
        ''') % BANNER_C,
    "App/Legacy.m": _d('''
        %s
        #import <Foundation/Foundation.h>
        #import <Security/Security.h>
        #import <CommonCrypto/CommonDigest.h>
        #import <UIKit/UIKit.h>

        @implementation Legacy
        - (void)store:(NSString *)password {
            NSDictionary *q = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlways,
                                 (__bridge id)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding] };
            SecItemAdd((__bridge CFDictionaryRef)q, NULL);
            NSLog(@"password is %%@", password);
            char buf[16];
            strcpy(buf, [password UTF8String]);
            unsigned char md[CC_MD5_DIGEST_LENGTH];
            CC_MD5(buf, (CC_LONG)strlen(buf), md);
            UIWebView *w = [[UIWebView alloc] init];
            [w loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"http://api.example.com"]]];
        }
        @end
        ''') % BANNER_C,
}

IOS_CLEAN = {
    "App/Info.plist": _d('''
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleIdentifier</key>
            <string>com.example.clean</string>
            <key>NSAppTransportSecurity</key>
            <dict>
                <key>NSAllowsArbitraryLoads</key>
                <false/>
            </dict>
        </dict>
        </plist>
        '''),
    "App/Calc.swift": "struct Calc {\n    func add(_ a: Int, _ b: Int) -> Int { return a + b }\n}\n",
    "App/Calc.m": ("#import <Foundation/Foundation.h>\n@implementation Calc\n"
                   "- (NSInteger)add:(NSInteger)a to:(NSInteger)b { return a + b; }\n@end\n"),
}

# ---------------------------------------------------------------- build-aware C/C++
# THE DEFECT IS ONLY VISIBLE THROUGH THE BUILD. BUF_LEN comes from include/config.h, which is found
# only through the include directory CMake passes (-I include). Source-only, cppcheck cannot resolve
# the macro and is silent; with the compilation database it reports the out-of-bounds write. That
# difference is what a source-only scan reads as clean, and why it is CPP_ANALYSIS_PARTIAL.
CPP_BUILD = {
    "cmake/CMakeLists.txt": _d('''
        cmake_minimum_required(VERSION 3.10)
        project(fixture C)
        add_executable(fixture src/main.c)
        target_include_directories(fixture PRIVATE include)
        '''),
    "cmake/include/config.h": "#define BUF_LEN 8\n",
    "cmake/src/main.c": _d('''
        %s
        #include "config.h"
        int main(void) {
            char buf[BUF_LEN];
            buf[BUF_LEN] = 0;
            return buf[0];
        }
        ''') % BANNER_C,
    "make/Makefile": _d('''
        CFLAGS = -Iinclude
        all: app
        app: src/app.c
        \tcc $(CFLAGS) -c src/app.c -o app.o
        '''),
    "make/include/limits_cfg.h": "#define SLOTS 4\n",
    "make/src/app.c": _d('''
        %s
        #include "limits_cfg.h"
        int main(void) {
            int slots[SLOTS];
            slots[SLOTS] = 1;
            return slots[0];
        }
        ''') % BANNER_C,
    # Source with no build system at all: the scan must say CPP_ANALYSIS_PARTIAL and must NOT
    # invent one. Nothing may be written beside these files.
    "nobuild/src/loose.c": "int loose(int a) { return a * 2; }\n",
}

# ---------------------------------------------------------------- a real-shaped .NET solution
# Multi-project: an ASP.NET Core web project referencing a data library; a test project; a
# solution file tying them together. The vulnerable NuGet versions are long-published High
# advisories (Newtonsoft.Json 12.0.1: GHSA-5crp-9r3c-p9vr; System.Data.SqlClient 4.8.5:
# GHSA-98g6-xh36-x2p7 / CVE-2024-0056). The controller carries the planted SAST findings.
_SLN = '''
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Shop.Web", "src\\Shop.Web\\Shop.Web.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Shop.Data", "src\\Shop.Data\\Shop.Data.csproj", "{22222222-2222-2222-2222-222222222222}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Shop.Tests", "tests\\Shop.Tests\\Shop.Tests.csproj", "{33333333-3333-3333-3333-333333333333}"
EndProject
Global
\tGlobalSection(SolutionConfigurationPlatforms) = preSolution
\t\tDebug|Any CPU = Debug|Any CPU
\tEndGlobalSection
\tGlobalSection(ProjectConfigurationPlatforms) = postSolution
\t\t{11111111-1111-1111-1111-111111111111}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
\t\t{11111111-1111-1111-1111-111111111111}.Debug|Any CPU.Build.0 = Debug|Any CPU
\t\t{22222222-2222-2222-2222-222222222222}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
\t\t{22222222-2222-2222-2222-222222222222}.Debug|Any CPU.Build.0 = Debug|Any CPU
\t\t{33333333-3333-3333-3333-333333333333}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
\t\t{33333333-3333-3333-3333-333333333333}.Debug|Any CPU.Build.0 = Debug|Any CPU
\tEndGlobalSection
EndGlobal
'''.lstrip("\n")

DOTNET_SOLUTION = {
    "Shop.sln": _SLN,
    "src/Shop.Web/Shop.Web.csproj": _d('''
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup>
            <TargetFramework>net8.0</TargetFramework>
            <Nullable>enable</Nullable>
          </PropertyGroup>
          <ItemGroup>
            <!-- Known-vulnerable: GHSA-5crp-9r3c-p9vr (High) -->
            <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
          </ItemGroup>
          <ItemGroup>
            <ProjectReference Include="..\\Shop.Data\\Shop.Data.csproj" />
          </ItemGroup>
        </Project>
        '''),
    "src/Shop.Web/Program.cs": _d('''
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddControllers();
        var app = builder.Build();
        app.MapControllers();
        app.Run();
        '''),
    "src/Shop.Web/Controllers/OrdersController.cs": _d('''
        %s
        using System.Data.SqlClient;
        using System.Diagnostics;
        using Microsoft.AspNetCore.Mvc;

        namespace Shop.Web.Controllers;

        [ApiController]
        [Route("api/[controller]")]
        public class OrdersController : ControllerBase
        {
            private readonly SqlConnection _conn = new SqlConnection("Server=db;Database=shop;Integrated Security=true");

            [HttpGet("search")]
            public IActionResult Search(string customer)
            {
                // planted: SQL built by concatenation from request input
                var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = '" + customer + "'", _conn);
                return Ok(cmd.ExecuteScalar());
            }

            [HttpPost("export")]
            public IActionResult Export(string format)
            {
                // planted: request input reaches a process start
                Process.Start("cmd.exe", "/c export.bat " + format);
                return Ok();
            }

            [HttpGet("go")]
            public IActionResult Go(string returnUrl)
            {
                // planted: open redirect
                return Redirect(returnUrl);
            }
        }
        ''') % BANNER_C,
    "src/Shop.Data/Shop.Data.csproj": _d('''
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFramework>net8.0</TargetFramework>
          </PropertyGroup>
          <ItemGroup>
            <!-- Known-vulnerable: CVE-2024-0056 / GHSA-98g6-xh36-x2p7 (High) -->
            <PackageReference Include="System.Data.SqlClient" Version="4.8.5" />
          </ItemGroup>
        </Project>
        '''),
    "src/Shop.Data/OrderRepository.cs": _d('''
        namespace Shop.Data;
        public class OrderRepository
        {
            public string Table => "Orders";
        }
        '''),
    "tests/Shop.Tests/Shop.Tests.csproj": _d('''
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFramework>net8.0</TargetFramework>
            <IsPackable>false</IsPackable>
          </PropertyGroup>
          <ItemGroup>
            <ProjectReference Include="..\\..\\src\\Shop.Data\\Shop.Data.csproj" />
          </ItemGroup>
        </Project>
        '''),
    "tests/Shop.Tests/RepositoryTests.cs": _d('''
        namespace Shop.Tests;
        public class RepositoryTests
        {
            public bool TableIsOrders() => new Shop.Data.OrderRepository().Table == "Orders";
        }
        '''),
}

TREES = {
    "android": ANDROID,
    "android-clean": ANDROID_CLEAN,
    "ios": IOS,
    "ios-clean": IOS_CLEAN,
    "cpp-build": CPP_BUILD,
    "dotnet-solution": DOTNET_SOLUTION,
}

# THE PLANTED-FINDING CONTRACT. (tree, file, tool, rule-id fragment). A probe passes for a row only
# when THAT tool reports a rule whose id contains the fragment on THAT file -- never "something
# somewhere". The fragments are the rule ids measured on 2026-10-23 (KDEC-026).
_MAN = "app/src/main/AndroidManifest.xml"
_NSC = "app/src/main/res/xml/network_security_config.xml"
_KT = "app/src/main/java/com/example/fixture/MainActivity.kt"
SIGNALS = [
    # mobsfscan 1.0.1 (sast-mobile): manifest, network security config, Kotlin, Info.plist ATS,
    # Swift and Objective-C. Measured 2026-10-23, python:3.12-slim, mobsfscan 1.0.1 / semgrep 1.172.0.
    ("android", _MAN, "mobsfscan", "android_manifest_debugging_enabled"),
    ("android", _MAN, "mobsfscan", "android_manifest_allow_backup"),
    ("android", _MAN, "mobsfscan", "android_manifest_usescleartext"),
    ("android", _MAN, "mobsfscan", "android_manifest_insecure_minsdk_error"),
    ("android", _NSC, "mobsfscan", "android_manifest_base_config_cleartext"),
    ("android", _NSC, "mobsfscan", "android_manifest_base_config_trust_user_certs"),
    ("android", _KT, "mobsfscan", "android_kotlin_aes_ecb"),
    ("android", _KT, "mobsfscan", "android_kotlin_md5"),
    ("android", _KT, "mobsfscan", "android_kotlin_webview"),
    ("ios", "App/Info.plist", "mobsfscan", "ios_ats_arbitrary_loads"),
    ("ios", "App/Info.plist", "mobsfscan", "ios_ats_insecure_http_loads"),
    ("ios", "App/Info.plist", "mobsfscan", "ios_ats_weak_tls"),
    ("ios", "App/KeychainStore.swift", "mobsfscan", "ios_keychain_weak_accessibility_value"),
    ("ios", "App/KeychainStore.swift", "mobsfscan", "ios_uiwebview"),
    ("ios", "App/Legacy.m", "mobsfscan", "ios_weak_hash"),
    ("ios", "App/Legacy.m", "mobsfscan", "ios_banned_api"),
    # the kit's own rules, for what mobsfscan does not read (.github/actions/sast-mobile/
    # mobile-config.semgrep.yml): exported components, Gradle signing passwords, minSdk, debuggable.
    ("android", _MAN, "mobile-config", "android-exported-without-permission"),
    ("android", "app/build.gradle", "mobile-config", "android-gradle-hardcoded-signing-password"),
    ("android", "app/build.gradle", "mobile-config", "android-gradle-min-sdk-too-low"),
    ("android", "app/build.gradle", "mobile-config", "android-gradle-debuggable-release"),
    ("android", "lib/build.gradle.kts", "mobile-config", "android-gradle-hardcoded-signing-password"),
    ("android", "lib/build.gradle.kts", "mobile-config", "android-gradle-min-sdk-too-low"),
    # semgrep p/kotlin, the floor sast-semgrep adds whenever Kotlin is discovered
    ("android", _KT, "semgrep-kotlin", "kotlin.lang.security.use-of-md5"),
    ("android", _KT, "semgrep-kotlin", "kotlin.lang.security.ecb-cipher"),
    # build-aware cppcheck (sast-cpp): visible ONLY through the compilation database
    ("cpp-build", "cmake/src/main.c", "cppcheck", "arrayIndexOutOfBounds"),
    ("cpp-build", "make/src/app.c", "cppcheck", "arrayIndexOutOfBounds"),
    # the .NET solution (sast-dotnet): NuGet audit per project, Semgrep C# on the controller
    ("dotnet-solution", "src/Shop.Web/Shop.Web.csproj", "dotnet-vuln", "GHSA-5crp-9r3c-p9vr"),
    ("dotnet-solution", "src/Shop.Data/Shop.Data.csproj", "dotnet-vuln", "GHSA-98g6-xh36-x2p7"),
    ("dotnet-solution", "src/Shop.Web/Controllers/OrdersController.cs", "semgrep-csharp", "sql"),
]


def write_tree(root, name):
    for rel, body in TREES[name].items():
        p = os.path.join(root, name, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=",".join(TREES))
    a = ap.parse_args()
    names = [n for n in a.only.split(",") if n]
    unknown = [n for n in names if n not in TREES]
    if unknown:
        raise SystemExit("unknown tree(s): %s" % ", ".join(unknown))
    os.makedirs(a.out, exist_ok=True)
    for n in names:
        write_tree(a.out, n)
    with open(os.path.join(a.out, "PLATFORM_SIGNALS.json"), "w", encoding="utf-8") as fh:
        json.dump([{"tree": t, "path": p, "tool": tool, "rule": r} for t, p, tool, r in SIGNALS
                   if t in names], fh, indent=2)
    print("platform fixtures written to %s: %s" % (a.out, ", ".join(names)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
