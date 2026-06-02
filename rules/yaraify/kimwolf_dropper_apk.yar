/*
    Kimwolf residential proxy botnet -- Android APK dropper variants
    Detects the APK wrappers used to deliver Kimwolf ELF payloads to
    Android devices via ADB sideloading or direct install.

    Detection relies on two data sources visible to YARA inside APKs:
      1. Native library filenames in ZIP local/central directory headers
         (plaintext even though file contents are deflate-compressed)
      2. Package names in resources.arsc, which Android requires to be
         STORE'd (uncompressed) -- encoded as UTF-16LE

    Samples:
      - 54c478b499829a41f57edf93753b9842ab67dc13cff2cc1326ad7ced2f3dc0b9 (com.abcproxy.proxysdk, arm64+armv7)
      - 569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cca3d5 (com.example.networkservice, Jan 2026)
      - 68ea5dc48101d8bd27c4b237093025d8cf5b9d9985dc96363f2c7882f2b56341 (com.android.logcatd + Tor, Feb 2026)
      - 951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36 (com.android.logcatd non-root, Mar 2026)
      - fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4 (libdevice_emu.so + device_task assets, Dec 2025)
      - b9047ded41187be3c15d0d183e4fdd3d38c8f2fe16dcc495a68d12e5c7ff0f8c (libdevice.so + libbcsdk.so, Jan 2026)
      - c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73 (com.abcproxy.lolsdk, Mar 2026)
*/

rule kimwolf_dropper_apk
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - Android APK dropper"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "8788f651-5f65-4c0f-a192-dc16c77a4cd6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "09587b0c67d0c9e7211c8b2edb6037ba"

    strings:
        // Native library paths in ZIP local/central directory headers
        $lib_device = "libdevice.so"
        $lib_device1 = "libdevice1.so"
        $lib_device_emu = "libdevice_emu.so"
        $lib_android_rt = "libandroid_runtime.so"
        $lib_dalvik_rt = "libdalvik_runtime.so"
        $lib_bcsdk = "libbcsdk.so"

        // Asset paths in ZIP directory (older dropper variants)
        $asset_task = "assets/device_task"

        // APK structural markers (ZIP directory entries)
        $classes_dex = "classes.dex"
        $manifest = "AndroidManifest.xml"

        // Kimwolf package names in resources.arsc (STORE'd, UTF-16LE)
        $pkg_proxysdk = { 63 00 6f 00 6d 00 2e 00 61 00 62 00 63 00 70 00
                          72 00 6f 00 78 00 79 00 2e 00 70 00 72 00 6f 00
                          78 00 79 00 73 00 64 00 6b 00 }  // com.abcproxy.proxysdk
        $pkg_lolsdk   = { 63 00 6f 00 6d 00 2e 00 61 00 62 00 63 00 70 00
                          72 00 6f 00 78 00 79 00 2e 00 6c 00 6f 00 6c 00
                          73 00 64 00 6b 00 }  // com.abcproxy.lolsdk
        $pkg_logcatd  = { 63 00 6f 00 6d 00 2e 00 61 00 6e 00 64 00 72 00
                          6f 00 69 00 64 00 2e 00 6c 00 6f 00 67 00 63 00
                          61 00 74 00 64 00 }  // com.android.logcatd
        $pkg_androidsvc = { 63 00 6f 00 6d 00 2e 00 61 00 2e 00 61 00 6e 00
                            64 00 72 00 6f 00 69 00 64 00 73 00 76 00 63 00 }  // com.a.androidsvc
        $pkg_netservice = { 63 00 6f 00 6d 00 2e 00 65 00 78 00 61 00 6d 00
                            70 00 6c 00 65 00 2e 00 6e 00 65 00 74 00 77 00
                            6f 00 72 00 6b 00 73 00 65 00 72 00 76 00 69 00
                            63 00 65 00 }  // com.example.networkservice
        $pkg_n2       = { 63 00 6f 00 6d 00 2e 00 6e 00 32 00 2e 00 73 00
                          79 00 73 00 74 00 65 00 6d 00 73 00 65 00 72 00
                          76 00 69 00 63 00 65 00 30 00 36 00 }  // com.n2.systemservice06
        $pkg_proxypeer = { 63 00 6f 00 6d 00 2e 00 70 00 72 00 6f 00 78 00
                           79 00 70 00 65 00 65 00 72 00 2e 00 70 00 65 00
                           65 00 72 00 61 00 70 00 70 00 }  // com.proxypeer.peerapp

        // AbcProxy SDK build path leaked in some native libs
        $path_sylvia = "SylviaFennec/AbcProxySDK"

        // ByteConnect companion C2 (in STORE'd libbcsdk.so)
        $byteconnect = "byteconnect.io"

    condition:
        uint32(0) == 0x04034b50 and  // ZIP/APK magic
        $classes_dex and $manifest and  // confirm this is an APK
        (
            // High confidence: Kimwolf native runtime pair (Tor+DDoS variant)
            ($lib_android_rt and $lib_dalvik_rt) or

            // High confidence: known Kimwolf package name + native payload
            (1 of ($pkg_*) and 1 of ($lib_*)) or

            // High confidence: dual payload (proxy bot + ByteConnect SDK)
            ($lib_device and $lib_bcsdk) or

            // High confidence: modified-UPX emulator lib (AbcProxy dropper)
            $lib_device_emu or

            // High confidence: AbcProxy build path in embedded native lib
            $path_sylvia or

            // High confidence: ELF payloads in assets directory
            $asset_task or

            // Medium confidence: stub loader pair (libdevice + libdevice1)
            ($lib_device and $lib_device1) or

            // Medium confidence: libdevice.so + ByteConnect C2
            ($lib_device and $byteconnect) or

            // Medium confidence: known Kimwolf package name alone
            (2 of ($pkg_*))
        )
}
