/*
    Kimwolf residential proxy botnet -- ADB install script
    Detects the shell scripts used to sideload Kimwolf APKs onto
    Android devices with open ADB (tcp/5555) or local shell access.

    These scripts disable Android install verification, download the
    APK via netcat, install it with pm, start the service, then clean
    up. Observed dropper IPs: 89.39.70.40, 95.133.240.218,
    89.125.255.206, 130.12.180.126.

    Samples:
      - 3a7b5a13 install script (Feb 2026, from 89.39.70.40)
      - Dropper at 172.232.50.12:/root/2026-01-11/dropper
      - 68ea5dc4 installer (from 95.133.240.218:1001)
*/

rule kimwolf_dropper_script
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - ADB sideload install script"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "8e8a791e-6de9-4983-85ce-3d2a97fa63b8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "09587b0c67d0c9e7211c8b2edb6037ba"

    strings:
        // Shell indicators (shebang or common shell commands)
        $shell1 = "#!/bin/sh"
        $shell2 = "#!/bin/bash"
        $shell3 = "#!/system/bin/sh"

        // ADB verification bypass (disables install verification)
        $adb_bypass = "verifier_verify_adb_installs"

        // Package manager install command
        $pm_install = "pm install"

        // Activity manager service start
        $am_start = "am startservice"
        $am_start2 = "am start-foreground-service"

        // Download via busybox/toybox netcat (no curl/wget on stock Android)
        $dl_toybox = "toybox nc"
        $dl_busybox = "busybox nc"

        // Kimwolf APK package names used in install scripts
        $pkg_androidsvc = "com.a.androidsvc"
        $pkg_logcatd = "com.android.logcatd"
        $pkg_networkservice = "com.example.networkservice"
        $pkg_proxypeer = "com.proxypeer.peerapp"
        $pkg_abcproxy = "com.abcproxy.proxysdk"
        $pkg_n2 = "com.n2.systemservice06"

        // Service components launched after install
        $svc_sdk = "SDKService"

        // Battery optimization bypass (keeps service alive)
        $doze_bypass = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
        $doze_bypass2 = "dumpsys deviceidle whitelist"

        // Dropper IPs observed across campaigns
        $ip_dropper1 = "89.39.70.40"
        $ip_dropper2 = "95.133.240.218"
        $ip_dropper3 = "89.125.255.206"
        $ip_dropper4 = "130.12.180.126"

    condition:
        filesize < 10KB and
        not uint32(0) == 0x464c457f and  // not ELF
        not uint32(0) == 0x04034b50 and  // not ZIP/APK
        1 of ($shell*) and  // must be a shell script
        (
            // High confidence: ADB bypass + package install + known package
            ($adb_bypass and $pm_install and 1 of ($pkg_*)) or

            // High confidence: netcat download + package install + service start
            (1 of ($dl_*) and $pm_install and ($am_start or $am_start2) and $svc_sdk) or

            // High confidence: known dropper IP + package install + known package
            (1 of ($ip_dropper*) and $pm_install and 1 of ($pkg_*)) or

            // Medium confidence: ADB bypass + netcat download + service start
            ($adb_bypass and 1 of ($dl_*) and ($am_start or $am_start2)) or

            // Medium confidence: known package + doze bypass + service
            (1 of ($pkg_*) and ($doze_bypass or $doze_bypass2) and $svc_sdk)
        )
}
