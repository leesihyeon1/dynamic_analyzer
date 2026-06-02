/*
    Aisuru DDoS botnet -- main detection rule (a.k.a. Airashi)
    Mirai-derived botnet with custom crypto, SOCKS5 proxy, and extended
    DDoS attack set (stomp, raknet, VSE, TFO, GRE, wra). Uses DNS TXT
    records XOR'd with CAFEBABE for C2 resolution.

    The table XOR key PJbiNbbeasddDfsc is shared with Jackskid/RCtea
    (same actor, different codebase). This rule distinguishes Aisuru by
    requiring the key alongside Aisuru-specific indicators and excluding
    Jackskid-unique markers (FrshPckBnnnSplit, RC4 key).

    References:
      - XLab QAX "Aisuru Botnet" (Oct 2024)
      - XLab QAX "Airashi DDoS Botnet" (Jan 2025)
      - Nokia Deepfield ERT analysis (2025-2026)

    Samples:
      - 39682d9b4ef8d9730e6c090a161d28d34cb47d9e4548344119a731f34d3867e0 (x86, Aug 2024, earliest gen1)
      - 3fe583fb7fa6646b25765553eb9495275daa2a17bf393e816dd33009e366f48a (ARM, unstripped)
      - 75a1199fbf8abd52bc957b07ff7574ddc98719272ad9f2f0d427178ac1c60967 (ARM, SOCKS5)
      - ab67a6ae19b9d0fc79840894a257a2ece9110e13a027b7c19c8b3a99b88cdc49 (ARM)
      - d07e4ff966f0852a0d7832b55c20ac47bbe9c6bd2fabf0253695a3cd231363cf (ARM)
      - 02356742d3564b258677fe18441eb71defc05ec029a53e31a1f2ce6a3d7acedb (MIPS)
      - 90e3b997161e33c6485b48182073a864dd3d0775ab96cadbf1b7c9dd4821c6d1 (AArch64, stripped)
      - 50d3806f47d3f701d5f1f93bf39f827f936e3d1f43fa2cd8408db9655d53fb83 (ARM, stripped)
      - 7500925a26cecd84ebed2914855cdf0812a18661e1bb6f3c91dede36f34bd7f3 (ARM, Mar 2026, latest gen2)
*/

rule aisuru_ddos_botnet
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Aisuru DDoS botnet - Mirai derivative with custom crypto"
        date = "2026-03-09"
        reference = "https://blog.xlab.qianxin.com/aisuru-botnet-en/"
        family = "aisuru"
        aka = "airashi"
        severity = "high"
        yarahub_uuid = "d5bef5fd-e68e-4d67-ab79-7c198615229c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "279c1addab1dfaf8a1d7dc9fe3875b81"

    strings:
        // Aisuru crypto key: DEADBEEF CAFEBABE 12345678 90ABCDEF (gen1)
        // Distinct from Jackskid's key (same first 8 bytes, different last 8)
        $crypto_key = { de ad be ef ca fe ba be 12 34 56 78 90 ab cd ef }

        // Aisuru XOR key variant: 12345678 90ABCDEF FEDCBA98 76543210 (earliest gen1)
        $xor_key_early = { 12 34 56 78 90 ab cd ef fe dc ba 98 76 54 32 10 }

        // C2 protocol magic bytes (little-endian)
        $magic_deadbeef_1337 = { ef be ad de 37 13 20 04 }  // C2 handshake magic (gen1 earliest)
        $magic_1ceb = { da 00 eb 1c }                       // C2 protocol magic (gen2 latest, replaces CAFEBABE)
        $magic_1ceb_verify = { a4 88 eb 1c }                // C2 verification XOR (gen2 latest)

        // Shared table XOR key (used as toggle_obf key in Aisuru,
        // auth XOR key in Jackskid -- not unique alone)
        $table_key = "PJbiNbbeasddDfsc"

        // Jackskid-only markers (used for exclusion)
        $jackskid_frsh = "FrshPckBnnnSplit"
        $jackskid_botd = "botd_single_lock"

        // Connectivity check domain (unique to this actor)
        $conn_check = "motherfuckingwebsite.com"

        // ChaCha20 constant (used for C2 transport encryption)
        $chacha20 = "expand 32-byte k"
        // Scrambled ChaCha20 constant variant 1 (Mirai table obfuscation)
        $chacha20_scrambled = "nd 3expa2-byte k"
        // Scrambled ChaCha20 constant variant 2 (stripped builds, "2-by"
        // removed; found in 90f05f64, q8.so from 5d20d294)
        $chacha20_truncated = "expand 3te k"

        // CAFEBABE XOR for DNS TXT C2 resolution (all gens)
        $cafebabe_le = { be ba fe ca }

        // SSH version banner set used for scanner evasion
        $ssh_motty = "SSH-2.0-MoTTY_Release_0.77"
        $ssh_tectia = "SSH-2.0-Tectia_6.4.13"
        $ssh_libssh = "SSH-2.0-libssh-0.8.0"
        $ssh_putty = "SSH-2.0-PuTTY_Release_0.78"
        $ssh_win81 = "SSH-2.0-OpenSSH_for_Windows_8.1"

        // Valve Source Engine query payload (attack template)
        $vse_query = "TSource Engine Query"

        // Extended DDoS attack modules (beyond standard Mirai)
        $atk_wra = "attacks_wra"
        $atk_stomp = "attacks_stomp"
        $atk_raknet = "attacks_raknet"
        $atk_tfo = "attacks_tfo"
        $atk_vse = "attacks_vse"
        $atk_gre = "attacks_gre"
        $atk_ack = "attacks_ack"
        $atk_std = "attacks_std"
        $atk_socket = "attacks_socket"

        // Aisuru-specific function names (not in vanilla Mirai)
        $fn_toggle_obf = "toggle_obf"
        $fn_select_profile = "select_profile"
        $fn_send_heartbeat = "send_heartbeat"
        $fn_single_instance = "single_instance"
        $fn_esi_fd = "esi_fd"

        // Locker persistence module (unique to Aisuru)
        $locker_init = "locker_init"
        $locker_find = "locker_find"
        $locker_insert = "locker_insert"
        $locker_pid = "locker_pid"

        // Anti-analysis / researcher taunt User-Agent
        $ua_gcore = "GCore Labs Cyberthreat Research"

        // DNS TXT C2 domain patterns (unique to this actor)
        $dns_dvrexpert = "dvrexpert"
        $dns_tiananmen = "tiananmensquare1989"
        $dns_krebstresser = "krebstresser"
        $dns_idsource = "idsource"

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        // Jackskid exclusion: only exclude if Jackskid markers are present
        // WITHOUT Aisuru-specific indicators. Latest gen2 builds (7500925a)
        // contain both Aisuru and Jackskid code (codebase convergence),
        // so we allow through if Aisuru-unique markers are also present.
        not ($jackskid_frsh and not $magic_1ceb and not $cafebabe_le) and
        not ($jackskid_botd and not $magic_1ceb and not $cafebabe_le and not $table_key) and
        (
            // High confidence: crypto key unique to this family
            $crypto_key or
            $xor_key_early or

            // High confidence: gen2 C2 protocol magic (1CEB00DA)
            ($magic_1ceb and $magic_1ceb_verify) or

            // High confidence: gen1 earliest handshake magic
            ($magic_deadbeef_1337 and ($table_key or $conn_check)) or

            // High confidence: connectivity check + attack modules
            ($conn_check and 3 of ($atk_*)) or

            // High confidence: SSH banner set + VSE query
            (3 of ($ssh_*) and $vse_query and $conn_check) or

            // High confidence: locker module + Aisuru functions
            (2 of ($locker_*) and 2 of ($fn_*)) or

            // High confidence: table key + ChaCha20 (stripped Aisuru variants)
            // PJbiNbbeasddDfsc used as Mirai table_key with ChaCha20 transport
            ($table_key and ($chacha20 or $chacha20_scrambled or $chacha20_truncated)) or

            // High confidence: table key + CAFEBABE DNS TXT XOR
            ($table_key and $cafebabe_le) or

            // High confidence: table key + any DNS C2 domain
            ($table_key and 1 of ($dns_*)) or

            // Medium confidence: attack module cluster (5+ attack types)
            (5 of ($atk_*) and 2 of ($fn_*)) or

            // Medium confidence: GCore Labs UA + attack indicators
            ($ua_gcore and 2 of ($atk_*)) or

            // Medium confidence: SSH banners + Aisuru functions + heartbeat
            (3 of ($ssh_*) and $fn_send_heartbeat and $fn_toggle_obf)
        )
}
