/*
    Cecilio botnet -- CatDDoS derivative with modified RC4 table encryption
    CatDDoS variant ("Cecilio Network") derived from leaked CatDDoS source.
    Self-identifies as "the cecilio botnet" in encrypted table.
    Uses OpenNIC TLDs (.dyn, .oss, .geek) alongside .su domains for C2.
    Modified RC4 cipher with j-carryover from KSA to PRGA.
    Shares credential set with Jackskid (Pon521, Zte521, root621, Zxic521,
    wabjtam, tsgoingon). Operated by the Aisuru/Jackskid actor.
    References:
      - XLab QAX "CatDDoS-Related Gangs" (May 2024)
      - QianXin TIC "New Botnet CatDDoS Continues to Evolve"

    Samples:
      - 04315269969dd37353592ca248a8801d339355cd0ded5a2b99130c683d6056f7 (ARM, May 2025, kamru.su)
      - 00def227563541e149047cdbbf610401cbce51c60cec8d3b4c1d1ef77d6869c2 (ARM, Feb 2026, oceanic-node.su)
      - 08b2b3e74a0a2b11ddf2bd51ebb460f4e91dca14ad6c53f1ca3ceb71509c855c (ARM, Feb 2026)
      - 12144c665553ebe004a5f21d684c82ccfa16b2212387a1bdb61557c36cb6d6d5 (MIPS, Feb 2026)
*/

rule cecilio_botnet
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Cecilio botnet - CatDDoS derivative with modified RC4 table encryption"
        reference = "https://blog.xlab.qianxin.com/catddos-derivative-en/"
        date = "2026-03-09"
        family = "cecilio"
        severity = "high"
        yarahub_uuid = "28c1ad64-c553-4358-9d89-84472251d3b6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a6758a2eac67b6e2fbe4c3ee4f3e4b7c"

    strings:
        // Modified RC4 key (256 bytes, identical across builds)
        // First 16 bytes are sufficient for high-confidence match
        $rc4_key = { c9 ba 3e 11 4f 2a 7d e0 e6 8d bb eb 9a 87 87 7e }

        // C2 registration magic (8 bytes, sent on connect before hostname)
        // Unique to Cecilio, not present in Jackskid or other CatDDoS forks
        $reg_magic = { 56 63 34 86 90 69 21 01 }

        // Brute-force credential set (shared with Jackskid, not unique)
        $cred_pon = "Pon521"
        $cred_zte = "Zte521"
        $cred_root621 = "root621"
        $cred_zxic = "Zxic521"
        $cred_wabjtam = "wabjtam"
        $cred_tsgoingon = "tsgoingon"

        // Busybox FASTCAT variant
        $fastcat = "/bin/busybox FASTCAT"

        // SNQUERY DVR scanner probe
        $snquery = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"

        // Valve Source Engine query
        $vse = "TSource Engine Query"

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        (
            // High confidence: RC4 key unique to this family
            $rc4_key or

            // High confidence: registration magic unique to this family
            $reg_magic or

            // Medium confidence: FASTCAT + credentials + registration magic
            // (credentials alone overlap with Jackskid, require reg_magic)
            ($reg_magic and $fastcat and 3 of ($cred_*)) or

            // Medium confidence: credentials + scanner + attack payload + registration
            ($reg_magic and 3 of ($cred_*) and ($vse or $snquery))
        )
}
