/*
    Kimwolf residential proxy botnet -- C/C++ variants (Gen 1-3)
    Covers WolfSSL (Gen 1), BoringSSL (Gen 2), and AbcProxy SDK (Gen 3) builds.
    All use ENS blockchain C2 resolution, SOCKS proxy, and libcurl.

    Samples:
      - 72142e7a704e2b5f7da279af349c5490eaa8b5cac83015e7115b10796f1af641 (Gen 1, WolfSSL, Dec 2025)
      - 5b2475d4915c5aecbeb66f52fb4e5b5c342144830cc32cc039a6573b5b6cb2ff (Gen 2, BoringSSL, Jan 2026)
      - 99443ec987417f05f52cf6e0e4f3d51021b37e24c857ad9ae70b08c060c4d139 (Gen 3, AbcProxy, Feb 2026)
*/

rule kimwolf_proxy
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "Kimwolf residential proxy botnet - C/C++ variants with ENS C2 (Gen 1-3)"
        date = "2026-03-09"
        family = "kimwolf"
        severity = "high"
        yarahub_uuid = "7592efd1-8805-4ca1-8e2f-f01da1a30d01"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "036bcb62be72c4663b9564955f93b05f"

    strings:
        // Ethereum RPC endpoints for ENS C2 resolution
        $rpc_0xrpc = "0xrpc.io/eth"
        $rpc_llama = "eth.llamarpc.com"
        $rpc_publicnode = "ethereum-rpc.publicnode.com"
        $rpc_blxrbdn = "eth-protect.rpc.blxrbdn.com"
        $rpc_merkle = "eth.merkle.io"
        $rpc_payload = "rpc.payload.de"
        $rpc_flashbots = "rpc.flashbots.net"

        // ENS smart contract selectors
        $ens_resolver = { 01 78 b8 bf }
        $ens_text = { 59 d1 d4 3c }

        // Ethereum JSON-RPC method
        $eth_call = "eth_call"

        // Process masquerade name
        $netd_service = "netd_service"

        // STUN NAT traversal
        $stun = "stun.cloudflare.com"

        // C++ RTTI class names
        $rtti_proxy = "ProxySession"
        $rtti_ddos = "NiggerTransferProtocolSession"

        // Proxy functionality
        $socks5 = "SOCKS5: connecting to HTTP proxy"
        $cpool = "[CPOOL]"

        // Build path artifacts
        $path_sylvia = "/home/SylviaFennec/AbcProxySDK/"
        $path_proxy_client = "/home/user/proxy-client/"

    condition:
        uint32(0) == 0x464c457f and
        // ENS evidence required: 3+ Ethereum RPC endpoints or ENS selectors
        (3 of ($rpc_*) or $ens_resolver or $ens_text or $eth_call) and
        (
            // High confidence: ENS selectors + RPC endpoints
            (($ens_resolver or $ens_text) and 3 of ($rpc_*)) or

            // High confidence: build path + proxy indicators
            (($path_sylvia or $path_proxy_client) and ($socks5 or $cpool)) or

            // High confidence: RTTI unique to this family + ENS
            (($rtti_ddos or $rtti_proxy) and $eth_call) or

            // Medium confidence: proxy + infrastructure combo
            ($socks5 and $netd_service and $stun and $eth_call) or

            // Medium confidence: RPC endpoints + proxy + process masquerade
            (3 of ($rpc_*) and $netd_service and ($socks5 or $cpool))
        )
}
