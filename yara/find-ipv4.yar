rule Catch_Hardcoded_IPv4_Strict
{
    meta:
        description = "Generic IPv4 catcher"
        author = "Bierchermuesli"
        date = "2025-12-02"
        yarahub_reference_md5 = "0f5ab6b575e76b8e4f33f65723ca1802"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid="7e8c95e7-24b2-41fc-91f5-cf355f0d9bcb"


    strings:
        // Matches valid IPv4: 0–255 per octet
        $ipv4 = /((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}
                 (25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])/ ascii

    condition:
        $ipv4
}
