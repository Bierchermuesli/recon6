rule Detect_IPv6_All_Text_Forms
{
    meta:
        description = "Generic IPv6 catcher"
        author = "Bierchermuesli"
        date = "2025-12-02"
        yarahub_reference_md5 = "0f5ab6b575e76b8e4f33f65723ca1802"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid="7e8c95e7-24b2-41fc-91f5-cf355f0d9bcb"

    strings:
        //
        // Full, uncompressed IPv6:
        // Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        //
        $full = /([A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}/

        //
        // Compressed forms:
        // Example: 2001:db8::1, ::1, fe80::, ::ffff:192.0.2.1
        //
        $compressed = /(([A-Fa-f0-9]{1,4}:){1,7}:|:([A-Fa-f0-9]{1,4}:){1,7}|::)/

        //
        // IPv6 with embedded IPv4:
        // Example: ::ffff:192.168.1.1
        //
        $mixed = /([A-Fa-f0-9]{1,4}:){6}\d{1,3}(\.\d{1,3}){3}/

    condition:
        any of ($full, $compressed, $mixed)
}
