rule hasNSLocalNetworkUsageDescription {
    meta:
        description = "Detects permissions in AndroidManifest"
    strings:
        $x4 = "NSLocalNetworkUsageDescription" ascii
    condition:
        (filename == "Info.plist" or filename == "InfoPlist.strings") and 1 of them
}



rule hasNSBonjourServices {
    meta:
        description = "Detects NSBonjourServices in AndroidManifest"
    strings:
        $x4 = "NSBonjourServices" ascii
    condition:
        (filename == "Info.plist" or filename == "InfoPlist.strings") and 1 of them
}
