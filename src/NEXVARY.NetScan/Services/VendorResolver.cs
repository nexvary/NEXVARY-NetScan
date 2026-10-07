using System.Globalization;

namespace NEXVARY.NetScan.Services;

public static class VendorResolver
{
    private static readonly IReadOnlyDictionary<string, string> Vendors =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // MikroTik / RouterBOARD
            ["000C42"] = "MikroTik",
            ["4C5E0C"] = "MikroTik",
            ["E48D8C"] = "MikroTik",
            ["64D154"] = "MikroTik",

            // TP-Link
            ["503EAA"] = "TP-Link",
            ["6CB158"] = "TP-Link",
            ["78605B"] = "TP-Link",
            ["B09575"] = "TP-Link",
            ["403F8C"] = "TP-Link",
            ["480EEC"] = "TP-Link",
            ["EC6073"] = "TP-Link",
            ["7CB59B"] = "TP-Link",
            ["6032B1"] = "TP-Link",

            // Huawei
            ["E00630"] = "Huawei",
            ["001882"] = "Huawei",
            ["001E10"] = "Huawei",
            ["002568"] = "Huawei",
            ["00259E"] = "Huawei",
            ["002EC7"] = "Huawei",
            ["0034FE"] = "Huawei",
            ["00464B"] = "Huawei",
            ["004F1A"] = "Huawei",
            ["005A13"] = "Huawei",
            ["006151"] = "Huawei",
            ["00664B"] = "Huawei",
            ["006B6F"] = "Huawei",
            ["00991D"] = "Huawei",
            ["009ACD"] = "Huawei",
            ["00A91D"] = "Huawei",
            ["00BE3B"] = "Huawei",
            ["00CC05"] = "Huawei",
            ["00E0FC"] = "Huawei",
            ["28353A"] = "Huawei",
            ["089E84"] = "Huawei",
            ["5C7D5E"] = "Huawei",
            ["D82918"] = "Huawei",
            ["542F2B"] = "Huawei",

            // Apple
            ["000393"] = "Apple",
            ["709684"] = "Apple",
            ["68A729"] = "Apple",
            ["A0782D"] = "Apple",
            ["28022E"] = "Apple",

            // Samsung
            ["0000F0"] = "Samsung",
            ["641B2F"] = "Samsung",

            // Xiaomi
            ["3C7F6E"] = "Xiaomi",
            ["3007EB"] = "Xiaomi",
            ["1CCCD6"] = "Xiaomi",

            // OPPO
            ["00CAE0"] = "OPPO",
            ["042405"] = "OPPO",
            ["04DBD9"] = "OPPO",
            ["084ACF"] = "OPPO",
            ["08DD03"] = "OPPO",
            ["0C938F"] = "OPPO",
            ["0CBD75"] = "OPPO",
            ["1016B1"] = "OPPO",
            ["1071FA"] = "OPPO",
            ["587A6A"] = "OPPO",

            // Surveillance
            ["74C929"] = "Dahua",
            ["30DDAA"] = "Dahua",
            ["00BC99"] = "Hikvision",
            ["040312"] = "Hikvision",
            ["04EECD"] = "Hikvision",
            ["083BC1"] = "Hikvision",
            ["085411"] = "Hikvision",
            ["08A189"] = "Hikvision",
            ["08CC81"] = "Hikvision",
            ["0C75D2"] = "Hikvision",
            ["1012FB"] = "Hikvision",
            ["1868CB"] = "Hikvision",
            ["188025"] = "Hikvision",
            ["240F9B"] = "Hikvision",
            ["2428FD"] = "Hikvision",
            ["2CA59C"] = "Hikvision",
            ["98DF82"] = "Hikvision",
            ["98F112"] = "Hikvision"
        };

    private static readonly IReadOnlyDictionary<string, string> Registry = LoadRegistry();

    private static IReadOnlyDictionary<string, string> LoadRegistry()
    {
        using var stream = typeof(VendorResolver).Assembly.GetManifestResourceStream("NEXVARY.NetScan.Assets.vendors.tsv")
            ?? throw new InvalidOperationException("Missing IEEE vendor registry.");
        using var reader = new System.IO.StreamReader(stream);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.ReadLine() is { } line)
        {
            var parts = line.Split('\t', 2);
            if (parts.Length == 2) values[parts[0]] = parts[1];
        }
        return values;
    }

    public static string Resolve(string? macAddress)
    {
        if (!TryNormalize(macAddress, out string normalized))
            return "غير معروف";

        if (IsLocallyAdministered(normalized))
            return "MAC خاص/عشوائي";

        string oui = normalized[..6];
        if (!Registry.TryGetValue(oui, out var registered)) return "غير معروف";
        if (Vendors.TryGetValue(oui, out var alias) && registered.Contains(alias.Replace("-", ""), StringComparison.OrdinalIgnoreCase)) return alias;
        if (registered.Equals("Routerboard.com", StringComparison.OrdinalIgnoreCase)) return "MikroTik";
        string compact = registered.Replace("-", "").Replace(" ", "");
        foreach (var brand in new[] { "MikroTik", "TP-Link", "Huawei", "ZTE", "Cisco", "Ubiquiti", "Tenda", "D-Link", "Mercusys", "Xiaomi", "OPPO", "realme", "Samsung", "Apple", "Honor", "Hikvision", "Dahua", "Uniview", "Imou", "Ezviz", "Tuya", "Intel", "Dell", "Lenovo", "ASUS", "Acer", "Epson", "Canon", "Brother" })
            if (compact.Contains(brand.Replace("-", ""), StringComparison.OrdinalIgnoreCase)) return brand;
        if (registered.Contains("Hewlett", StringComparison.OrdinalIgnoreCase)) return "HP";
        return registered;
    }

    public static bool IsLocallyAdministered(string? macAddress)
    {
        if (!TryNormalize(macAddress, out string normalized))
            return false;

        byte firstByte = byte.Parse(normalized[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return (firstByte & 0x02) != 0;
    }

    private static bool TryNormalize(string? macAddress, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(macAddress))
            return false;

        normalized = new string(macAddress.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        return NetworkScanner.NormalizeMac(macAddress) is not null;
    }
}
