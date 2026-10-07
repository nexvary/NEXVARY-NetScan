namespace NEXVARY.NetScan.Services;

public sealed record DevicePresentation(string DeviceType, string IconGlyph, string IconBackground);

public static class DeviceClassifier
{
    public static DevicePresentation Classify(string hostName, string vendor, bool isGateway, bool isLocalComputer)
    {
        string text = $"{hostName} {vendor}".ToLowerInvariant();

        if (isGateway)
            return new("راوتر / بوابة", "🌐", "#173A46");

        if (isLocalComputer)
            return new("هذا الكمبيوتر", "💻", "#263B58");

        if (ContainsAny(text, "hikvision", "dahua", "camera", "cam-", "ipc", "nvr", "dvr"))
            return new("كاميرا / مراقبة", "📷", "#3D2E52");

        if (ContainsAny(text, "printer", "epson", "canon", "brother", "laserjet", "deskjet"))
            return new("طابعة", "🖨️", "#4A3B22");

        if (ContainsAny(text, "iphone", "ipad", "android", "oppo", "realme", "xiaomi", "redmi", "samsung", "galaxy", "phone"))
            return new("هاتف / جهاز محمول", "📱", "#1F4550");

        if (ContainsAny(text, "tv", "chromecast", "roku", "bravia", "webos", "tizen"))
            return new("تلفاز / وسائط", "📺", "#3F3655");

        if (ContainsAny(text, "tuya", "smart", "esp32", "esp8266", "tasmota", "shelly", "iot"))
            return new("منزل ذكي / IoT", "💡", "#4B4321");

        if (ContainsAny(text, "mikrotik", "tp-link", "huawei", "ubiquiti", "router", "switch", "access point", "ap-"))
            return new("معدات شبكة", "📡", "#23423D");

        return new("جهاز شبكة", "◆", "#273641");
    }

    private static bool ContainsAny(string text, params string[] tokens) =>
        tokens.Any(text.Contains);
}
