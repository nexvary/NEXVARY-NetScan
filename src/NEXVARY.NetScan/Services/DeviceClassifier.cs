namespace NEXVARY.NetScan.Services;

public sealed record DevicePresentation(string DeviceType, string IconKind);

public static class DeviceClassifier
{
    public static DevicePresentation Classify(string hostName, string vendor, bool isGateway, bool isLocalComputer)
    {
        string text = $"{hostName} {vendor}".ToLowerInvariant();

        if (isGateway)
            return new("راوتر / بوابة", "Router");

        if (isLocalComputer)
            return new("هذا الكمبيوتر", "Computer");

        if (ContainsAny(text, "hikvision", "dahua", "camera", "cam-", "ipc", "nvr", "dvr"))
            return new("كاميرا / مراقبة", "Camera");

        if (ContainsAny(text, "printer", "epson", "canon", "brother", "laserjet", "deskjet"))
            return new("طابعة", "Printer");

        if (ContainsAny(text, "iphone", "ipad", "android", "oppo", "realme", "xiaomi", "redmi", "samsung", "galaxy", "phone"))
            return new("هاتف / جهاز محمول", "Phone");

        if (ContainsAny(text, "tv", "chromecast", "roku", "bravia", "webos", "tizen"))
            return new("تلفاز / وسائط", "Tv");

        if (ContainsAny(text, "tuya", "smart", "esp32", "esp8266", "tasmota", "shelly", "iot"))
            return new("منزل ذكي / IoT", "IoT");

        if (ContainsAny(text, "mikrotik", "tp-link", "huawei", "ubiquiti", "router", "switch", "access point", "ap-"))
            return new("معدات شبكة", "Network");

        return new("جهاز شبكة", "Generic");
    }

    private static bool ContainsAny(string text, params string[] tokens) =>
        tokens.Any(text.Contains);
}
