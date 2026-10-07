using NEXVARY.NetScan.Services;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class DeviceClassifierTests
{
    [Fact]
    public void Gateway_IsAlwaysRouter()
    {
        var result = DeviceClassifier.Classify("anything", "anything", true, false);
        Assert.Equal("راوتر / بوابة", result.DeviceType);
        Assert.Equal("Router", result.IconKind);
    }

    [Fact]
    public void Dahua_IsClassifiedAsCamera()
    {
        var result = DeviceClassifier.Classify("ipc-front", "Dahua", false, false);
        Assert.Equal("كاميرا / مراقبة", result.DeviceType);
    }

    [Fact]
    public void Xiaomi_IsClassifiedAsMobileDevice()
    {
        var result = DeviceClassifier.Classify("android-123", "Xiaomi", false, false);
        Assert.Equal("هاتف / جهاز محمول", result.DeviceType);
    }
}
