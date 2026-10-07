using NEXVARY.NetScan.Services;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class VendorResolverTests
{
    [Theory]
    [InlineData("4C:5E:0C:11:22:33", "MikroTik")]
    [InlineData("50:3E:AA:11:22:33", "TP-Link")]
    [InlineData("64:1B:2F:11:22:33", "Samsung")]
    [InlineData("74:C9:29:11:22:33", "Dahua")]
    [InlineData("58:7A:6A:11:22:33", "OPPO")]
    [InlineData("98:DF:82:11:22:33", "Hikvision")]
    public void Resolve_ReturnsKnownVendor(string mac, string expected)
    {
        Assert.Equal(expected, VendorResolver.Resolve(mac));
    }

    [Fact]
    public void Resolve_DetectsLocallyAdministeredAddress()
    {
        Assert.Equal("MAC خاص/عشوائي", VendorResolver.Resolve("02:11:22:33:44:55"));
    }

    [Fact]
    public void Resolve_ReturnsUnknownForUnsupportedOui()
    {
        Assert.Equal("غير معروف", VendorResolver.Resolve("FC:FF:FF:33:44:55"));
    }
}
