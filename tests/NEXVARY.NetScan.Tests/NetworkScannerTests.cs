using System.Net;
using NEXVARY.NetScan.Services;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class NetworkScannerTests
{
    [Theory]
    [InlineData("192.168.1.20", "192.168.1.55", "255.255.255.0", true)]
    [InlineData("192.168.2.20", "192.168.1.55", "255.255.255.0", false)]
    [InlineData("10.10.4.30", "10.10.5.22", "255.255.254.0", true)]
    [InlineData("10.10.6.30", "10.10.5.22", "255.255.254.0", false)]
    public void IsSameSubnet_UsesActualMask(string address, string local, string mask, bool expected)
    {
        Assert.Equal(
            expected,
            NetworkScanner.IsSameSubnet(
                IPAddress.Parse(address),
                IPAddress.Parse(local),
                IPAddress.Parse(mask)));
    }

    [Fact]
    public void IsUsableHostAddress_RejectsNetworkAndBroadcast()
    {
        var local = IPAddress.Parse("192.168.1.107");
        var mask = IPAddress.Parse("255.255.255.0");

        Assert.False(NetworkScanner.IsUsableHostAddress(IPAddress.Parse("192.168.1.0"), local, mask));
        Assert.False(NetworkScanner.IsUsableHostAddress(IPAddress.Parse("192.168.1.255"), local, mask));
        Assert.True(NetworkScanner.IsUsableHostAddress(IPAddress.Parse("192.168.1.1"), local, mask));
        Assert.True(NetworkScanner.IsUsableHostAddress(IPAddress.Parse("192.168.1.102"), local, mask));
    }

    [Fact]
    public void FormatDnsServers_ShowsOnlyIpv4AndRemovesDuplicates()
    {
        var value = NetworkScanner.FormatDnsServers(new[]
        {
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("2001:4860:4860::8888")
        });

        Assert.Equal("192.168.1.1 / 8.8.8.8", value);
    }

    [Fact]
    public void FormatDnsServers_ReturnsArabicFallbackWhenEmpty()
    {
        Assert.Equal("غير متاح", NetworkScanner.FormatDnsServers(Array.Empty<IPAddress>()));
    }
    [Theory]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("FF:FF:FF:FF:FF:FF")]
    [InlineData("01:00:5E:00:00:01")]
    [InlineData("4C:5E:0C:11:22:33:44")]
    [InlineData("invalid")]
    public void InvalidOrMulticastMacIsRejected(string mac) => Assert.Null(NetworkScanner.NormalizeMac(mac));

    [Fact]
    public void PrivateMacRemainsValid() => Assert.Equal("02:11:22:33:44:55", NetworkScanner.NormalizeMac("02-11-22-33-44-55"));

    [Fact]
    public void MulticastIpRejected() => Assert.False(NetworkScanner.IsUsableHostAddress(IPAddress.Parse("224.0.0.1"), IPAddress.Parse("192.168.1.1"), IPAddress.Parse("0.0.0.0")));
}
