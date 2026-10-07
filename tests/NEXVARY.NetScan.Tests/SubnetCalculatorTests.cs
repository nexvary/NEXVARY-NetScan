using System.Net;
using NEXVARY.NetScan.Services;

namespace NEXVARY.NetScan.Tests;

public sealed class SubnetCalculatorTests
{
    [Fact]
    public void GetHostAddresses_ReturnsUsableHosts_ForSlash24()
    {
        var hosts = SubnetCalculator.GetHostAddresses(
            IPAddress.Parse("192.168.1.55"),
            IPAddress.Parse("255.255.255.0"));

        Assert.Equal(254, hosts.Count);
        Assert.Equal("192.168.1.1", hosts[0].ToString());
        Assert.Equal("192.168.1.254", hosts[^1].ToString());
    }

    [Fact]
    public void Describe_ReturnsNetworkAndPrefix()
    {
        var label = SubnetCalculator.Describe(
            IPAddress.Parse("192.168.10.77"),
            IPAddress.Parse("255.255.255.0"));

        Assert.Equal("192.168.10.0/24", label);
    }

    [Fact]
    public void LargeSubnet_IsSafetyCappedToLocalSlash24()
    {
        var hosts = SubnetCalculator.GetHostAddresses(
            IPAddress.Parse("10.22.33.44"),
            IPAddress.Parse("255.0.0.0"));

        Assert.Equal(254, hosts.Count);
        Assert.Equal("10.22.33.1", hosts[0].ToString());
    }
}
