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
}
