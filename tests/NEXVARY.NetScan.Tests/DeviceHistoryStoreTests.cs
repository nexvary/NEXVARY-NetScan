using System.Net;
using NEXVARY.NetScan.Models;
using NEXVARY.NetScan.Services;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class DeviceHistoryStoreTests
{
    [Fact]
    public void Merge_PreservesFirstSeenAndMarksMissingDeviceOffline()
    {
        string path = Path.Combine(Path.GetTempPath(), $"netscan-history-{Guid.NewGuid():N}.json");
        try
        {
            var store = new DeviceHistoryStore(path);
            var first = new DateTimeOffset(2026, 10, 7, 8, 0, 0, TimeSpan.Zero);
            var second = first.AddMinutes(10);

            var router = Device("192.168.1.1", "4C:5E:0C:11:22:33", "MikroTik");
            var phone = Device("192.168.1.20", "64:1B:2F:11:22:33", "Samsung");

            store.Merge(new[] { router, phone }, first);
            var merged = store.Merge(new[] { router }, second);

            var savedRouter = Assert.Single(merged.Where(x => x.MacAddress == router.MacAddress));
            var savedPhone = Assert.Single(merged.Where(x => x.MacAddress == phone.MacAddress));

            Assert.Equal(first, savedRouter.FirstSeenUtc);
            Assert.Equal(second, savedRouter.LastSeenUtc);
            Assert.True(savedRouter.IsOnline);
            Assert.False(savedPhone.IsOnline);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
            if (File.Exists(path + ".tmp")) File.Delete(path + ".tmp");
        }
    }

    private static DeviceInfo Device(string ip, string mac, string vendor) => new()
    {
        IpAddress = IPAddress.Parse(ip),
        MacAddress = mac,
        Vendor = vendor,
        HostName = "test-device",
        DeviceType = "جهاز شبكة"
    };
}
