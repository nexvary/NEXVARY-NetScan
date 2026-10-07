using System.Net;

namespace NEXVARY.NetScan.Models;

public sealed class DeviceInfo
{
    public required IPAddress IpAddress { get; init; }
    public string Ip => IpAddress.ToString();
    public string HostName { get; init; } = "غير معروف";
    public string MacAddress { get; init; } = "غير متاح";
    public string Vendor { get; init; } = "غير معروف";
    public string DeviceType { get; init; } = "جهاز شبكة";
    public string IconKind { get; init; } = "Generic";
    public string Status { get; init; } = "متصل";
    public bool IsGateway { get; init; }
    public bool IsLocalComputer { get; init; }
}
