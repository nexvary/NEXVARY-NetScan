using System.Net;

namespace NEXVARY.NetScan.Models;

public sealed class DeviceInfo
{
    public required IPAddress IpAddress { get; init; }
    public string Ip => IpAddress.ToString();
    public string HostName { get; init; } = "غير معروف";
    public string MacAddress { get; init; } = "غير متاح";
    public string DeviceType { get; init; } = "جهاز شبكة";
    public string Status { get; init; } = "متصل";
    public bool IsGateway { get; init; }
    public bool IsLocalComputer { get; init; }
}
