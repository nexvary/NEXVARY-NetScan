using System.Text.Json.Serialization;

namespace NEXVARY.NetScan.Models;

public sealed class DeviceHistoryEntry
{
    public string Key { get; set; } = string.Empty;
    public string Ip { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string DnsServer { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string DeviceType { get; set; } = string.Empty;
    public string IconKind { get; set; } = "Generic";
    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public bool IsOnline { get; set; }

    [JsonIgnore]
    public string Status => IsOnline ? "متصل الآن" : "غير موجود الآن";

    [JsonIgnore]
    public string FirstSeen => FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

    [JsonIgnore]
    public string LastSeen => LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
}
