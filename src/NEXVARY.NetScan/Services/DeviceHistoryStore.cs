using System.IO;
using System.Text.Json;
using NEXVARY.NetScan.Models;

namespace NEXVARY.NetScan.Services;

public sealed class DeviceHistoryStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _filePath;

    public DeviceHistoryStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NEXVARY",
            "NetScan",
            "device-history.json");
    }

    public IReadOnlyList<DeviceHistoryEntry> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return Array.Empty<DeviceHistoryEntry>();

            string json = File.ReadAllText(_filePath);
            return JsonSerializer.Deserialize<List<DeviceHistoryEntry>>(json, JsonOptions)
                ?? new List<DeviceHistoryEntry>();
        }
        catch
        {
            return Array.Empty<DeviceHistoryEntry>();
        }
    }

    public IReadOnlyList<DeviceHistoryEntry> Merge(IEnumerable<DeviceInfo> discovered, DateTimeOffset now)
    {
        var entries = Load().GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToDictionary(x => x.Key, x => x.OrderByDescending(e => e.LastSeenUtc).First(), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.Values)
            entry.IsOnline = false;

        foreach (var device in discovered.Where(d => d.Status == "متصل"))
        {
            string key = BuildKey(device);
            if (!entries.ContainsKey(key) && key.StartsWith("mac:", StringComparison.Ordinal) && entries.Remove("ip:" + device.Ip, out var unresolved))
            {
                unresolved.Key = key;
                entries[key] = unresolved;
            }
            if (!entries.TryGetValue(key, out var entry))
            {
                entry = new DeviceHistoryEntry
                {
                    Key = key,
                    FirstSeenUtc = now
                };
                entries[key] = entry;
            }

            entry.Ip = device.Ip;
            entry.MacAddress = device.MacAddress;
            entry.DnsServer = device.DnsServer;
            entry.HostName = device.HostName;
            entry.Vendor = device.Vendor;
            entry.DeviceType = device.DeviceType;
            entry.IconKind = device.IconKind;
            entry.LastSeenUtc = now;
            entry.IsOnline = true;
        }

        var result = entries.Values
            .OrderByDescending(x => x.IsOnline)
            .ThenByDescending(x => x.LastSeenUtc)
            .ToList();

        Save(result);
        return result;
    }

    public void Clear()
    {
        if (File.Exists(_filePath)) File.Delete(_filePath);
    }

    private void Save(IReadOnlyList<DeviceHistoryEntry> entries)
    {
        string? directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        string tempPath = _filePath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(entries, JsonOptions));
        File.Move(tempPath, _filePath, true);
    }

    private static string BuildKey(DeviceInfo device)
    {
        if (!string.IsNullOrWhiteSpace(device.MacAddress) && device.MacAddress != "غير متاح")
            return "mac:" + device.MacAddress.Replace(":", string.Empty).Replace("-", string.Empty).ToUpperInvariant();

        return "ip:" + device.Ip;
    }
}
