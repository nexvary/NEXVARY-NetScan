using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NEXVARY.NetScan.Models;

namespace NEXVARY.NetScan.Services;

public sealed record NetworkContext(
    string AdapterName,
    int InterfaceIndex,
    IPAddress LocalAddress,
    IPAddress SubnetMask,
    IPAddress? Gateway,
    IReadOnlyList<IPAddress> DnsServers,
    string NetworkLabel);

public sealed class NetworkScanner
{
    private const int MaxParallelism = 96;
    private const int PingTimeoutMs = 420;
    private const int ErrorInsufficientBuffer = 122;

    public NetworkContext GetActiveNetwork()
    {
        uint? bestInterface = TryGetBestInterfaceIndex();

        var candidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(TryCreateCandidate)
            .Where(x => x is not null)
            .Cast<AdapterCandidate>()
            .OrderByDescending(x => bestInterface.HasValue && x.InterfaceIndex == bestInterface.Value)
            .ThenByDescending(x => x.Gateway is not null)
            .ThenBy(x => AdapterRank(x.Interface.NetworkInterfaceType))
            .ThenByDescending(x => x.Interface.Speed)
            .ToList();

        var selected = candidates.FirstOrDefault()
            ?? throw new InvalidOperationException(
                "لم يتم العثور على اتصال IPv4 نشط. تأكد أن الكمبيوتر متصل بالراوتر عبر Wi-Fi أو كابل شبكة.");

        return new NetworkContext(
            selected.Interface.Name,
            selected.InterfaceIndex,
            selected.Unicast.Address,
            selected.Unicast.IPv4Mask!,
            selected.Gateway,
            selected.DnsServers,
            SubnetCalculator.Describe(selected.Unicast.Address, selected.Unicast.IPv4Mask!));
    }

    public async Task<IReadOnlyList<DeviceInfo>> ScanAsync(
        NetworkContext context,
        IProgress<(int Done, int Total)>? progress,
        CancellationToken cancellationToken)
    {
        var addresses = SubnetCalculator.GetHostAddresses(context.LocalAddress, context.SubnetMask);
        var discovered = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        discovered[context.LocalAddress.ToString()] = GetLocalMacForIp(context.LocalAddress) ?? string.Empty;

        if (context.Gateway is not null &&
            IsUsableHostAddress(context.Gateway, context.LocalAddress, context.SubnetMask))
        {
            discovered.TryAdd(context.Gateway.ToString(), string.Empty);
        }

        var gate = new SemaphoreSlim(MaxParallelism, MaxParallelism);
        int completed = 0;

        // Active LAN sweep: ICMP wakes responsive devices and SendARP directly asks
        // every IPv4 host for its layer-2 address. This is considerably stronger
        // than treating a successful ping as sufficient discovery.
        var tasks = addresses.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                bool pingOk = await TryPingAsync(ip, cancellationToken).ConfigureAwait(false);
                string? mac = TryGetMacAddress(ip);

                if (pingOk || mac is not null)
                {
                    discovered.AddOrUpdate(
                        ip.ToString(),
                        mac ?? string.Empty,
                        (_, existing) => mac ?? existing);
                }
            }
            finally
            {
                gate.Release();
                int done = Interlocked.Increment(ref completed);
                progress?.Report((done, addresses.Count));
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        await Task.Delay(180, cancellationToken).ConfigureAwait(false);

        MergeNeighbors(discovered, ReadArpTable(context.InterfaceIndex), context);

        // Modern Windows neighbor cache is an additional fallback. It frequently
        // contains MAC addresses for APs/cameras/IoT devices even when legacy ARP
        // APIs do not return them in the same scan cycle.
        MergeNeighbors(discovered, ReadWindowsNeighborTable(context.InterfaceIndex), context);

        string dnsDisplay = FormatDnsServers(context.DnsServers);

        var deviceTasks = discovered
            .Where(pair =>
                IPAddress.TryParse(pair.Key, out var address) &&
                IsUsableHostAddress(address, context.LocalAddress, context.SubnetMask))
            .Select(async pair =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                var ip = IPAddress.Parse(pair.Key);
                bool isLocal = ip.Equals(context.LocalAddress);
                bool isGateway = context.Gateway is not null && ip.Equals(context.Gateway);

                string? mac = NormalizeMac(pair.Value);
                if (mac is null)
                {
                    mac = isLocal ? GetLocalMacForIp(ip) : TryGetMacAddress(ip);
                }

                return await BuildDeviceAsync(
                        ip,
                        mac,
                        dnsDisplay,
                        isLocal,
                        isGateway,
                        cancellationToken)
                    .ConfigureAwait(false);
            });

        var devices = await Task.WhenAll(deviceTasks).ConfigureAwait(false);

        return devices
            .GroupBy(d => d.Ip, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(d => d.IpAddress.GetAddressBytes(), ByteArrayComparer.Instance)
            .ToList();
    }

    private static void MergeNeighbors(
        ConcurrentDictionary<string, string> discovered,
        IEnumerable<ArpNeighbor> neighbors,
        NetworkContext context)
    {
        foreach (var neighbor in neighbors)
        {
            if (!IsUsableHostAddress(neighbor.Address, context.LocalAddress, context.SubnetMask))
                continue;

            string? normalizedMac = NormalizeMac(neighbor.MacAddress);
            if (normalizedMac is null)
                continue;

            discovered.AddOrUpdate(
                neighbor.Address.ToString(),
                normalizedMac,
                (_, existing) => string.IsNullOrWhiteSpace(existing) ? normalizedMac : existing);
        }
    }

    private static AdapterCandidate? TryCreateCandidate(NetworkInterface networkInterface)
    {
        try
        {
            var properties = networkInterface.GetIPProperties();
            var unicast = properties.UnicastAddresses.FirstOrDefault(u =>
                u.Address.AddressFamily == AddressFamily.InterNetwork &&
                !IPAddress.IsLoopback(u.Address) &&
                u.IPv4Mask is not null &&
                !u.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal));

            if (unicast is null)
                return null;

            var ipv4 = properties.GetIPv4Properties();
            if (ipv4 is null)
                return null;

            var gateway = properties.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a =>
                    a.AddressFamily == AddressFamily.InterNetwork &&
                    !a.Equals(IPAddress.Any) &&
                    !a.Equals(IPAddress.None));

            var dnsServers = properties.DnsAddresses
                .Where(a =>
                    a.AddressFamily == AddressFamily.InterNetwork &&
                    !a.Equals(IPAddress.Any) &&
                    !a.Equals(IPAddress.None))
                .Distinct()
                .ToList();

            return new AdapterCandidate(
                networkInterface,
                unicast,
                gateway,
                ipv4.Index,
                dnsServers);
        }
        catch (NetworkInformationException)
        {
            return null;
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }

    private static int AdapterRank(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Wireless80211 => 0,
        NetworkInterfaceType.Ethernet => 0,
        NetworkInterfaceType.GigabitEthernet => 0,
        NetworkInterfaceType.FastEthernetFx => 0,
        NetworkInterfaceType.FastEthernetT => 0,
        _ => 1
    };

    private static uint? TryGetBestInterfaceIndex()
    {
        try
        {
            byte[] destinationBytes = IPAddress.Parse("1.1.1.1").GetAddressBytes();
            uint destination = BitConverter.ToUInt32(destinationBytes, 0);
            uint result = GetBestInterface(destination, out uint index);
            return result == 0 ? index : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> TryPingAsync(IPAddress ip, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, PingTimeoutMs)
                .WaitAsync(TimeSpan.FromMilliseconds(PingTimeoutMs + 250), token)
                .ConfigureAwait(false);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<DeviceInfo> BuildDeviceAsync(
        IPAddress ip,
        string? mac,
        string dnsServer,
        bool isLocal,
        bool isGateway,
        CancellationToken token)
    {
        string hostName = await TryResolveHostNameAsync(ip, token).ConfigureAwait(false);
        string macAddress = NormalizeMac(mac) ?? "غير متاح";
        string vendor = VendorResolver.Resolve(macAddress);
        var presentation = DeviceClassifier.Classify(hostName, vendor, isGateway, isLocal);

        return new DeviceInfo
        {
            IpAddress = ip,
            HostName = hostName,
            MacAddress = macAddress,
            DnsServer = dnsServer,
            Vendor = vendor,
            DeviceType = presentation.DeviceType,
            IconKind = presentation.IconKind,
            Status = "متصل",
            IsGateway = isGateway,
            IsLocalComputer = isLocal
        };
    }

    private static async Task<string> TryResolveHostNameAsync(IPAddress ip, CancellationToken token)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip)
                .WaitAsync(TimeSpan.FromMilliseconds(500), token)
                .ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(entry.HostName) ? "غير معروف" : entry.HostName;
        }
        catch
        {
            return "غير معروف";
        }
    }

    private static IReadOnlyList<ArpNeighbor> ReadArpTable(int interfaceIndex)
    {
        var result = new List<ArpNeighbor>();
        int size = 0;
        int first = GetIpNetTable(IntPtr.Zero, ref size, false);
        if (first != ErrorInsufficientBuffer || size <= 0)
            return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int second = GetIpNetTable(buffer, ref size, false);
            if (second != 0)
                return result;

            int count = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibIpNetRow>();
            IntPtr rowPointer = IntPtr.Add(buffer, sizeof(int));

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibIpNetRow>(rowPointer);
                rowPointer = IntPtr.Add(rowPointer, rowSize);

                if (row.InterfaceIndex != (uint)interfaceIndex)
                    continue;
                if (row.PhysicalAddress is null || row.PhysicalAddressLength < 6)
                    continue;

                var address = new IPAddress(BitConverter.GetBytes(row.Address));
                string mac = string.Join(":", row.PhysicalAddress.Take(6).Select(b => b.ToString("X2")));
                if (NormalizeMac(mac) is not null)
                    result.Add(new ArpNeighbor(address, mac));
            }
        }
        catch
        {
            // Other discovery sources still work if legacy ARP-table access fails.
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static IReadOnlyList<ArpNeighbor> ReadWindowsNeighborTable(int interfaceIndex)
    {
        var result = new List<ArpNeighbor>();

        try
        {
            string command =
                $"Get-NetNeighbor -InterfaceIndex {interfaceIndex} -AddressFamily IPv4 -ErrorAction SilentlyContinue | " +
                "Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' -and $_.State -ne 'Incomplete' } | " +
                "ForEach-Object { Write-Output ($_.IPAddress + '|' + $_.LinkLayerAddress) }";

            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"{command}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
                return result;

            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(2500))
            {
                try { process.Kill(true); } catch { }
                return result;
            }

            foreach (string rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = rawLine.Trim();
                int separator = line.IndexOf('|');
                if (separator <= 0 || separator >= line.Length - 1)
                    continue;

                if (!IPAddress.TryParse(line[..separator].Trim(), out var address))
                    continue;

                string? mac = NormalizeMac(line[(separator + 1)..].Trim());
                if (mac is not null)
                    result.Add(new ArpNeighbor(address, mac));
            }
        }
        catch
        {
            // PowerShell is a fallback only; native APIs remain the primary path.
        }

        return result;
    }

    public static string FormatDnsServers(IEnumerable<IPAddress> dnsServers)
    {
        var values = dnsServers
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => a.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return values.Count == 0 ? "غير متاح" : string.Join(" / ", values);
    }

    public static bool IsSameSubnet(IPAddress address, IPAddress localAddress, IPAddress subnetMask)
    {
        byte[] addressBytes = address.GetAddressBytes();
        byte[] localBytes = localAddress.GetAddressBytes();
        byte[] maskBytes = subnetMask.GetAddressBytes();

        if (addressBytes.Length != 4 || localBytes.Length != 4 || maskBytes.Length != 4)
            return false;

        for (int i = 0; i < 4; i++)
        {
            if ((addressBytes[i] & maskBytes[i]) != (localBytes[i] & maskBytes[i]))
                return false;
        }

        return true;
    }

    public static bool IsUsableHostAddress(IPAddress address, IPAddress localAddress, IPAddress subnetMask)
    {
        if (!IsSameSubnet(address, localAddress, subnetMask))
            return false;

        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length != 4 || bytes[0] >= 224)
            return false;

        uint addressValue = ToUInt32(bytes);
        uint localValue = ToUInt32(localAddress.GetAddressBytes());
        uint maskValue = ToUInt32(subnetMask.GetAddressBytes());
        uint network = localValue & maskValue;
        uint broadcast = network | ~maskValue;

        return addressValue > network && addressValue < broadcast;
    }

    private static uint ToUInt32(byte[] bytes) =>
        ((uint)bytes[0] << 24) |
        ((uint)bytes[1] << 16) |
        ((uint)bytes[2] << 8) |
        bytes[3];

    private static string? GetLocalMacForIp(IPAddress ip)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(ip)))
                continue;

            var bytes = nic.GetPhysicalAddress().GetAddressBytes();
            if (bytes.Length < 6)
                return null;

            return NormalizeMac(string.Join(":", bytes.Take(6).Select(b => b.ToString("X2"))));
        }

        return null;
    }

    private static string? TryGetMacAddress(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return null;

        try
        {
            byte[] mac = new byte[8];
            int length = mac.Length;
            uint destination = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
            uint result = SendARP(destination, 0, mac, ref length);
            if (result != 0 || length < 6)
                return null;

            return NormalizeMac(string.Join(":", mac.Take(6).Select(b => b.ToString("X2"))));
        }
        catch
        {
            return null;
        }
    }

    private static string? NormalizeMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
            return null;

        string hex = new(mac.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length < 12)
            return null;

        hex = hex[..12].ToUpperInvariant();

        if (hex.All(c => c == '0') || hex.All(c => c == 'F'))
            return null;

        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLength);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestInterface(uint destAddr, out uint bestIfIndex);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetIpNetTable(IntPtr ipNetTable, ref int sizePointer, bool order);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public uint InterfaceIndex;
        public uint PhysicalAddressLength;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysicalAddress;

        public uint Address;
        public uint Type;
    }

    private sealed record AdapterCandidate(
        NetworkInterface Interface,
        UnicastIPAddressInformation Unicast,
        IPAddress? Gateway,
        int InterfaceIndex,
        IReadOnlyList<IPAddress> DnsServers);

    private sealed record ArpNeighbor(IPAddress Address, string MacAddress);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;

            for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
            {
                int cmp = x[i].CompareTo(y[i]);
                if (cmp != 0)
                    return cmp;
            }

            return x.Length.CompareTo(y.Length);
        }
    }
}
