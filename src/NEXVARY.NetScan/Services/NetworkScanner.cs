using System.Collections.Concurrent;
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
    string NetworkLabel);

public sealed class NetworkScanner
{
    private const int MaxParallelism = 96;
    private const int PingTimeoutMs = 450;
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
            SubnetCalculator.Describe(selected.Unicast.Address, selected.Unicast.IPv4Mask!));
    }

    public async Task<IReadOnlyList<DeviceInfo>> ScanAsync(
        NetworkContext context,
        IProgress<(int Done, int Total)>? progress,
        CancellationToken cancellationToken)
    {
        var addresses = SubnetCalculator.GetHostAddresses(context.LocalAddress, context.SubnetMask);
        var discovered = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Always expose this PC even if the network blocks ICMP.
        discovered[context.LocalAddress.ToString()] = GetLocalMacForIp(context.LocalAddress) ?? string.Empty;

        // The default gateway is a valid network device even when it blocks ping.
        if (context.Gateway is not null)
            discovered.TryAdd(context.Gateway.ToString(), string.Empty);

        var gate = new SemaphoreSlim(MaxParallelism, MaxParallelism);
        int completed = 0;

        // An ICMP sweep has two purposes: discover ping-capable hosts and, more
        // importantly, force Windows to resolve ARP/neighbor entries for local hosts.
        var tasks = addresses.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                bool pingOk = await TryPingAsync(ip, cancellationToken).ConfigureAwait(false);
                if (pingOk)
                    discovered.TryAdd(ip.ToString(), string.Empty);
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

        // Give Windows a moment to commit neighbor-cache updates produced by the sweep.
        await Task.Delay(180, cancellationToken).ConfigureAwait(false);

        // Read the real Windows ARP table. This finds devices that reject ICMP but
        // still answered layer-2 ARP, which is common for cameras, APs and IoT gear.
        foreach (var neighbor in ReadArpTable(context.InterfaceIndex))
        {
            if (!IsSameSubnet(neighbor.Address, context.LocalAddress, context.SubnetMask))
                continue;

            discovered.AddOrUpdate(
                neighbor.Address.ToString(),
                neighbor.MacAddress,
                (_, existing) => string.IsNullOrWhiteSpace(existing) ? neighbor.MacAddress : existing);
        }

        var deviceTasks = discovered.Select(async pair =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ip = IPAddress.Parse(pair.Key);
            bool isLocal = ip.Equals(context.LocalAddress);
            bool isGateway = context.Gateway is not null && ip.Equals(context.Gateway);

            string? mac = string.IsNullOrWhiteSpace(pair.Value) ? null : pair.Value;
            if (mac is null)
                mac = isLocal ? GetLocalMacForIp(ip) : TryGetMacAddress(ip);

            return await BuildDeviceAsync(ip, mac, isLocal, isGateway, cancellationToken)
                .ConfigureAwait(false);
        });

        var devices = await Task.WhenAll(deviceTasks).ConfigureAwait(false);

        return devices
            .OrderBy(d => d.IpAddress.GetAddressBytes(), ByteArrayComparer.Instance)
            .ToList();
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

            return new AdapterCandidate(networkInterface, unicast, gateway, ipv4.Index);
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
        bool isLocal,
        bool isGateway,
        CancellationToken token)
    {
        string hostName = await TryResolveHostNameAsync(ip, token).ConfigureAwait(false);
        string macAddress = mac ?? "غير متاح";
        string vendor = VendorResolver.Resolve(macAddress);
        var presentation = DeviceClassifier.Classify(hostName, vendor, isGateway, isLocal);

        return new DeviceInfo
        {
            IpAddress = ip,
            HostName = hostName,
            MacAddress = macAddress,
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
                if (row.PhysicalAddress is null || row.PhysicalAddressLength == 0)
                    continue;

                int macLength = (int)Math.Min(row.PhysicalAddressLength, 8u);
                var macBytes = row.PhysicalAddress.Take(macLength).ToArray();
                if (macBytes.All(b => b == 0))
                    continue;

                var address = new IPAddress(BitConverter.GetBytes(row.Address));
                if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.Broadcast))
                    continue;

                string mac = string.Join(":", macBytes.Select(b => b.ToString("X2")));
                result.Add(new ArpNeighbor(address, mac));
            }
        }
        catch
        {
            // Discovery still returns ping/local/gateway results if ARP-table access fails.
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
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

    private static string? GetLocalMacForIp(IPAddress ip)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(ip)))
                continue;

            var bytes = nic.GetPhysicalAddress().GetAddressBytes();
            return bytes.Length == 0 ? null : string.Join(":", bytes.Select(b => b.ToString("X2")));
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
            if (result != 0 || length <= 0)
                return null;

            return string.Join(":", mac.Take(Math.Min(length, mac.Length)).Select(b => b.ToString("X2")));
        }
        catch
        {
            return null;
        }
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
        int InterfaceIndex);

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
