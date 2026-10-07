using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NEXVARY.NetScan.Models;

namespace NEXVARY.NetScan.Services;

public sealed record NetworkContext(
    string AdapterName,
    IPAddress LocalAddress,
    IPAddress SubnetMask,
    IPAddress? Gateway,
    string NetworkLabel);

public sealed class NetworkScanner
{
    private const int MaxParallelism = 64;

    public NetworkContext GetActiveNetwork()
    {
        var candidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n => new { Interface = n, Properties = n.GetIPProperties() })
            .Select(x => new
            {
                x.Interface,
                x.Properties,
                Unicast = x.Properties.UnicastAddresses.FirstOrDefault(u =>
                    u.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(u.Address) &&
                    u.IPv4Mask is not null),
                Gateway = x.Properties.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))
            })
            .Where(x => x.Unicast is not null)
            .OrderByDescending(x => x.Gateway is not null)
            .ThenByDescending(x => x.Interface.Speed)
            .ToList();

        var selected = candidates.FirstOrDefault()
            ?? throw new InvalidOperationException("لم يتم العثور على اتصال شبكة IPv4 نشط.");

        var local = selected.Unicast!.Address;
        var mask = selected.Unicast.IPv4Mask!;
        return new NetworkContext(
            selected.Interface.Name,
            local,
            mask,
            selected.Gateway,
            SubnetCalculator.Describe(local, mask));
    }

    public async Task<IReadOnlyList<DeviceInfo>> ScanAsync(
        NetworkContext context,
        IProgress<(int Done, int Total)>? progress,
        CancellationToken cancellationToken)
    {
        var addresses = SubnetCalculator.GetHostAddresses(context.LocalAddress, context.SubnetMask);
        var results = new List<DeviceInfo>();
        var gate = new SemaphoreSlim(MaxParallelism, MaxParallelism);
        var sync = new object();
        int completed = 0;

        var tasks = addresses.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var device = await ProbeAsync(ip, context, cancellationToken).ConfigureAwait(false);
                if (device is not null)
                {
                    lock (sync)
                        results.Add(device);
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
        return results
            .OrderBy(d => d.IpAddress.GetAddressBytes(), ByteArrayComparer.Instance)
            .ToList();
    }

    private static async Task<DeviceInfo?> ProbeAsync(IPAddress ip, NetworkContext context, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        bool isLocal = ip.Equals(context.LocalAddress);
        bool isGateway = context.Gateway is not null && ip.Equals(context.Gateway);
        bool pingOk = isLocal;

        if (!isLocal)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 300).ConfigureAwait(false);
                pingOk = reply.Status == IPStatus.Success;
            }
            catch
            {
                pingOk = false;
            }
        }

        string? mac = isLocal ? GetLocalMacForIp(ip) : TryGetMacAddress(ip);
        if (!pingOk && mac is null && !isGateway)
            return null;

        string hostName = await TryResolveHostNameAsync(ip, token).ConfigureAwait(false);
        return new DeviceInfo
        {
            IpAddress = ip,
            HostName = hostName,
            MacAddress = mac ?? "غير متاح",
            DeviceType = isGateway ? "الراوتر / البوابة" : isLocal ? "هذا الكمبيوتر" : "جهاز شبكة",
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
                .WaitAsync(TimeSpan.FromMilliseconds(450), token)
                .ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(entry.HostName) ? "غير معروف" : entry.HostName;
        }
        catch
        {
            return "غير معروف";
        }
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

        byte[] mac = new byte[6];
        int length = mac.Length;
        byte[] bytes = ip.GetAddressBytes();
        uint destination = BitConverter.ToUInt32(bytes, 0);
        uint result = SendARP(destination, 0, mac, ref length);
        if (result != 0 || length <= 0)
            return null;

        return string.Join(":", mac.Take(length).Select(b => b.ToString("X2")));
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLength);

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
                if (cmp != 0) return cmp;
            }
            return x.Length.CompareTo(y.Length);
        }
    }
}
