using System.Net;

namespace NEXVARY.NetScan.Services;

public static class SubnetCalculator
{
    public static IReadOnlyList<IPAddress> GetHostAddresses(IPAddress localAddress, IPAddress subnetMask, int maxHosts = 512)
    {
        var ip = localAddress.GetAddressBytes();
        var mask = subnetMask.GetAddressBytes();
        if (ip.Length != 4 || mask.Length != 4)
            throw new ArgumentException("IPv4 addresses are required.");

        uint ipValue = ToUInt32(ip);
        uint maskValue = ToUInt32(mask);
        uint network = ipValue & maskValue;
        uint broadcast = network | ~maskValue;
        ulong hostCount = broadcast > network ? (ulong)broadcast - network - 1UL : 0UL;

        // Very large corporate/VPN subnets should not trigger an accidental full sweep.
        if (hostCount > (ulong)maxHosts)
        {
            maskValue = 0xFFFFFF00;
            network = ipValue & maskValue;
            broadcast = network | ~maskValue;
        }

        var result = new List<IPAddress>();
        for (uint value = network + 1; value < broadcast && result.Count < maxHosts; value++)
            result.Add(FromUInt32(value));

        return result;
    }

    public static string Describe(IPAddress localAddress, IPAddress subnetMask)
    {
        var ip = localAddress.GetAddressBytes();
        var mask = subnetMask.GetAddressBytes();
        uint network = ToUInt32(ip) & ToUInt32(mask);
        int prefix = mask.Sum(b => CountBits(b));
        return $"{FromUInt32(network)}/{prefix}";
    }

    private static int CountBits(byte value)
    {
        int count = 0;
        while (value != 0)
        {
            count += value & 1;
            value >>= 1;
        }
        return count;
    }

    private static uint ToUInt32(byte[] bytes) =>
        ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];

    private static IPAddress FromUInt32(uint value) => new(new byte[]
    {
        (byte)(value >> 24),
        (byte)(value >> 16),
        (byte)(value >> 8),
        (byte)value
    });
}
