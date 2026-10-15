using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace NEXVARY.NetScan.Analysis;

// Observations belong to a snapshot, never to a globally unique IP/MAC identity.
public sealed record DeviceObservation(string Ip, string? Mac, string HostName);
public sealed record DiscoverySnapshot(
    Guid Id, DateTimeOffset CapturedAtUtc, string AdapterId, string AdapterName,
    string LocalIp, string SubnetMask, string? GatewayIp,
    IReadOnlyList<DeviceObservation> Devices);

public enum FindingSeverity { Unknown, Info, Low, Medium, High, Critical }
public enum CorrelationState { Unmatched, Candidate, Stale, Ambiguous }
public enum ReviewState { NeedsReview, Confirmed, FalsePositive, Resolved }

public sealed record Finding
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Source { get; init; } = "Nuclei";
    public required string TemplateId { get; init; }
    public required string Title { get; init; }
    public string Matcher { get; init; } = "";
    public string Protocol { get; init; } = "";
    public required string Target { get; init; }
    public string? TargetIp { get; init; }
    public int? Port { get; init; }
    public string LocationHash { get; init; } = "";
    public FindingSeverity Severity { get; init; }
    public string[] CveIds { get; init; } = [];
    public DateTimeOffset? ObservedAtUtc { get; init; }
    public DateTimeOffset ImportedAtUtc { get; init; }
    public Guid? SnapshotId { get; init; }
    public CorrelationState Correlation { get; init; }
    public ReviewState Review { get; init; } = ReviewState.NeedsReview;

    [JsonIgnore]
    public string DeduplicationKey => Hash(string.Join("\n", Source, TemplateId, Matcher,
        Protocol, Target, TargetIp, Port, LocationHash, ObservedAtUtc?.ToString("O"), SnapshotId));

    internal static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

public sealed record ImportResult(IReadOnlyList<Finding> Findings, int InvalidLines, int Duplicates);
public sealed record AnalysisDocument
{
    public int SchemaVersion { get; init; } = 1;
    public List<DiscoverySnapshot> Snapshots { get; init; } = [];
    public List<Finding> Findings { get; init; } = [];
}

public static class FindingCorrelator
{
    public static Finding Correlate(Finding finding, DiscoverySnapshot? snapshot)
    {
        if (snapshot is null || !IPAddress.TryParse(finding.TargetIp, out var ip))
            return finding with { SnapshotId = null, Correlation = CorrelationState.Unmatched };

        var matches = snapshot.Devices.Where(d => IPAddress.TryParse(d.Ip, out var other) && other.Equals(ip)).ToArray();
        var state = matches.Length switch
        {
            0 => CorrelationState.Unmatched,
            > 1 => CorrelationState.Ambiguous,
            _ when finding.ObservedAtUtc is null ||
                (finding.ObservedAtUtc.Value - snapshot.CapturedAtUtc).Duration() > TimeSpan.FromMinutes(15) => CorrelationState.Stale,
            _ => CorrelationState.Candidate
        };
        // Imported reports do not prove MAC ownership, even when timestamps agree.
        return finding with { SnapshotId = snapshot.Id, Correlation = state };
    }
}
