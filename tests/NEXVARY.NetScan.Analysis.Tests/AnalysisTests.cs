using System.Text;
using System.Text.Json;
using NEXVARY.NetScan.Analysis;
using Xunit;

namespace NEXVARY.NetScan.Analysis.Tests;

public sealed class AnalysisTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 2, 0, 0, TimeSpan.Zero);
    private static string Report(string target = "http://192.168.1.10:8080/admin?token=secret", string? timestamp = "2026-10-15T02:00:00Z", string? ip = null) => JsonSerializer.Serialize(new Dictionary<string, object?>
    {
        ["template-id"] = "test-rule", ["matched-at"] = target, ["timestamp"] = timestamp, ["ip"] = ip,
        ["type"] = "http", ["matcher-name"] = "test-matcher",
        ["info"] = new { name = "Test observation", severity = "high", classification = new Dictionary<string, object> { ["cve-id"] = new[] { "CVE-2026-12345", "bad-cve" } } },
        ["request"] = "Authorization: Bearer secret", ["response"] = "password=secret", ["extracted-results"] = new[] { "private-key=secret" }
    });
    private static async Task<ImportResult> Import(string text) => await new NucleiJsonlImporter().ImportAsync(new MemoryStream(Encoding.UTF8.GetBytes(text)), Now);
    private static DiscoverySnapshot Snapshot(params DeviceObservation[] devices) => new(Guid.NewGuid(), Now, "adapter-a", "LAN", "192.168.1.2", "255.255.255.0", "192.168.1.1", devices);

    [Fact]
    public async Task ImportsStructuredFieldsAndExcludesRawSecrets()
    {
        var result = await Import(Report("https://user:password@192.168.1.10:8443/private-secret?token=secret#secret"));
        var finding = Assert.Single(result.Findings);
        Assert.Equal("https://192.168.1.10:8443", finding.Target);
        Assert.Equal("192.168.1.10", finding.TargetIp);
        Assert.Equal(8443, finding.Port);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal("CVE-2026-12345", Assert.Single(finding.CveIds));
        Assert.DoesNotContain("secret", JsonSerializer.Serialize(finding));
        Assert.DoesNotContain("password", JsonSerializer.Serialize(finding));
        Assert.Equal(ReviewState.NeedsReview, finding.Review);
    }

    [Fact]
    public async Task DuplicateAndMalformedLinesAreReportedWithoutDiscardingValidRows()
    {
        string valid = Report();
        var result = await Import("\r\nnot-json\n[]\n" + valid + "\r\n" + valid + "\n");
        Assert.Single(result.Findings); Assert.Equal(2, result.InvalidLines); Assert.Equal(1, result.Duplicates);
    }

    [Fact]
    public async Task DistinctPathsRetainDistinctFingerprintsWithoutStoringPaths()
    {
        var result = await Import(Report("http://192.168.1.10/a") + "\n" + Report("http://192.168.1.10/b"));
        Assert.Equal(2, result.Findings.Count);
        Assert.All(result.Findings, f => Assert.Equal("http://192.168.1.10:80", f.Target));
    }

    [Fact]
    public async Task HostnameUsesReportedIpWithoutDnsResolution()
    {
        var finding = Assert.Single((await Import(Report("https://example.invalid/path", ip: "192.168.1.10"))).Findings);
        Assert.Equal("192.168.1.10", finding.TargetIp);
        Assert.Equal("https://example.invalid:443", finding.Target);
    }

    [Fact]
    public async Task ReportedIpCannotReplaceLiteralTarget()
    {
        var finding = Assert.Single((await Import(Report(ip: "10.0.0.7"))).Findings);
        Assert.Equal("192.168.1.10", finding.TargetIp);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///etc/passwd")]
    [InlineData("http://")]
    public async Task InvalidOrUnsupportedTargetIsRejected(string target) => Assert.Equal(1, (await Import(Report(target))).InvalidLines);

    [Fact]
    public async Task FailedMatchersAndErrorEventsAreNotFindings()
    {
        var failed = Report().Replace("\"type\":\"http\"", "\"matcher-status\":false,\"type\":\"http\"");
        Assert.Empty((await Import(failed)).Findings);
        Assert.Empty((await Import(Report().Replace("\"type\":\"http\"", "\"error\":\"timeout\",\"type\":\"http\""))).Findings);
    }

    [Fact]
    public async Task UnknownSeverityRemainsUnknown()
    {
        var finding = Assert.Single((await Import(Report().Replace("high", "100"))).Findings);
        Assert.Equal(FindingSeverity.Unknown, finding.Severity);
    }

    [Fact]
    public async Task OversizedLineAbortsImport() => await Assert.ThrowsAsync<InvalidDataException>(() => Import(new string('x', NucleiJsonlImporter.MaxLineChars + 1)));

    [Fact]
    public async Task OversizedSeekableFileRejectedBeforeReading()
    {
        using var input = new MemoryStream(new byte[NucleiJsonlImporter.MaxFileBytes + 1]);
        await Assert.ThrowsAsync<InvalidDataException>(() => new NucleiJsonlImporter().ImportAsync(input, Now));
    }

    [Fact]
    public async Task NonSeekableStreamBudgetCountsWhitespace()
    {
        using var input = new NonSeekableStream(new byte[NucleiJsonlImporter.MaxFileBytes + 1].Select(_ => (byte)'\n').ToArray());
        await Assert.ThrowsAsync<InvalidDataException>(() => new NucleiJsonlImporter().ImportAsync(input, Now));
    }

    [Fact]
    public async Task ExcessiveJsonDepthIsCountedAsInvalid()
    {
        var result = await Import("{\"extra\":" + new string('[', 40) + "0" + new string(']', 40) + "}");
        Assert.Equal(1, result.InvalidLines);
    }

    [Fact]
    public async Task CancellationStopsImport()
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report()));
        using var source = new CancellationTokenSource(); source.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new NucleiJsonlImporter().ImportAsync(input, Now, source.Token));
    }

    [Fact]
    public async Task CorrelationRequiresExplicitSnapshotAndNeverConfirmsIdentity()
    {
        var finding = Assert.Single((await Import(Report())).Findings);
        Assert.Equal(CorrelationState.Unmatched, FindingCorrelator.Correlate(finding, null).Correlation);
        var snapshot = Snapshot(new DeviceObservation("192.168.1.10", "00:11:22:33:44:55", "device"));
        var matched = FindingCorrelator.Correlate(finding, snapshot);
        Assert.Equal(snapshot.Id, matched.SnapshotId);
        Assert.Equal(CorrelationState.Candidate, matched.Correlation);
        Assert.Equal(ReviewState.NeedsReview, matched.Review);
        Assert.Equal(CorrelationState.Unmatched, FindingCorrelator.Correlate(finding, Snapshot(new DeviceObservation("10.0.0.10", null, "other"))).Correlation);
        Assert.Equal(CorrelationState.Ambiguous, FindingCorrelator.Correlate(finding, Snapshot(new DeviceObservation("192.168.1.10", "00:11:22:33:44:55", "a"), new DeviceObservation("192.168.1.10", "00:11:22:33:44:66", "b"))).Correlation);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("2025-01-01T00:00:00Z")]
    [InlineData("2027-01-01T00:00:00Z")]
    public async Task MissingOrDistantTimestampIsNotFreshMatch(string? timestamp)
    {
        var finding = Assert.Single((await Import(Report(timestamp: timestamp))).Findings);
        Assert.Equal(CorrelationState.Stale, FindingCorrelator.Correlate(finding, Snapshot(new DeviceObservation("192.168.1.10", null, "device"))).Correlation);
    }

    [Fact]
    public async Task SameIpInDifferentSnapshotsNeverSharesDeduplicationIdentity()
    {
        var finding = Assert.Single((await Import(Report())).Findings);
        var a = FindingCorrelator.Correlate(finding, Snapshot(new DeviceObservation("192.168.1.10", "00:11:22:33:44:55", "a")));
        var b = FindingCorrelator.Correlate(finding, Snapshot(new DeviceObservation("192.168.1.10", "00:11:22:33:44:66", "b")));
        Assert.NotEqual(a.DeduplicationKey, b.DeduplicationKey);
    }

    [Fact]
    public async Task StoreRoundTripsSnapshotsAndReviewAndRejectsFutureSchema()
    {
        string path = Path.Combine(Path.GetTempPath(), "netscan-analysis-" + Guid.NewGuid() + ".json");
        try
        {
            var store = new FindingStore(path);
            var snapshot = Snapshot(new DeviceObservation("192.168.1.10", null, "device"));
            var finding = FindingCorrelator.Correlate(Assert.Single((await Import(Report())).Findings), snapshot) with { Review = ReviewState.Resolved };
            store.Save(new() { Snapshots = [snapshot], Findings = [finding] });
            var loaded = store.Load();
            Assert.Equal(ReviewState.Resolved, Assert.Single(loaded.Findings).Review);
            Assert.Equal(snapshot.Id, Assert.Single(loaded.Snapshots).Id);
            Assert.Single(loaded.Snapshots[0].Devices);
            string before = File.ReadAllText(path);
            Assert.Throws<InvalidDataException>(() => store.Save(loaded with { SchemaVersion = 2 }));
            Assert.Equal(before, File.ReadAllText(path));
            File.WriteAllText(path, "{\"SchemaVersion\":2}");
            Assert.Throws<InvalidDataException>(() => store.Load());
            Assert.Equal("{\"SchemaVersion\":2}", File.ReadAllText(path));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{\"Findings\":null}")]
    [InlineData("{\"Findings\":[null]}")]
    [InlineData("{\"Snapshots\":[null]}")]
    public void CorruptStoreDoesNotSilentlyBecomeEmpty(string json)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            File.WriteAllText(path, json);
            Assert.Throws<InvalidDataException>(() => new FindingStore(path).Load());
            Assert.Equal(json, File.ReadAllText(path));
        }
        finally { File.Delete(path); }
    }

    private sealed class NonSeekableStream(byte[] buffer) : MemoryStream(buffer)
    {
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    }
}
