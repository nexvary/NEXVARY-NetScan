using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NEXVARY.NetScan.Analysis;

public interface IFindingImporter
{
    Task<ImportResult> ImportAsync(Stream input, DateTimeOffset importedAtUtc, CancellationToken cancellationToken = default);
}

public sealed partial class NucleiJsonlImporter : IFindingImporter
{
    public const int MaxFileBytes = 20 * 1024 * 1024;
    public const int MaxLineChars = 256 * 1024;
    public const int MaxFindings = 10000;

    public async Task<ImportResult> ImportAsync(Stream input, DateTimeOffset importedAtUtc, CancellationToken cancellationToken = default)
    {
        if (input.CanSeek && input.Length - input.Position > MaxFileBytes)
            throw new InvalidDataException("حجم الملف يتجاوز 20 MB.");
        // A read budget also applies to non-seekable/growing streams and counts blank lines.
        using var limited = new BudgetStream(input, MaxFileBytes);
        using var reader = new StreamReader(limited, new UTF8Encoding(false, true), true, 4096, leaveOpen: true);
        var findings = new List<Finding>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        int invalid = 0, duplicates = 0;
        var line = new StringBuilder();
        var buffer = new char[4096];
        while (true)
        {
            int count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            for (int i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                char c = buffer[i];
                if (c == '\n') { ProcessLine(); line.Clear(); }
                else
                {
                    if (line.Length >= MaxLineChars) throw new InvalidDataException("أحد أسطر الملف أطول من الحد المسموح.");
                    line.Append(c);
                }
            }
        }
        ProcessLine();
        return new(findings.AsReadOnly(), invalid, duplicates);

        void ProcessLine()
        {
            if (string.IsNullOrWhiteSpace(line.ToString())) return;
            if (findings.Count >= MaxFindings) throw new InvalidDataException("الملف يتجاوز حد 10000 نتيجة.");
            try
            {
                var finding = Parse(line.ToString(), importedAtUtc);
                if (keys.Add(finding.DeduplicationKey)) findings.Add(finding);
                else duplicates++;
            }
            catch (Exception ex) when (ex is JsonException or FormatException or InvalidDataException or InvalidOperationException)
            {
                invalid++;
            }
        }
    }

    private static Finding Parse(string line, DateTimeOffset importedAtUtc)
    {
        using var doc = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 32 });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
        if (root.TryGetProperty("matcher-status", out var status) && status.ValueKind == JsonValueKind.False)
            throw new InvalidDataException();
        if (Get(root, "error").Length > 0) throw new InvalidDataException();
        string id = Get(root, "template-id");
        if (id.Length == 0 || id.Length > 256) throw new InvalidDataException();
        var info = root.TryGetProperty("info", out var value) && value.ValueKind == JsonValueKind.Object ? value : default;
        string rawTarget = Get(root, "matched-at");
        if (rawTarget.Length == 0) rawTarget = Get(root, "host");
        if (rawTarget.Length == 0 || rawTarget.Length > 8192) throw new InvalidDataException();
        var (target, targetIp, port) = ParseTarget(rawTarget);
        string reportedIp = Get(root, "ip");
        // The report's resolved address may support a hostname; never override a literal target.
        if (targetIp is null && IPAddress.TryParse(reportedIp, out var parsedIp)) targetIp = parsedIp.ToString();
        string portText = Get(root, "port");
        if (port is null && int.TryParse(portText, out int number) && number is > 0 and <= 65535) port = number;
        DateTimeOffset? timestamp = DateTimeOffset.TryParse(Get(root, "timestamp"), CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var observed) ? observed.ToUniversalTime() : null;
        string severityText = Get(info, "severity");
        FindingSeverity severity = severityText.ToLowerInvariant() switch
        {
            "info" => FindingSeverity.Info, "low" => FindingSeverity.Low, "medium" => FindingSeverity.Medium,
            "high" => FindingSeverity.High, "critical" => FindingSeverity.Critical, _ => FindingSeverity.Unknown
        };
        var cves = new List<string>();
        if (info.ValueKind == JsonValueKind.Object && info.TryGetProperty("classification", out var classification) &&
            classification.ValueKind == JsonValueKind.Object && classification.TryGetProperty("cve-id", out var cve))
        {
            if (cve.ValueKind == JsonValueKind.String) AddCve(cve.GetString());
            if (cve.ValueKind == JsonValueKind.Array) foreach (var item in cve.EnumerateArray().Take(32))
                if (item.ValueKind == JsonValueKind.String) AddCve(item.GetString());
        }
        string name = Get(info, "name");
        return new Finding
        {
            TemplateId = Clean(id, 256), Title = Clean(name.Length > 0 ? name : id, 256),
            Matcher = Clean(Get(root, "matcher-name"), 128), Protocol = Clean(Get(root, "type"), 32),
            Target = target, TargetIp = targetIp, Port = port, LocationHash = Finding.Hash(rawTarget),
            Severity = severity, CveIds = cves.Distinct().ToArray(), ObservedAtUtc = timestamp, ImportedAtUtc = importedAtUtc
        };
        void AddCve(string? text) { if (text is not null && CvePattern().IsMatch(text)) cves.Add(text.ToUpperInvariant()); }
    }

    private static (string Target, string? Ip, int? Port) ParseTarget(string raw)
    {
        if (IPAddress.TryParse(raw, out var direct)) return (direct.ToString(), direct.ToString(), null);
        var withScheme = raw.Contains("://", StringComparison.Ordinal) ? raw : "tcp://" + raw;
        if (!Uri.TryCreate(withScheme, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host) ||
            uri.Scheme is not ("http" or "https" or "tcp" or "ssl" or "tls" or "dns")) throw new InvalidDataException();
        string host = uri.IdnHost.Trim('[', ']');
        string? ip = IPAddress.TryParse(host, out var parsed) ? parsed.ToString() : null;
        string displayHost = ip?.Contains(':') == true ? "[" + ip + "]" : host;
        int? port = uri.Port is > 0 and <= 65535 ? uri.Port : null;
        // Deliberately do not retain URL credentials, paths, queries, fragments, raw requests or extracted secrets.
        return ($"{uri.Scheme}://{displayHost}{(port is null ? "" : ":" + port)}", ip, port);
    }

    private static string Get(JsonElement root, string name) => root.ValueKind == JsonValueKind.Object &&
        root.TryGetProperty(name, out var value) ? value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? "", JsonValueKind.Number => value.GetRawText(), _ => ""
        } : "";

    private static string Clean(string value, int limit) => new(value.Where(c => !char.IsControl(c) &&
        c is not (>= '\u202A' and <= '\u202E') && c is not (>= '\u2066' and <= '\u2069')).Take(limit).ToArray());

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();

    private sealed class BudgetStream(Stream inner, long budget) : Stream
    {
        private long _remaining = budget;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, (int)Math.Min(count, _remaining + 1));
            Consume(n); return n;
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int n = await inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _remaining + 1)], cancellationToken).ConfigureAwait(false);
            Consume(n); return n;
        }
        private void Consume(int count) { _remaining -= count; if (_remaining < 0) throw new InvalidDataException("حجم الملف يتجاوز 20 MB."); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
