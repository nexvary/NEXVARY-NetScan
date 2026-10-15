using System.Text.Json;
using System.Text.Json.Serialization;

namespace NEXVARY.NetScan.Analysis;

public sealed class FindingStore(string filePath)
{
    private const int MaxStoreBytes = 32 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        MaxDepth = 32,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };

    public AnalysisDocument Load()
    {
        if (!File.Exists(filePath)) return new();
        if (new FileInfo(filePath).Length > MaxStoreBytes) throw new InvalidDataException("ملف نتائج الأمان أكبر من الحد المسموح.");
        using var stream = File.OpenRead(filePath);
        var document = JsonSerializer.Deserialize<AnalysisDocument>(stream, Options)
            ?? throw new InvalidDataException("ملف نتائج الأمان غير صالح.");
        Validate(document);
        return document;
    }

    public void Save(AnalysisDocument document)
    {
        Validate(document);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(document, Options);
        if (bytes.Length > MaxStoreBytes) throw new InvalidDataException("امسح النتائج القديمة قبل إضافة مزيد من البيانات.");
        string path = Path.GetFullPath(filePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static void Validate(AnalysisDocument document)
    {
        if (document.SchemaVersion != 1) throw new InvalidDataException("إصدار ملف نتائج الأمان غير مدعوم. لم يتم تغييره.");
        if (document.Findings is null || document.Snapshots is null || document.Findings.Count > 10000 || document.Snapshots.Count > 100 ||
            document.Findings.Any(f => f is null || string.IsNullOrWhiteSpace(f.TemplateId) || string.IsNullOrWhiteSpace(f.Target) || f.Title is null) ||
            document.Snapshots.Any(s => s is null || s.Devices is null || s.Devices.Any(d => d is null)))
            throw new InvalidDataException("بنية ملف نتائج الأمان غير صالحة أو تتجاوز السعة.");
    }
}
