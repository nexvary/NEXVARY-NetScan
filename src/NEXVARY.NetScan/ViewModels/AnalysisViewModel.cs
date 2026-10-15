using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows.Data;
using NEXVARY.NetScan.Analysis;

namespace NEXVARY.NetScan.ViewModels;

public sealed record FindingRow(Finding Finding)
{
    public string Title => Finding.Title;
    public string Target => Finding.Target;
    public string Address => Finding.TargetIp ?? "غير متاح";
    public string Rule => Finding.TemplateId;
    public string Severity => Finding.Severity switch
    {
        FindingSeverity.Critical => "حرجة", FindingSeverity.High => "عالية", FindingSeverity.Medium => "متوسطة",
        FindingSeverity.Low => "منخفضة", FindingSeverity.Info => "معلومة", _ => "غير محددة"
    };
    public string SeverityColor => Finding.Severity switch
    {
        FindingSeverity.Critical or FindingSeverity.High => "#FF8D96", FindingSeverity.Medium => "#F0BD5B",
        FindingSeverity.Low => "#6BC7EF", _ => "#A9BAC9"
    };
    public string Correlation => Finding.Correlation switch
    {
        CorrelationState.Candidate => "مطابقة محتملة", CorrelationState.Stale => "توقيت غير متوافق",
        CorrelationState.Ambiguous => "مطابقة ملتبسة", _ => "غير مرتبط"
    };
    public string Review => Finding.Review switch
    {
        ReviewState.Confirmed => "مؤكدة يدويًا", ReviewState.FalsePositive => "إنذار كاذب",
        ReviewState.Resolved => "تم العلاج", _ => "تحتاج مراجعة"
    };
    public string Details => $"المصدر: {Finding.Source}\nالقاعدة: {Finding.TemplateId}\nالمطابق: {Finding.Matcher}\nالبروتوكول: {Finding.Protocol}\n" +
        $"الهدف: {Finding.Target}\nIP المُبلّغ: {Address}\nCVE: {string.Join(", ", Finding.CveIds ?? [])}\n" +
        $"وقت الرصد UTC: {Finding.ObservedAtUtc?.ToString("u") ?? "غير متاح"}\nوقت الاستيراد UTC: {Finding.ImportedAtUtc:u}\n" +
        $"لقطة الاكتشاف: {Finding.SnapshotId?.ToString() ?? "لا توجد"}\nالربط: {Correlation}\nالمراجعة: {Review}\n" +
        "الربط مبني على عنوان IP المبلّغ ولقطة محددة، ولا يثبت هوية الجهاز أو وجود الثغرة. حُذفت مسارات URL وبيانات الطلب والاستجابة من الاستيراد.";
}

public sealed class AnalysisViewModel : INotifyPropertyChanged
{
    private readonly FindingStore _store;
    private AnalysisDocument _document = new();
    private DiscoverySnapshot? _currentSnapshot;
    private bool _readOnly;
    private bool _busy;
    private bool _linkToCurrentSnapshot;
    private string _search = "";
    private string _message = "استورد تقرير Nuclei JSONL لعرضه محليًا. لا يبدأ الاستيراد أي فحص للشبكة.";
    private FindingRow? _selected;

    public ObservableCollection<FindingRow> Findings { get; } = new();
    public ICollectionView FindingsView { get; }
    public event PropertyChangedEventHandler? PropertyChanged;
    public bool IsBusy => _busy;
    public bool CanImport => !_busy && !_readOnly;
    public bool CanClear => !_busy;
    public bool CanReview => CanImport && SelectedFinding is not null;
    public bool HasCurrentSnapshot => _currentSnapshot is not null && !_busy;
    public string SnapshotLabel => _currentSnapshot is null ? "لا توجد لقطة اكتشاف؛ ستبقى النتائج غير مرتبطة." :
        $"اللقطة الحالية: {_currentSnapshot.LocalIp} • {_currentSnapshot.AdapterName} • {_currentSnapshot.CapturedAtUtc.ToLocalTime():HH:mm:ss}";
    public bool LinkToCurrentSnapshot { get => _linkToCurrentSnapshot; set { _linkToCurrentSnapshot = value; Changed(); } }
    public string Message { get => _message; private set { _message = value; Changed(); } }
    public string Summary => $"{Findings.Count} نتيجة • {Findings.Count(x => x.Finding.Severity is FindingSeverity.Critical or FindingSeverity.High)} عالية / حرجة • {Findings.Count(x => x.Finding.Review == ReviewState.NeedsReview)} تحتاج مراجعة";
    public string Search { get => _search; set { _search = value; FindingsView.Refresh(); Changed(); } }
    public FindingRow? SelectedFinding { get => _selected; set { _selected = value; Changed(); Changed(nameof(CanReview)); } }

    public AnalysisViewModel(FindingStore? store = null)
    {
        _store = store ?? new FindingStore(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NEXVARY", "NetScan", "security-results.json"));
        FindingsView = CollectionViewSource.GetDefaultView(Findings);
        FindingsView.Filter = item => item is FindingRow row && (string.IsNullOrWhiteSpace(Search) ||
            new[] { row.Title, row.Target, row.Address, row.Rule, row.Severity, row.Correlation, row.Review, string.Join(" ", row.Finding.CveIds ?? []) }
                .Any(text => text.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase)));
        try { _document = _store.Load(); Reload(); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            _readOnly = true;
            Message = "تعذر قراءة النتائج المحفوظة؛ أُوقف الاستيراد لحماية الملف. يمكنك مسح نتائج الأمان صراحةً للبدء مجددًا.";
        }
    }

    public void SetSnapshot(DiscoverySnapshot? snapshot)
    {
        _currentSnapshot = snapshot;
        LinkToCurrentSnapshot = false;
        Changed(nameof(HasCurrentSnapshot)); Changed(nameof(SnapshotLabel));
    }

    public async Task ImportAsync(string path)
    {
        if (!CanImport) return;
        var snapshot = LinkToCurrentSnapshot ? _currentSnapshot : null;
        SetBusy(true);
        try
        {
            var result = await Task.Run(async () =>
            {
                await using var stream = File.OpenRead(path);
                return await new NucleiJsonlImporter().ImportAsync(stream, DateTimeOffset.UtcNow);
            });
            var keys = _document.Findings.Select(f => f.DeduplicationKey).ToHashSet(StringComparer.Ordinal);
            var additions = result.Findings.Select(f => FindingCorrelator.Correlate(f, snapshot)).Where(f => keys.Add(f.DeduplicationKey)).ToArray();
            if (additions.Length == 0)
            {
                Message = $"لم تُضف نتائج. أسطر غير صالحة: {result.InvalidLines}؛ مكررة: {result.Duplicates + result.Findings.Count}. غياب النتائج لا يعني أن الأجهزة آمنة.";
                return;
            }
            var snapshots = _document.Snapshots.ToList();
            if (snapshot is not null && snapshots.All(s => s.Id != snapshot.Id)) snapshots.Add(snapshot);
            var next = _document with { Findings = _document.Findings.Concat(additions).ToList(), Snapshots = snapshots };
            await Task.Run(() => _store.Save(next));
            _document = next; Reload();
            Message = $"أُضيفت {additions.Length} نتيجة؛ أسطر غير صالحة: {result.InvalidLines}؛ مكررة: {result.Duplicates + result.Findings.Count - additions.Length}. النتائج تحتاج مراجعة.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.DecoderFallbackException)
        { Message = "لم يُحفظ الاستيراد. " + ex.Message; }
        finally { SetBusy(false); }
    }

    public async Task SetReviewAsync(ReviewState state)
    {
        if (!CanReview || SelectedFinding is null) return;
        Guid selectedId = SelectedFinding.Finding.Id;
        SetBusy(true);
        try
        {
            var next = _document with { Findings = _document.Findings.Select(f => f.Id == selectedId ? f with { Review = state } : f).ToList() };
            await Task.Run(() => _store.Save(next));
            _document = next; Reload();
            SelectedFinding = Findings.FirstOrDefault(f => f.Finding.Id == selectedId);
            Message = "حُفظ قرار المراجعة اليدوية محليًا؛ لم يُنفذ أي تغيير على الجهاز.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException) { Message = "تعذر حفظ المراجعة. " + ex.Message; }
        finally { SetBusy(false); }
    }

    public async Task ClearAsync()
    {
        if (_busy) return;
        SetBusy(true);
        try
        {
            var empty = new AnalysisDocument();
            await Task.Run(() => _store.Save(empty));
            _document = empty; _readOnly = false; Reload();
            Message = "مُسحت نتائج الأمان ولقطاتها المحفوظة. سجل اكتشاف الأجهزة مستقل.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException) { Message = "تعذر مسح النتائج. " + ex.Message; }
        finally { SetBusy(false); }
    }

    private void Reload()
    {
        SelectedFinding = null; Findings.Clear();
        foreach (var finding in _document.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.ImportedAtUtc)) Findings.Add(new(finding));
        Changed(nameof(Summary));
    }
    private void SetBusy(bool busy)
    {
        _busy = busy;
        foreach (var name in new[] { nameof(IsBusy), nameof(CanImport), nameof(CanClear), nameof(CanReview), nameof(HasCurrentSnapshot) }) Changed(name);
    }
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}
