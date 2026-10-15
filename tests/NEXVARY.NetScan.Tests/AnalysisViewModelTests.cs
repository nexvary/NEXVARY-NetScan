using System.IO;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows.Threading;
using NEXVARY.NetScan.Analysis;
using NEXVARY.NetScan.ViewModels;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class AnalysisViewModelTests
{
    [Fact]
    public void ImportReviewReloadClearAndCorruptStoreProtection()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
            var frame = new DispatcherFrame();
            async void Run()
            {
                string folder = Path.Combine(Path.GetTempPath(), "netscan-vm-" + Guid.NewGuid());
                Directory.CreateDirectory(folder);
                try
                {
                    string path = Path.Combine(folder, "results.json");
                    string fixture = Path.Combine(folder, "report.jsonl");
                    await File.WriteAllTextAsync(fixture, "{\"template-id\":\"test\",\"matched-at\":\"http://192.168.1.10\",\"info\":{\"name\":\"test observation\",\"severity\":\"high\"}}");
                    var vm = new AnalysisViewModel(new FindingStore(path));
                    Assert.False(vm.LinkToCurrentSnapshot);
                    await vm.ImportAsync(fixture);
                    Assert.Single(vm.Findings);
                    Assert.Equal(CorrelationState.Unmatched, vm.Findings[0].Finding.Correlation);
                    await vm.ImportAsync(fixture);
                    Assert.Single(vm.Findings);
                    vm.SelectedFinding = vm.Findings[0];
                    await vm.SetReviewAsync(ReviewState.FalsePositive);
                    var reloaded = new AnalysisViewModel(new FindingStore(path));
                    Assert.Equal(ReviewState.FalsePositive, Assert.Single(reloaded.Findings).Finding.Review);
                    reloaded.Search = "no-such-finding";
                    Assert.Empty(reloaded.FindingsView.Cast<object>());
                    reloaded.Search = "192.168.1.10";
                    Assert.Single(reloaded.FindingsView.Cast<object>());
                    await reloaded.ClearAsync();
                    Assert.Empty(new FindingStore(path).Load().Findings);
                    await File.WriteAllTextAsync(path, "{\"SchemaVersion\":99}");
                    var protectedVm = new AnalysisViewModel(new FindingStore(path));
                    Assert.False(protectedVm.CanImport);
                    await protectedVm.ImportAsync(fixture);
                    Assert.Equal("{\"SchemaVersion\":99}", await File.ReadAllTextAsync(path));
                    await protectedVm.ClearAsync();
                    Assert.True(protectedVm.CanImport);
                }
                catch (Exception ex) { failure = ex; }
                finally { Directory.Delete(folder, true); frame.Continue = false; }
            }
            Dispatcher.CurrentDispatcher.BeginInvoke((Action)Run);
            Dispatcher.PushFrame(frame);
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(30))) throw new TimeoutException("Analysis view model test timed out.");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
