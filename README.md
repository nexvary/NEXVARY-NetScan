# NEXVARY NetScan

NEXVARY NetScan is a lightweight Windows desktop utility for discovering devices connected to the local network without requiring command-line tools.

## Goals
- One-click local network discovery
- Clear Windows-native graphical interface
- Show IP address, host name, MAC address, vendor hint and reachability
- Refresh, search, copy and export results
- Safe local-network operation only

Development happens on `dev/foundation`.

## Local security report analysis (0.2.8 development)

The **نتائج الأمان** tab imports existing Nuclei JSONL reports without executing
scans or templates. Correlation to the current LAN discovery snapshot is opt-in
and remains a candidate match. Reports and manual review decisions are stored
locally and independently of device history. See [usage, limits and scope](docs/RELEASE-0.2.8.md).

Analysis tests can run on .NET 8 without Windows:

```text
dotnet test tests/NEXVARY.NetScan.Analysis.Tests -c Release
```

WPF, startup and installer verification run on Windows through GitHub Actions.
