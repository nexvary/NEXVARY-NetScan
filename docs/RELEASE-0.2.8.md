# NEXVARY NetScan 0.2.8

Development build: local security report analysis. This is not an integrated vulnerability scanner.

- Independent .NET 8 analysis library with bounded Nuclei JSONL import (20 MiB/file, 256 KiB characters/line, depth 32, 10,000 findings).
- Reports are untrusted observations. Import does not execute templates, resolve DNS, follow URLs, access cloud services, or scan devices.
- URL credentials, paths, queries, fragments, raw request/response, and extracted results are not retained. Rule titles and identifiers are plain untrusted text; review reports before sharing.
- Opt-in correlation against a captured discovery snapshot. IP matches remain candidates, never verified identity. Missing timestamps or differences beyond 15 minutes are labeled stale; duplicate IP observations are ambiguous.
- Snapshot stores interface ID, network addresses, gateway, capture time, and device observations. No findings are associated through legacy history keys or automatically reassigned on refresh/restart.
- Separate versioned atomic local store, import deduplication, search, manual review states, and confirmed clearing. Unknown/corrupt store versions block imports rather than silently overwriting data.
- Arabic security results tab, severity labels and colors, provenance/details, installed WPF rendering verification using explicitly labeled fixture data.
- Cross-platform analysis tests and Windows view model/installer checks. Release publication now requires explicit workflow dispatch with publish_release=true; development pushes only produce build artifacts.

## Use

1. Open **نتائج الأمان** and choose **استيراد Nuclei JSONL**.
2. Optionally run ordinary LAN discovery first and explicitly select correlation to its current snapshot. A report from another network should remain unlinked.
3. Search findings and inspect the selected finding's details. Imported severity is not a confidence score.
4. Record a manual review decision; this never changes the target device. A report without findings is not proof of safety.

## Deferred

No scanner runner, service/port discovery, template execution, AI provider, credential storage, remediation, or automatic report uploads. Any future active scanner requires a separately reviewed runner, explicit authorized targets, vetted templates, rate/time limits and cancellation. Existing device history remains an independent discovery feature.
