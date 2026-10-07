# NEXVARY NetScan — v0.1

## User workflow
1. Open the Windows app.
2. Click **اكتشاف الأجهزة**.
3. The app selects the active IPv4 adapter automatically.
4. It scans the local subnet and combines ICMP reachability with Windows ARP resolution.
5. Results show IP, MAC, host name, device type and status.
6. Search, copy selected/all rows, or export CSV.

## Safety and scope
- Local network discovery only.
- No port exploitation, credential guessing, or remote modification.
- No administrator rights are required for the normal discovery flow.
- Large address spaces are capped to a local /24 scan to avoid accidental broad scanning.

## Planned follow-ups
- Offline OUI/vendor identification database.
- Friendly device names and notes saved locally.
- Optional device history (first seen / last seen).
- Signed installer after the core scan is validated on physical networks.
