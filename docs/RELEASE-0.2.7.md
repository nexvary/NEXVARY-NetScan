# NEXVARY NetScan 0.2.7

- Organized dark Arabic workspace, separate toolbar, eight network cards and colored vector icons.
- High-resolution application icon and consistent dark tabs, selected rows and scrollbars.
- Interface-bound SendARP, repeated MAC resolution, merged native ARP and Windows neighbor sources, invalid/multicast filtering.
- Offline IEEE vendor database with 9,593 records; private MACs are identified without guessing a vendor.
- Refresh checks known addresses; full discovery scans the local subnet (active sweep capped to local /24 for large networks).
- IPv4 DNS reflects this computer's adapter configuration. Other devices' DNS is left unavailable because ARP/ICMP cannot retrieve their configuration.
- Improved history identity and first-seen preservation, confirmed delete handling and DNS history column.
- Self-contained Windows x64 portable executable and Inno Setup installer.
- CI verifies unit tests, WPF startup, icon and row rendering, dark tabs, installed startup, modal error detection, repeat installation and uninstall.

Real-device discovery still depends on LAN isolation, reachable Layer-2 neighbors and device behavior. Wi-Fi SSID and network profile are not reported without a reliable source. UI verification uses explicitly labeled fixture data.
