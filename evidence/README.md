# Evidence index

| Evidence | Scope |
| --- | --- |
| [Run manifest](manifest.json) | Execution profile, resource use, policy fingerprint and artifact SHA-256 digests |
| [Acceptance results](results.md) and [test data](checks.json) | Per-check outcomes and executable coverage of policy rows |
| [Network status](network.json) | Guest-only segment state and boot-time policy hash |
| [Telemetry](telemetry.json) and [dashboard](dashboard.html) | Network, firewall, service and VPN measurements |
| [Dashboard screenshot](dashboard.png) | Chromium rendering of the authorized dashboard response |
| [Firewall events](firewall-events.log) and [identity events](identity-events.jsonl) | Filtered guest verdicts and fixture role decisions |
| [VPN events](vpn-events.jsonl) | Handshake and revocation observations under local peer labels |
| [Restored firewall rules](firewall-backup.nft) | Guest kernel ruleset captured and restored during the acceptance run |
| [Canary capture](synthetic-dns.pcap) and [tcpdump decode](packet-summary.txt) | One synthetic DNS request from the guest monitor tap |
| [Live operator output](live-operations.txt) | Supplementary console check of firewall commands, the private dashboard and key file modes |

The packet capture contains reserved lab addresses and the canary name `ids-check.lab.test`. The project generates credentials for each boot. Exported evidence uses fixture labels and omits WireGuard keys, certificate fingerprints, raw boot output and real host addresses.
