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
| [Host inventory](host-inventory.json) | Read-only SELinux, KVM, route overlap and libvirt counts with host identifiers omitted |
| [Follow-up host observations](host-preservation.json) | Aggregate inventory and SELinux state from read-only checks |
| [Targeted results](add-ons/results.md) and [manifest](add-ons/manifest.json) | Named-engine acceptance, unchanged policy fingerprint and artifact integrity |
| [IDS detection](add-ons/ids-observations.json) and [inline prevention](add-ons/ips-observations.json) | Live Suricata alert and blocked verdict, Zeek DNS and connection correlation, and queue rollback |
| [Prometheus and Grafana](add-ons/observability.json) | mTLS scrape, firing canary alert, authenticated data queries and 11 panel results |
| [Grafana](add-ons/grafana.png), [operator dashboard](add-ons/dashboard-visible.png) and [browser observations](add-ons/browser-observations.json) | Headed Chromium display with live Grafana requests and the authorized operator response |
| [Ansible controller](ansible-controller.json) and [guest play](add-ons/ansible-observations.json) | Local check mode, detached provisioning, and guest check, apply and idempotent repeat |
| [Enrollment lifecycle](identity-lifecycle.json) | Fresh TLS and WireGuard credentials authenticated on two independent boots |
| [Dependency provenance](dependency-provenance.json) | Verified RPM signatures and release and wheel checksums |

The packet capture contains reserved lab addresses and the canary name `ids-check.lab.test`. The project generates credentials for each boot. Exported evidence uses fixture labels and omits WireGuard keys, certificate fingerprints, raw boot output and real host addresses.
