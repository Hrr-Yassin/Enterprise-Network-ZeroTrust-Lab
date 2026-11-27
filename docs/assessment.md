# Security assessment

Assessment date 2026-11-27 UTC. The evidence is tied to the execution and artifact hashes in the [run manifest](../evidence/manifest.json). The [acceptance report](../evidence/results.md) records each result against its policy row or control.

## Environment and test boundary

The host was Fedora 45 on x86-64, with eight logical CPUs, 31 GiB of RAM and 38 GiB available in the workspace filesystem during initial preflight. Local inspection found QEMU, libvirt, GNS3 and Podman. The follow-up read-only host inspection confirmed SELinux Enforcing, an accessible KVM device, five powered-off libvirt domains and six libvirt networks. No lab segment overlapped with a non-default IPv4 host route or inspected libvirt IPv4 prefix. [Sanitized host inventory](../evidence/host-inventory.json)

All active validation used the detached QEMU guest. The guest edge had connected routes only, the simulated WAN was internal to the guest, and the source and destination addresses belonged to the fixtures. Kernel policy validation, nftables counters, TCP and UDP service responses, TLS decisions, WireGuard handshakes and the monitored packet are independent data sources.

## Scoring

**90/100 on the requested rubric.** This score covers the verified guest and its evidence. The requested Suricata and Zeek deployments remain open.

| Criterion | Score | Observed results and deductions |
| --- | ---: | --- |
| Network architecture | 15/15 | Ten live segments, connected routing without a guest uplink, isolated WAN and separate server tiers. The matrix matches the source policy. |
| Firewall and segmentation | 20/20 | All 26 allowed protocol paths and 23 denied paths were checked against live named counters. The run verified default denial, anti-spoofing, stateful replies, DNAT, restricted SNAT, DNS and kernel ruleset rollback. |
| Zero Trust and identity security | 18/20 | Independent WireGuard and mTLS identities, role and resource access, trusted hostname verification, and revocation at both layers. Enrollment and credential lifecycle across guest boots lack validation. |
| Network monitoring | 9/15 | The tap delivered the expected DNS and denied TCP traffic. Kernel decisions, a synthetic canary, availability, latency and dashboard output are recorded. Suricata, Zeek, Prometheus and Grafana receive zero credit. |
| Infrastructure automation | 8/10 | Verified offline build, provisioning, policy deployment and validation, connectivity, backup, drift and reporting through Python. Ansible execution receives zero credit. |
| Real validation and evidence | 10/10 | 68 executable checks passed. The manifest, role and firewall events, narrow PCAP and Chromium screenshot were reviewed. |
| GitHub portfolio quality | 10/10 | The standalone local repository has versioned configuration, reproduction and recovery instructions, a threat model, sanitized evidence and an MIT license. |

## Verified run and resource use

The KVM screenshot profile ran for **51.84 seconds** with two vCPUs and 1,536 MiB allocated guest RAM. Peak QEMU resident memory was **893,624 KiB**. The compressed initramfs was **147,708,479 bytes**. The base guest allocates 640 MiB and uses no persistent virtual disk. The verification guest powered off after emitting its run evidence. [Run manifest](../evidence/manifest.json)

The dashboard sample showed 10 up links, six available service probes, two recent WireGuard handshakes, 849 mirrored packets, 60 observed TCP flows and a canary alert. The firewall's counters are scoped to the active ruleset and restart at zero on a ruleset reload. Kernel decisions and the acceptance report preserve earlier policy outcomes. [Dashboard screenshot](../evidence/dashboard.png)

A separate 640 MiB live boot verified the operator commands and dashboard probe. Backup, validation and restore preserved the firewall fingerprint. The operator API returned HTTP 200 with six healthy services, and all nine fixture client and VPN key files had mode `0600`. The base initramfs was 29,414,213 bytes. [Live operator output](../evidence/live-operations.txt)

## Remaining scope

- The offline guest profiles cover live Suricata and Zeek capture, Prometheus scraping and Grafana provisioning. Live engine acceptance still requires the local release files. The baseline capture and dashboard use nftables logs, tcpdump and the lab's passive sensor.
- The Ansible launcher accepts a local `ansible-core` wheelhouse and can validate the chosen guest profiles in check mode. Running the playbook requires `ansible-core` and its dependencies.
- The admin control plane is the guest serial console. Operating system compromise in the guest can affect all namespaces. Fixture keys are volatile and the environment omits enterprise enrollment, hardware-backed device posture, 802.1X and identity federation.
- The lab uses a closed IPv4 WAN with fixed transport addresses. The passive parser's demonstrated coverage is Ethernet TCP SYNs and UDP DNS requests. VPN visibility comes from WireGuard state and inner-flow firewall verdicts. Production scale, Internet transit, failover and inline IPS require separate scenarios.

The [operations guide](operations.md) includes the tested profile and reproduction commands. See the [integration guide](integrations.md) for the remaining monitoring and identity extension points.
