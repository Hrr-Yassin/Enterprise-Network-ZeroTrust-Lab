# Security assessment

Assessment date 2026-11-27 UTC. The [baseline](../evidence/results.md) records the communication matrix and core controls. The [targeted integration run](../evidence/add-ons/results.md) records the named monitoring engines, headed Chromium and guest Ansible. Each run has its own artifact hashes.

## Environment and test boundary

The host was Fedora 45 on x86-64, with eight logical CPUs, 31 GiB of RAM and 38 GiB available in the workspace filesystem during initial preflight. Local inspection found QEMU, libvirt, GNS3 and Podman. The follow-up read-only host inspection confirmed SELinux Enforcing, an accessible KVM device, five powered-off libvirt domains and six libvirt networks. No lab segment overlapped with a non-default IPv4 host route or inspected libvirt IPv4 prefix. [Sanitized host inventory](../evidence/host-inventory.json)

All active validation used the detached QEMU guest. The guest edge had connected routes only, the simulated WAN was internal, and the test addresses belonged to the fixtures. The integration run used the same policy digest and live firewall fingerprint as the baseline. The follow-up host reads confirmed SELinux Enforcing and recorded aggregate inventory changes between observations. The host commands queried inventory, and the guest had no host network attachment. [Targeted manifest](../evidence/add-ons/manifest.json) · [Follow-up host observations](../evidence/host-preservation.json)

## Scoring

**100/100 on the requested laboratory rubric.** The score covers the implemented lab scope and its observed acceptance results.

| Criterion | Score | Observed results |
| --- | ---: | --- |
| Network architecture | 15/15 | Ten live segments, connected routing without a guest uplink, isolated WAN and separate server tiers. The matrix matches the source policy. |
| Firewall and segmentation | 20/20 | All 26 allowed protocol paths and 23 denied paths were checked against live named counters. The run verified default denial, anti-spoofing, stateful replies, DNAT, restricted SNAT, DNS and kernel ruleset rollback. |
| Zero Trust and identity security | 20/20 | Independent WireGuard and mTLS identities, role and resource authorization, hostname verification and revocation. Two boots re-enrolled both roles and both peers with new public fingerprints and removed the issuer private keys. [Enrollment evidence](../evidence/identity-lifecycle.json) |
| Network monitoring | 15/15 | Suricata logged the mirrored canary and blocked it inline. Zeek correlated DNS and the connection log. Prometheus scraped via mTLS and fired the canary alert, and Grafana returned live data for all 11 panels. [Detection](../evidence/add-ons/ids-observations.json) · [Prevention](../evidence/add-ons/ips-observations.json) · [Observability](../evidence/add-ons/observability.json) |
| Infrastructure automation | 10/10 | Verified offline build, policy deployment, connectivity, backup, drift and reporting through Python. Ansible's localhost controller provisioned and checked the guest. Guest Ansible ran check, apply and an idempotent repeat. [Controller](../evidence/ansible-controller.json) · [Guest play](../evidence/add-ons/ansible-observations.json) |
| Real validation and evidence | 10/10 | 68 baseline and five targeted checks passed. Both headed Chromium views, the synthetic PCAP and the sanitized artifacts were reviewed. [Browser results](../evidence/add-ons/browser-observations.json) · [Baseline](../evidence/results.md) · [Targeted results](../evidence/add-ons/results.md) |
| GitHub portfolio quality | 10/10 | The standalone local repository has versioned configuration, reproduction and recovery instructions, a threat model, sanitized evidence and an MIT license. |

## Verified run and resource use

The KVM screenshot profile ran for **51.84 seconds** with two vCPUs and 1,536 MiB allocated guest RAM. Peak QEMU resident memory was **893,624 KiB**. The compressed initramfs was **147,708,479 bytes**. The base guest allocates 640 MiB and uses no persistent virtual disk. The verification guest powered off after emitting its run evidence. [Run manifest](../evidence/manifest.json)

The targeted KVM profile ran for **97.63 seconds** with two vCPUs and 4,096 MiB allocated guest RAM. Peak QEMU resident memory was **3,697,624 KiB**, and the compressed initramfs was **703,115,637 bytes**. The run used Suricata 8.0.8, Zeek 9.0.1, Prometheus 3.13.5, Grafana 13.3.2 and Ansible Core 2.22.0. Headed Chromium recorded ten successful UI data-source responses while rendering Grafana, then rendered the freshly authorized operator HTTPS response. [Run resources](../evidence/add-ons/manifest.json) · [Grafana screenshot](../evidence/add-ons/grafana.png) · [Operator screenshot](../evidence/add-ons/dashboard-visible.png)

The dashboard sample showed 10 up links, six available service probes, two recent WireGuard handshakes, 849 mirrored packets, 60 observed TCP flows and a canary alert. The firewall's counters are scoped to the active ruleset and restart at zero on a ruleset reload. Kernel decisions and the acceptance report preserve earlier policy outcomes. [Dashboard screenshot](../evidence/dashboard.png)

A separate 640 MiB live boot verified the operator commands and dashboard probe. Backup, validation and restore preserved the firewall fingerprint. The operator API returned HTTP 200 with six healthy services, and all nine fixture client and VPN key files had mode `0600`. The base initramfs was 29,414,213 bytes. [Live operator output](../evidence/live-operations.txt)

## Lab limitations

- The admin control plane is the guest serial console. A guest kernel compromise can affect all namespaces. Fixture identity state is volatile. Enterprise enrollment, hardware-backed posture, 802.1X and federation are extension points.
- The closed IPv4 WAN uses fixed simulator addresses. The inline IPS exercise covers the synthetic Employee-to-Resolver DNS path and verifies restoration. Production throughput, Internet transit, failover and broader inline deployment need separate scenarios.
- The headed browser uses a guest X11 display. It queries Grafana live and renders a fresh authenticated HTTPS response for the operator dashboard. Both screenshots retain the visible browser window.

The [operations guide](operations.md) includes the tested profile and reproduction commands. The [integration guide](integrations.md) documents the offline release layouts and optional SOC and Active Directory interfaces.
