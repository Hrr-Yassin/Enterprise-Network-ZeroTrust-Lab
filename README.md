# Enterprise Network Zero Trust Lab

A reproducible network security lab for Fedora x86-64. A disposable QEMU guest contains a simulated WAN, nine enterprise and VPN segments, a stateful nftables edge, service-level mTLS, two WireGuard peers, and a passive monitoring interface. Three independent controls can decide an app request. The edge checks the network path, TLS checks the service and client certificates, and the service authorizes the identity for the resource.

The QEMU guest starts without a virtual NIC. The WAN is an Ethernet bridge inside the guest. Every service, test target, and packet capture remains inside that guest.

**Verified portfolio readiness is 100/100 on the requested lab rubric.** The KVM baseline passed 68 checks, including all 49 communication-matrix paths. The targeted integration run passed five additional checks and preserved the baseline firewall fingerprint. TLS and WireGuard identities also authenticated after fresh enrollment on two independent boots. [Security assessment](docs/assessment.md)

Suricata detected the mirrored DNS canary and blocked it in a scoped inline exercise. Zeek correlated the DNS and connection records. Prometheus scraped via mTLS and fired the canary alert, Grafana returned live data for all 11 panels, and Ansible applied and checked the guest policy idempotently. Both dashboard views were rendered with headed Chromium in the guest. [Targeted results](evidence/add-ons/results.md)

## Run the lab

Use a readable Fedora kernel under `/boot` with matching modules and local Fedora packages for QEMU, BusyBox, cpio, gzip, kmod, iproute, iproute-tc, nftables, wireguard-tools, dnsmasq, OpenSSL, tcpdump and Python 3. The build uses local binaries and packages. See the deployment guide for the package and resource requirements.

```sh
python3 labctl.py plan
python3 labctl.py verify
python3 labctl.py report
```

Use `python3 labctl.py live` to bring up the services and open the guest console. To render a dashboard screenshot during verification, run `python3 labctl.py verify --browser --timeout 420` with a local Chromium Headless Shell installation.

Use the targeted workflow to verify Suricata, Zeek, Prometheus, Grafana, Ansible, and headed Chromium from verified local packages. It records its own evidence without rerunning the communication matrix. [Targeted commands](docs/operations.md#targeted-extension-verification) · [Dependency receipt](evidence/dependency-provenance.json)

| Project material | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Topology, address plan, trust boundaries, routing and data flows |
| [Communication matrix](docs/communication-matrix.md) | Allowed paths and selected default-deny probes with evidence IDs |
| [Policy and identities](docs/policies.md) | Stateful firewall, NAT, DNS, TLS authorization, VPN and sensor design |
| [Deployment and recovery](docs/operations.md) | Reproduction, inspection, firewall validation, backup, restore and evidence export |
| [Threat model](docs/threat-model.md) | Assets, threats, mitigating controls and residual risk |
| [Integration interfaces](docs/integrations.md) | SOC and AD extension points and optional monitoring tools |
| [Security assessment](docs/assessment.md) | Weighted readiness, validation findings and remaining gaps |
| [Acceptance results](evidence/results.md) | Per-check observations and coverage of the communication matrix |

## Source and evidence

- [Policy model](config/lab.json) and [generated edge rules](config/edge.nft)
- [Python controller](labctl.py) and [Ansible playbook](automation/site.yml)
- [Run manifest](evidence/manifest.json), [firewall events](evidence/firewall-events.log), [role decisions](evidence/identity-events.jsonl), and [one-packet synthetic DNS capture](evidence/synthetic-dns.pcap)
- [Live Grafana in Chromium](evidence/add-ons/grafana.png) and [operator dashboard in Chromium](evidence/add-ons/dashboard-visible.png)

The [handoff](HANDOFF.md) documents the local repository and evidence export. The source is available under the [MIT License](LICENSE).
