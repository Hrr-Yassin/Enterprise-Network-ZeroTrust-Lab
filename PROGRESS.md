# Project progress

## 2026-11-27 UTC

- Inspected the Fedora environment, available resources and installed tooling. The session can read host kernel and package metadata. Its host netlink and libvirt calls are denied, and the session has no visible `/dev/kvm`. The exposed SELinux enforcement file reads `1`.
- Proved a direct QEMU PC guest boots a readable local Fedora kernel and powers off without a NIC. Implemented ten segments, routed point-to-point links, a simulated WAN bridge and the default-deny nftables edge in that guest.
- Provisioned isolated application, DNS, upstream and dashboard services. Implemented independent WireGuard and client-certificate identities and a mirrored packet sensor.
- The first full execution passed all 26 allowed protocol paths and 23 denied paths. The tcpdump reader needed an explicit guest user, and the Brave render reached its time limit. Fixed the decoder and selected the locally cached Chromium Headless Shell for the evidence run.
- Created the source and generated views of policy, the acceptance suite, a local deployment playbook and the standalone Git repository. The [assessment](docs/assessment.md) records the outcome of runtime checks and the local dependency gaps.
- Run `20261127T022719875248Z` passed all 68 checks. Reviewed the 1440 × 1120 Chromium screenshot, decoded the one-packet canary capture, verified 11 artifact digests and cross-checked all 49 matrix paths. The weighted score is 90/100. Suricata and Zeek replay reported missing local binaries.
- Booted the 640 MiB profile in live mode. The serial-console rollback commands reproduced the expected firewall hash. The operator dashboard returned HTTP 200 with six healthy services, and the guest reported mode `0600` for nine client and VPN keys.
