# Threat model

## Assets and assumptions

Protect the restricted service, management endpoints, DNS integrity, service and peer keys, and evidence provenance. The host user and the guest serial-console operator control provisioning. WAN and Guest clients are untrusted. Employee clients and authenticated VPN devices can be compromised. The workload fixtures are test services with synthetic data.

| Threat | Control | Residual risk |
| --- | --- | --- |
| WAN path into private services | Detached VM, default-deny edge, one source-scoped DMZ DNAT | Anyone with guest-console control has access to lab state |
| Lateral movement from DMZ, Guest, or either server tier | Routed veth boundaries, explicit destination and port rules, source validation | A compromised kernel controls all namespaces in this guest |
| Unauthorized management | Admin and operator overlay permit distinct management paths, with an operator certificate required by each service | Theft of a current operator key still requires an authorized path and permits that role's operations |
| Source-address spoofing on a wired segment | Edge matches source IP and ingress interface | A device controlling its own allowed endpoint can still send from that endpoint |
| VPN key leak or removal | Independent peer keys and `/32` source mapping, live peer removal, independent app authentication | No MFA or automated key replacement service |
| Improper certificate use | Separate service/client CAs, TLS 1.3, hostname checks, per-service fingerprint authorization | Guest fixture issuance lacks enterprise enrollment, external revocation distribution and hardware key protection |
| DNS bypass or external egress | Local-only resolver and source, destination and port policies | Application-layer tunneling through an authorized service is outside the fixture model |
| Policy error or drift | Model checks, kernel validation, atomic transactions, backup/restore and live fingerprint | Already established conntrack entries may survive policy-only edits until flows expire |
| Monitoring visibility loss | Mirrored ingress, bounded flow and DNS telemetry, active probes and firewall events | Encrypted payloads, heavily loaded collectors and a compromised sensor can limit visibility |
| Sensitive evidence disclosure | Artifact allowlist, one canary packet, synthetic addresses and namespace roles, private raw run logs | Review new fixtures and their outputs before exporting evidence |

## Recovery assumptions

The guest is disposable and generates fresh credentials on restart. The key store, fixture state and operational snapshots live in RAM. Export an approved sanitized firewall snapshot before guest shutdown if cross-boot comparison is required. Production changes to a routed environment would need persistence, rollback state, time synchronization, and separate administrative authentication.
