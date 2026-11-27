# Project goals

Build an operational Enterprise Network Security and Zero Trust lab and assess it against a 90/100 portfolio threshold. Give credit for implemented controls supported by runtime evidence.

- Route a simulated WAN, DMZ, Employee, Server, Identity, Admin, Monitoring, Guest and VPN through a stateful edge. Separate the two server tiers and show the resulting policy decisions.
- Require service authentication and role authorization on private HTTPS endpoints. Use independent WireGuard identities for standard and privileged remote access.
- Record firewall decisions, mirrored TCP and DNS traffic, a synthetic alert and service health. Verify the dashboard and the reachability of its management paths.
- Provision and validate using versioned automation and local tools. Exercise rollback, drift, revocation and service recovery through the same entry points.
- Prepare a standalone `Enterprise-Network-ZeroTrust-Lab` Git repository with reproducible deployment and reviewed evidence.

All active validation takes place in the detached guest. Existing host and project networks stay outside the lab. The [assessment](docs/assessment.md) records the scored results.
