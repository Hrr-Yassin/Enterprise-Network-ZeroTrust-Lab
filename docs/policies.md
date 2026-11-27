# Firewall, identity and remote access

## Stateful edge

- Default-drop IPv4 policy applies to new input, forwarded and output traffic at the edge. Conntrack permits established and related replies. The edge drops invalid state.
- Ingress source checks bind each lab interface to its assigned endpoint addresses. WireGuard also authenticates inner source addresses through per-peer `/32` AllowedIPs.
- Each permit uses a named counter and a rate-limited kernel decision log. The discard chains distinguish denied input, forwarding and output traffic. A separate counter records invalid state and unassigned sources.
- WAN publication requires destination NAT to the public DMZ service on TCP 443. Guest and Employee source NAT is confined to the simulated upstream service on TCP 8080.
- Approved clients use the Identity resolver over UDP and TCP 53. dnsmasq serves `lab.test` from local fixtures and has no upstream resolvers. The firewall blocks direct external DNS from Guest and blocks additional upstream destinations and ports.
- Every namespace uses IPv4. The edge disables IPv4 redirects. No physical interface, container network, host firewall or existing VM is part of the edge.

The reviewed policy is [config/lab.json](../config/lab.json). The generated nftables file is included for review. The controller loads rules in the guest edge namespace only. It first asks the kernel to validate the transaction, then applies it atomically. [Edge rules](../config/edge.nft)

## Identity and resource authorization

The CA that signs services is distinct from the CA that signs clients. TLS 1.3 clients verify the service CA and DNS name. Private services require a client certificate from the client CA and authorize its SHA-256 certificate fingerprint per resource. Employee and remote-user certificates open the app. The operator certificate opens management, the restricted tier and the dashboard from an approved network path. The observer certificate can read application health and dashboard metrics.

Each guest boot issues a fresh two-day set of fixture certificates. Keys remain in guest RAM with restricted permissions. Per-service keys belong to a dedicated UID. The controller removes issuer private keys after provisioning. Revocation removes a fingerprint from the service authorization file, which the service rereads on each request.

| Option | Decision and validation |
| --- | --- |
| FreeRADIUS | Evaluated for managed switch access through 802.1X. The lab focuses on routed controls and application authorization. |
| Mutual TLS | Implemented at each private HTTPS service with separate roles and service identity checks. |
| Certificates | Client and server certificates are short-lived and scoped by extended key usage. Acceptance covers invalid trust, wrong service name, missing certificate, unauthorized roles and fingerprint revocation. |
| Identity-aware proxy | Evaluated for future IdP and user-session integration. The service itself performs certificate and resource authorization in the current deployment. |

The guest authenticates possession of WireGuard and TLS keys. Endpoint posture, user MFA, enterprise identity federation and hardware-backed enrollment are outside the current profile.

## WireGuard access policy

| Peer identity | Permitted traffic after tunnel establishment |
| --- | --- |
| Standard user | App over mTLS and lab DNS |
| Operator | Management HTTPS, restricted service, dashboard and lab DNS |

Each peer has a private key generated in the guest and a unique tunnel address. A transport allowlist accepts handshakes from the two simulated WAN clients. The dashboard shows handshake recency and transfer counts under peer names. Removing a peer from the live interface stops its traffic and preserves the other peer's session. Operational revocation of a person should address the separate WireGuard and mTLS identities.

## Monitoring policy

The monitor receives copied ingress traffic, kernel verdicts and interface counters. Active health checks use the authorized source namespaces. The passive sensor observes IPv4 TCP SYNs, UDP DNS questions and a single synthetic DNS signature. The exported capture contains one request for `ids-check.lab.test`. Its filters and decoded output are part of the evidence.
