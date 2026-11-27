# Acceptance results

Run 20261127T024350258138Z passed 68 of 68 checks.
The suite tested 26 allowed protocol paths and 23 denied paths against the communication matrix.

| Check | Result | Observation |
| --- | --- | --- |
| guest_no_uplink | Pass | Root guest and edge have no default route, the WAN is a local bridge, and edge IPv6 is disabled |
| wan_web_tcp | Pass | HTTP 200; DNAT backend saw 192.0.2.20; allow counter +1 |
| wan_vpn_user_udp | Pass | user_vpn authenticated and used its assigned service; allow counter +1 |
| wan_vpn_ops_udp | Pass | ops_vpn authenticated and used its assigned service; allow counter +1 |
| employee_app_tcp | Pass | HTTP 200; allow counter +1 |
| employee_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| employee_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| employee_egress_tcp | Pass | HTTP 200; SNAT backend saw 192.0.2.1; allow counter +1 |
| dmz_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| dmz_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| guest_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| guest_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| guest_egress_tcp | Pass | HTTP 200; SNAT backend saw 192.0.2.1; allow counter +1 |
| admin_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| admin_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| admin_ops_tcp | Pass | HTTP 200; allow counter +1 |
| admin_vault_tcp | Pass | HTTP 200; allow counter +1 |
| admin_dashboard_tcp | Pass | HTTP 200; allow counter +1 |
| user_app_tcp | Pass | HTTP 200; allow counter +1 |
| user_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| user_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| ops_dns_udp | Pass | DNS UDP returned 10.77.30.10; allow counter +1 |
| ops_dns_tcp | Pass | DNS TCP returned 10.77.30.10; allow counter +1 |
| ops_admin_tcp | Pass | HTTP 200; allow counter +1 |
| ops_vault_tcp | Pass | HTTP 200; allow counter +1 |
| ops_dashboard_tcp | Pass | HTTP 200; allow counter +1 |
| sensor_app_health_tcp | Pass | HTTP 200; allow counter +1 |
| wan_direct_dmz | Pass | Timed out at 10.77.10.10:443; deny_forward +1 |
| wan_private_app | Pass | Timed out at 10.77.30.10:8443; deny_forward +1 |
| wan_unknown_peer | Pass | Timed out at 192.0.2.1:51820; deny_input +1 |
| dmz_private_app | Pass | Timed out at 10.77.30.10:8443; deny_forward +1 |
| dmz_admin | Pass | Timed out at 10.77.30.10:9443; deny_forward +1 |
| dmz_egress | Pass | Timed out at 192.0.2.80:8080; deny_forward +1 |
| employee_ops | Pass | Timed out at 10.77.30.10:9443; deny_forward +1 |
| employee_monitor | Pass | Timed out at 10.77.60.10:8443; deny_forward +1 |
| employee_vault | Pass | Timed out at 10.77.30.130:8443; deny_forward +1 |
| guest_app | Pass | Timed out at 10.77.30.10:8443; deny_forward +1 |
| guest_dmz | Pass | Timed out at 10.77.10.10:443; deny_forward +1 |
| guest_monitor | Pass | Timed out at 10.77.60.10:8443; deny_forward +1 |
| guest_admin | Pass | Timed out at 10.77.30.10:9443; deny_forward +1 |
| guest_direct_dns_udp | Pass | Timed out at 192.0.2.80:53; deny_forward +1 |
| guest_direct_dns_tcp | Pass | Timed out at 192.0.2.80:53; deny_forward +1 |
| guest_egress_other_port | Pass | Timed out at 192.0.2.80:8081; deny_forward +1 |
| vpn_user_ops | Pass | Timed out at 10.77.30.10:9443; deny_forward +1 |
| vpn_user_vault | Pass | Timed out at 10.77.30.130:8443; deny_forward +1 |
| vpn_user_monitor | Pass | Timed out at 10.77.60.10:8443; deny_forward +1 |
| vpn_ops_guest | Pass | Timed out at 10.77.70.10:8080; deny_forward +1 |
| app_to_vault | Pass | Timed out at 10.77.30.130:8443; deny_forward +1 |
| vault_to_app | Pass | Timed out at 10.77.30.10:8443; deny_forward +1 |
| sensor_admin | Pass | Timed out at 10.77.30.10:9443; deny_forward +1 |
| unassigned_ingress_source | Pass | The edge dropped a test packet sourced from an unassigned Guest address |
| edge_unsolicited_output | Pass | Denied a new connection from the firewall to the closed WAN simulator |
| mtls_certificate_required | Pass | - returned rejected (TLSV13_ALERT_CERTIFICATE_REQUIRED) |
| mtls_untrusted_ca | Pass | foreign returned rejected (TLSV1_ALERT_UNKNOWN_CA) |
| mtls_valid_certificate_without_role | Pass | unassigned returned 403 |
| mtls_wrong_role | Pass | employee returned 403 |
| mtls_admin_credential_from_guest | Pass | Operator certificate could not reach the management endpoint from Guest |
| mtls_observer_data_denied | Pass | observer returned 403 |
| tls_service_hostname_mismatch | Pass | employee returned certificate_error (Hostname mismatch, certificate is not valid for 'wrong.lab.test'.) |
| mtls_role_revocation | Pass | Removed certificate fingerprint, observed HTTP 403, preserved other role and restored HTTP 200 |
| wireguard_individual_revocation | Pass | Removed one peer from live WireGuard; that peer lost access, ops remained active, then reauthorized |
| dns_no_external_recursion | Pass | External namespace returned DNS RCODE 5 with no answers |
| invalid_policy_rejected | Pass | Kernel validation rejected an invalid candidate and the active policy was preserved |
| backup_restore_and_drift | Pass | Detected removal of one permit, observed denial, restored the kernel ruleset snapshot and connectivity |
| application_failure_and_recovery | Pass | Stopped the app, measured unavailability, restored it and measured a healthy response |
| mirrored_dns_and_canary_alert | Pass | A mirrored Ethernet frame produced one tcpdump record, a DNS telemetry record and a canary alert |
| operator_dashboard_and_metrics | Pass | Verified authorized HTTPS and metrics responses against live data, including DENY and ALLOW logs |
| chromium_dashboard_render | Pass | Chromium rendered a 1440 × 1120 PNG from the dashboard HTML fetched through authorized guest HTTPS |
