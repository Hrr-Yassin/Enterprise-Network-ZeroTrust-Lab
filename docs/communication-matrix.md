# Authorized communication matrix

Source of truth is [config/lab.json](../config/lab.json). The edge drops other new flows and permits stateful replies.

| Policy row | Source | Destination as seen by client | Transport | Decision | Constraint |
| --- | --- | --- | --- | --- | --- |
| wan_web | outside | public_web at 192.0.2.1:443 | tcp | Allow | DNAT |
| wan_vpn_user | remote_user | vpn at 192.0.2.1:51820 | udp | Allow | — |
| wan_vpn_ops | remote_ops | vpn at 192.0.2.1:51820 | udp | Allow | — |
| employee_app | employee | app at 10.77.30.10:8443 | tcp | Allow | employee |
| employee_dns | employee | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| employee_egress | employee | egress at 192.0.2.80:8080 | tcp | Allow | SNAT |
| dmz_dns | web | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| guest_dns | guest | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| guest_egress | guest | egress at 192.0.2.80:8080 | tcp | Allow | SNAT |
| admin_dns | admin | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| admin_ops | admin | ops at 10.77.30.10:9443 | tcp | Allow | operator |
| admin_vault | admin | vault at 10.77.30.130:8443 | tcp | Allow | operator |
| admin_dashboard | admin | dashboard at 10.77.60.10:8443 | tcp | Allow | operator |
| user_app | user_vpn | app at 10.77.30.10:8443 | tcp | Allow | remote_user |
| user_dns | user_vpn | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| ops_dns | ops_vpn | dns at 10.77.40.10:53 | udp, tcp | Allow | — |
| ops_admin | ops_vpn | ops at 10.77.30.10:9443 | tcp | Allow | operator |
| ops_vault | ops_vpn | vault at 10.77.30.130:8443 | tcp | Allow | operator |
| ops_dashboard | ops_vpn | dashboard at 10.77.60.10:8443 | tcp | Allow | operator |
| sensor_app_health | monitor | app at 10.77.30.10:8443 | tcp | Allow | observer, /health |
| wan_direct_dmz | outside | public_web at 10.77.10.10:443 | tcp | Drop | — |
| wan_private_app | outside | app at 10.77.30.10:8443 | tcp | Drop | — |
| wan_unknown_peer | outside | vpn at 192.0.2.1:51820 | udp | Drop | — |
| dmz_private_app | web | app at 10.77.30.10:8443 | tcp | Drop | — |
| dmz_admin | web | ops at 10.77.30.10:9443 | tcp | Drop | — |
| dmz_egress | web | egress at 192.0.2.80:8080 | tcp | Drop | — |
| employee_ops | employee | ops at 10.77.30.10:9443 | tcp | Drop | — |
| employee_monitor | employee | dashboard at 10.77.60.10:8443 | tcp | Drop | — |
| employee_vault | employee | vault at 10.77.30.130:8443 | tcp | Drop | — |
| guest_app | guest | app at 10.77.30.10:8443 | tcp | Drop | — |
| guest_dmz | guest | public_web at 10.77.10.10:443 | tcp | Drop | — |
| guest_monitor | guest | dashboard at 10.77.60.10:8443 | tcp | Drop | — |
| guest_admin | guest | ops at 10.77.30.10:9443 | tcp | Drop | — |
| guest_direct_dns_udp | guest | dns at 192.0.2.80:53 | udp | Drop | — |
| guest_direct_dns_tcp | guest | dns at 192.0.2.80:53 | tcp | Drop | — |
| guest_egress_other_port | guest | egress at 192.0.2.80:8081 | tcp | Drop | — |
| vpn_user_ops | user_vpn | ops at 10.77.30.10:9443 | tcp | Drop | — |
| vpn_user_vault | user_vpn | vault at 10.77.30.130:8443 | tcp | Drop | — |
| vpn_user_monitor | user_vpn | dashboard at 10.77.60.10:8443 | tcp | Drop | — |
| vpn_ops_guest | ops_vpn | egress at 10.77.70.10:8080 | tcp | Drop | — |
| app_to_vault | api | vault at 10.77.30.130:8443 | tcp | Drop | — |
| vault_to_app | vault | app at 10.77.30.10:8443 | tcp | Drop | — |
| sensor_admin | monitor | ops at 10.77.30.10:9443 | tcp | Drop | — |
