# Milestones

| Priority | Delivery | Validation gate |
| --- | --- | --- |
| 1 | Preflight, isolated topology, stateful firewall and policy model | Boot with no host NIC, bring links up, load the transaction and inspect routes |
| 2 | Internal DNS, application mTLS, operator authorization and WireGuard | Exercise each allowed protocol and selected denied flow, then revoke an app role and a VPN peer |
| 3 | Suricata, Zeek, the mirror, Prometheus and Grafana | Correlate the canary, verify a scoped inline drop and rollback, measure the mTLS scrape and alert, query every Grafana panel, and render both dashboard views in headed Chromium |
| 4 | Python and Ansible automation, change control and recovery | Test dry run, apply and idempotence, baseline drift, kernel ruleset restore and application restart |
| 5 | Portfolio and evidence review | Export allowlisted artifacts, review the packet and screenshot, assess the weighted criteria and verify the local repository |

Record the targeted engine and Ansible checks separately from the 68 baseline results.
