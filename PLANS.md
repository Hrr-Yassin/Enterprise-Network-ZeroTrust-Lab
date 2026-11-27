# Milestones

| Priority | Delivery | Validation gate |
| --- | --- | --- |
| 1 | Preflight, isolated topology, stateful firewall and policy model | Boot with no host NIC, bring links up, load the transaction and inspect routes |
| 2 | Internal DNS, application mTLS, operator authorization and WireGuard | Exercise each allowed protocol and selected denied flow, then revoke an app role and a VPN peer |
| 3 | Tap, traffic telemetry, firewall events, availability and dashboard | Capture the lab DNS canary, verify the sensor alert and denied-flow visibility, validate authenticated dashboard data and render it |
| 4 | Reproducible automation, change control and recovery | Test invalid input, baseline drift, kernel ruleset restore and application restart |
| 5 | Portfolio and evidence review | Export allowlisted artifacts, review the packet and screenshot, assess the weighted criteria and verify the local repository |

Named monitoring engines and Ansible execution depend on availability of local packages. Record their actual execution status separately from Python acceptance.
