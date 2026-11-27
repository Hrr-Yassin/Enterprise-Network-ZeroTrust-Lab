# Acceptance results

Run 20261127T102856682265Z passed 5 of 5 checks.
Targeted integration evidence for the selected lab extensions.

| Check | Result | Observation |
| --- | --- | --- |
| suricata_zeek_live | Pass | Suricata 8.0.8 matched SID 9900101. Zeek 9.0.1 correlated the DNS and UDP connection records. |
| chromium_live_dashboards | Pass | Headed Chromium rendered the live Grafana dashboard and authenticated operator dashboard on the guest display |
| prometheus_grafana_live | Pass | Prometheus scraped the mTLS endpoint and Grafana served live data for every provisioned panel |
| suricata_inline_prevention | Pass | Suricata allowed ordinary DNS and blocked the synthetic canary inline. Removed the queue and verified recovery. |
| ansible_guest_execution | Pass | Ansible Core 2.22.0 checked and recorded the live guest policy and repeated with zero changes |
