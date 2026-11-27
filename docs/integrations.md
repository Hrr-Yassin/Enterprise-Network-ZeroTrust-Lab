# Integration interfaces

## Existing SOC lab

The operator API returns a versioned deployment's status snapshot at `/api/status`. The passive sensor writes bounded DNS, connection and canary data. The edge provides rate-limited verdict records, and services record certificate role decisions. A SOC pipeline can ingest sanitized JSON and event exports offline. Use `evidence/telemetry.json`, `firewall-events.log` and `identity-events.jsonl` as schema examples. Keep a future live collector on a purpose-built lab link with its own authorization.

## Existing Active Directory lab

The current authorization boundary accepts client certificates and per-service fingerprints. A future, separately approved exercise can map the lab's Employee and Operator roles to AD groups using a read-only identity proxy or enrollment service. Use LDAPS with the AD lab's verified CA, a scoped bind identity, and explicit resolver and directory flows. Keep the service CA, peer identities, and default-deny routing independent. The current profile uses only local fixture identities.

## Suricata and Zeek

The repository ships a [Suricata canary rule](../monitoring/local.rules), [capture template](../monitoring/suricata.yaml) and [Zeek JSON logging profile](../monitoring/isolated.zeek). The intended live input is the guest Monitor namespace's `mon0` interface. It receives cloned ingress traffic and has no IP address.

With locally installed engines, first run the fixed capture replay. It reads the one-packet portfolio capture and checks its manifest hash before launching either engine.

```sh
python3 monitoring/replay.py all
```

For live validation, supply the engines inside the detached guest. Use Suricata in passive capture mode on `mon0` with the local canary rule. Point Zeek at the same interface in a separate writable log directory. Disable checksum enforcement for evidence capture offloads where necessary. Confirm the Suricata EVE alert ID `9900101`, Zeek's DNS question and connection output, and that neither process forwards traffic. Inline IPS needs a distinct deployment and acceptance profile.

## Prometheus and Grafana

The guest's `/metrics` endpoint exposes firewall, DNS, tap traffic, peer, link, service and policy signals. It accepts a metrics-scoped observer certificate. The [Prometheus scrape profile](../monitoring/prometheus.yml) uses the in-guest endpoint and verifies the TLS server name. The [alert rules](../monitoring/alerts.yml) evaluate service loss, drift and canary events. Grafana's [provisioning files](../monitoring/grafana-datasource.yml) and [dashboard](../monitoring/grafana.json) consume the local Prometheus instance.

Stage the CA certificate and observer certificate and key in the scrape profile's guest-only location with access restricted to the Prometheus service UID. Run a local Prometheus and Grafana instance in the guest sensor namespace, bind both to loopback, and provision Grafana with a unique operator password. Verify the Prometheus target state and dashboard datasource before crediting the optional deployment. The [assessment](assessment.md) records which monitoring engines were used during evidence collection.
