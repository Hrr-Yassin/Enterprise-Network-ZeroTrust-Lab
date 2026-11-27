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

For live validation, extract trusted x86-64 Linux builds locally with the following layout.

```text
ids-bundle/
├── bin/
│   ├── suricata
│   └── zeek
├── share/zeek/     complete upstream Zeek script tree
└── lib/           additional runtime libraries, if needed (lib64 also accepted)
```

```sh
python3 labctl.py plan --ids-bundle /path/to/ids-bundle
python3 labctl.py verify-addons --ids-bundle /path/to/ids-bundle --timeout 500
```

The build stages the two verified engine binaries, the Zeek release script tree, and the compatible ELF dependency closure. Put any runtime SONAMEs missing from the Fedora library cache under `lib` in the IDS bundle. The tested Fedora bundle uses the Fedora `libnetfilter_queue` and Vectorscan RPMs for two such libraries. Use the same flag with `live` to start both passive engines.

Use `verify-addons` for the targeted engine checks. The guest waits for both captures to bind to the unaddressed `mon0` mirror. It then sends a synthetic DNS query from Employee. Suricata must log SID `9900101`, and Zeek must correlate the DNS and connection records by connection ID. A separate inline exercise temporarily queues only Employee-to-Resolver UDP DNS on the guest edge. It checks a normal answer, a blocked canary under SID `9900102`, and restoration of the firewall and DNS behavior after removing the queue.

## Prometheus and Grafana

The guest's `/metrics` endpoint exposes firewall, DNS, tap traffic, peer, link, service and policy signals. The [Prometheus scrape profile](../monitoring/prometheus.yml) uses a metrics-scoped client certificate and verifies the TLS server name. The [alert rules](../monitoring/alerts.yml) cover service loss, drift and canary events. Grafana loads the [provisioned data source](../monitoring/grafana-datasource.yml) and [dashboard](../monitoring/grafana.json).

Arrange trusted, locally extracted Linux x86-64 release files in this layout. Keep copies of the vendor release assets with the Grafana executable and use the release that provides the unified `grafana server` command.

```text
observability-bundle/
├── prometheus/
│   ├── prometheus
│   └── promtool
└── grafana/
    ├── bin/grafana
    ├── conf/defaults.ini
    ├── public/
    │   └── build/
    └── data/plugins-bundled/prometheus/
```

The host checks structure and ELF metadata with `readelf` and uses its local library cache to stage any Linux runtime dependencies. The bundle includes the Prometheus data-source backend and assets from the same verified Grafana release. The guest runs `promtool check config`, binds the two daemons to Monitor loopback and runs them under separate non-root accounts. The monitor certificate and the random Grafana operator password remain in guest-only runtime files.

```sh
python3 labctl.py plan --observability-bundle /path/to/observability-bundle
python3 labctl.py verify-addons --observability-bundle /path/to/observability-bundle --timeout 500
```

The targeted suite checks an mTLS scrape, a firing synthetic canary alert and live series for all provisioned Grafana panels. It issues authenticated backend data-source queries and checks that the dashboard API rejects an unauthenticated request. With the IDS bundle enabled, the scrape must contain actual Suricata alert and Zeek DNS and connection counts. A successful run adds `observability.json` with engine versions, binary hashes and the measured API results. [Grafana data-source API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/data_source/#query-a-data-source)

Use the same option with `live` to start both services with the lab. From that guest console, run `python3 -m lab.observability` to inspect the dashboard API after metrics have been collected.

Add `--visible-browser-dir` with the root of the signed Fedora Xvfb RPM extraction. It must contain `usr/bin/Xvfb`. The host also needs `xkbcomp`, `/usr/share/X11/xkb`, and the full Playwright Chromium release under its local cache. Use `rpmkeys --checksig` to verify the RPM before extraction with `rpm2cpio` and `cpio`. The headed guest browser opens the live Grafana URL and renders the authorized operator HTTPS response. The acceptance check waits for actual Grafana data-source queries and exports both X11 screenshots.
