# Project handoff

The local Git repository is `Enterprise-Network-ZeroTrust-Lab`. Run the stock profile from its root.

```sh
python3 labctl.py plan
python3 labctl.py verify
python3 labctl.py report
```

Use `python3 labctl.py live` for the network and dashboard console. Use `python3 labctl.py verify --browser --timeout 420` to include screenshot rendering. The [operations guide](docs/operations.md) covers rollback, recovery and artifact export.

The [integration guide](docs/integrations.md) documents the local release layouts for live IDS, Prometheus and Grafana checks. A local Ansible Core install or wheelhouse is required to execute the Ansible profile.

The [evidence index](evidence/README.md) identifies the public files and the run manifest. The raw serial transcript, guest image and local run workspaces live under `.work/`. Evidence export uses fixed filenames and validates their SHA-256 digests. Fixture keys and the test CA stay in guest RAM.

Publish from the local `main` branch to a repository named `Enterprise-Network-ZeroTrust-Lab` under the supplied GitHub account when publication is authorized. Review `git status --short`, `git ls-files` and the packet decode before pushing. The public portfolio should include the current [readiness assessment](docs/assessment.md) alongside the evidence.
