# Deployment and recovery

## Prerequisites and launch

The tested path uses Fedora x86-64, Python 3.12 or newer, and an installed Fedora kernel with its matching modules in `/usr/lib/modules`. A Fedora host can provide the tools through local packages for `qemu-system-x86-core` and the PC machine support package as needed, `busybox`, `cpio`, `gzip`, `kmod`, `iproute`, `iproute-tc`, `nftables`, `wireguard-tools`, `openssl`, `dnsmasq` and `tcpdump`. Install optional tools from an approved local package source if needed.

```sh
python3 labctl.py plan
python3 labctl.py network
python3 labctl.py verify
python3 labctl.py report
```

The commands run as the current user. `plan` checks addressing and policy and prints the rules. `network` boots the isolated topology, verifies interface state and exports network data. `verify` boots the complete lab, runs the acceptance suite and powers off the guest. Each test run writes its private files under `.work/runs`. Use `--accelerator tcg` to reproduce software emulation explicitly or `--kernel /boot/vmlinuz-RELEASE` to select a compatible installed kernel.

The base guest has 2 vCPUs and 640 MiB. The optional local Chromium profile allocates 1,536 MiB. The guest uses RAM and a compressed initramfs, with no persistent VM disk. Confirm measured resources and elapsed time in the [run manifest](../evidence/manifest.json).

The Ansible playbook delegates to these same local entry points. Its check mode runs the static plan.

```sh
ansible-playbook -i localhost, automation/site.yml --check
ansible-playbook -i localhost, automation/site.yml
```

## Live operations

Boot the lab with `python3 labctl.py live`. At the guest console, fetch the protected dashboard through the Admin network or read the compiled policy state.

```sh
ip netns exec admin python3 -m lab.probe http 10.77.60.10 8443 dashboard operator /api/status
python3 -m lab.operate status
```

The health collector refreshes the dashboard while this guest is running. The lab console has administrative access to the isolated guest, including provisioned fixture identities. Use `poweroff -f` in the console for shutdown. No changes survive to the next guest boot.

## Change control, backup and restore

For version-controlled changes, edit `config/lab.json` and regenerate both checked-in views, then use `plan` and run verification against a fresh guest.

```sh
python3 - <<'PY'
from pathlib import Path
from lab.model import firewall, load, matrix
policy = load()
Path("config/edge.nft").write_text(firewall(policy), encoding="utf-8")
Path("docs/communication-matrix.md").write_text(matrix(policy), encoding="utf-8")
PY
python3 labctl.py plan
python3 labctl.py verify
```

For a live rollback exercise, invoke these commands from the guest console.

```sh
python3 -m lab.operate backup before-change
python3 -m lab.operate validate before-change
python3 -m lab.operate restore before-change
python3 -m lab.operate status
```

To apply an approved candidate in a live guest, stage its nftables file under `/run/ztlab/firewall-backups/<name>.nft`. Validate it with `python3 -m lab.operate validate <name>` and apply it with `python3 -m lab.operate apply <name>`. Status compares the new state to the reviewed boot-time policy fingerprint. Restarting from the reviewed model establishes a fresh baseline. The acceptance suite exercises invalid-input rejection, policy drift, rollback and application recovery.

## Reproduce and review the dashboard evidence

```sh
python3 labctl.py verify --browser --timeout 420
python3 labctl.py report --export-evidence
tcpdump -nn -r evidence/synthetic-dns.pcap
```

The browser profile looks for Chromium Headless Shell on `PATH` or in the local Playwright cache. Pass `--chromium /path/to/chrome-headless-shell` to use an existing installation with its companion files. The dashboard screenshot comes from the authorized HTTPS response rendered by Chromium in the disconnected guest. The operator API and metrics endpoint use live data. The screenshot and HTML are point-in-time exports. Keep the private serial log and complete guest build under `.work`. Use the manifest hashes and the capture decode before pulling evidence into a public branch.
