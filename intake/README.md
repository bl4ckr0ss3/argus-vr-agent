# intake/ — the collection→analysis contract

Any file dropped here is picked up by the ARGUS watcher (`python run.py watch`),
unpacked into `quarantine/`, statically triaged, and reported to the vault.
**Nothing is ever executed.** Run all of this inside an isolated analysis VM.

Sources that can feed this folder:

## 1. MalwareBazaar feed (built in)
```bash
python run.py fetch --limit 25            # recent samples
python run.py fetch --tag AgentTesla      # by family/tag
python run.py watch --once                # triage them (static, free)
```
Needs a free abuse.ch key in `.env` (`MALWAREBAZAAR_API_KEY`). Samples arrive as
`infected`-password ZIPs; the unpacker handles that.

## 2. A honeypot (add later)
Point your honeypot's captured-payload directory at this folder. Examples:

- **Dionaea** stores captured binaries under `var/lib/dionaea/binaries/`. On the
  analysis VM, pull them in one-way (no path back to the honeypot):
  ```bash
  rsync -av --remove-source-files honeypot:/opt/dionaea/var/lib/dionaea/binaries/ ./intake/
  ```
- **Cowrie** stores downloads under `var/lib/cowrie/downloads/`:
  ```bash
  rsync -av cowrie:/home/cowrie/cowrie/var/lib/cowrie/downloads/ ./intake/
  ```
- **T-Pot** aggregates many honeypots; export its collected payloads similarly.

Keep the transfer **one-way** (honeypot → analysis VM). The honeypot itself must
sit on an isolated segment with outbound blocked or sinkholed (INetSim/FakeNet).

## 3. Manual
Just drop a file here and run `python run.py watch --once`.

---
Contents of this folder are malware. It is gitignored — never commit it.
