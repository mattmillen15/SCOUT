# SCOUT

**Security Configuration Observation & Understanding Tool** — an offline Active
Directory security assessment for operators working from Linux.

SCOUT collects AD configuration over LDAP/LDAPS (and SMB/SYSVOL where reachable),
evaluates it against a broad rule set covering classic and modern escalation
paths, and produces an interactive single-file HTML report plus JSON and CSV.
It is built to run from a non-domain-joined box during an internal assessment.

## Features

- **Two-axis scoring → A–F grade.** *Exposure* (0–100) is set by the easiest
  available path to Tier 0, so a hardened domain scores low and a one-step
  takeover scores high — it actually differentiates environments. *Hygiene debt*
  (0–100) grades misconfiguration/stale load by prevalence. The two combine into
  an A–F posture grade. Findings are organized by **operational category**
  (Privilege Escalation, Credential Access, Lateral Movement, Persistence,
  Recon & Exposure, Hygiene & Legacy), not a compliance taxonomy.
- **Paths to Domain Dominance** — BloodHound-style control-path chains
  (attacker → control edge → … → Tier 0) with the exact tradecraft to walk each.
- **MITRE ATT&CK mapping** on findings, with a tactic coverage matrix.
- **Coverage tuned to internal pentests** — RBCD, constrained delegation on
  service accounts, ADCS ESC1/2/3/4/8, **SCCM/MECM** site infrastructure,
  **pre-staged (Pre-Windows 2000) computer accounts**, **password-spray surface**
  (no/weak lockout), computer accounts in privileged groups, orphaned
  `adminCount`, privileged SID-history, GPP passwords, WSUS-over-HTTP,
  Kerberoasting/AS-REP, coercion/relay (signing, LLMNR/NBT-NS, spooler/WebClient),
  and DCSync/ACL control paths. Watered-down/non-actionable checks are omitted by
  design.
- **Kerberos that works against hardened DCs.** SCOUT requests the TGT itself
  from a password, NT hash (overpass-the-hash) or AES key, then binds with
  GSS-SPNEGO. This satisfies *LDAP signing required* and, over plain 389,
  sidesteps *LDAPS channel binding (EPA)*. ccache reuse is also supported.
- **Interactive HTML report** — click any finding for evidence, copy-ready
  exploitation commands, remediation and affected objects; severity/category
  filters, search, ATT&CK coverage, prioritized action plan, light/dark theme
  and print-to-PDF. Plus machine-readable JSON and CSV for tracking over time.

## Install

```bash
pip3 install -r requirements.txt
```

Requires Python 3.9+, `ldap3`, `impacket` and `pycryptodome`.

## Usage

```bash
# Password
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' --dc-ip 10.0.0.10

# Pass-the-hash
./scout.py -d corp.local -u jdoe -H :<NThash> --dc-ip 10.0.0.10

# Kerberos — request a TGT from the password (best path for hardened DCs)
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' -k --dc-ip 10.0.0.10

# Overpass-the-hash / AES, and keep the ticket for reuse
./scout.py -d corp.local -u jdoe -H :<NThash> -k --save-ccache --dc-ip 10.0.0.10
./scout.py -d corp.local -u jdoe --aes-key <hex> --dc-ip 10.0.0.10

# Reuse an existing ccache
KRB5CCNAME=jdoe.ccache ./scout.py -d corp.local --dc-ip 10.0.0.10
./scout.py -d corp.local --ccache jdoe.ccache --dc-ip 10.0.0.10

# Extra outputs and report metadata
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' --dc-ip 10.0.0.10 \
    --json --csv --operator "Red Team" --scope "Internal — HQ"
```

When the bind hits `strongerAuthRequired` (signing/channel binding enforced) and
usable credentials are present, SCOUT transparently upgrades to Kerberos.

### Common options

| Option | Purpose |
| --- | --- |
| `-k`, `--kerberos` | Request a TGT and bind with Kerberos |
| `--ccache FILE` | Reuse an existing ccache (also honours `KRB5CCNAME`) |
| `--save-ccache [FILE]` | Persist the obtained TGT for reuse |
| `--aes-key HEX` | Kerberos AES key |
| `--ldaps` | Use LDAPS (636) |
| `--dc-host FQDN` | DC FQDN for the Kerberos SPN (auto-resolved otherwise) |
| `--no-smb` / `--no-adcs` | Skip SMB/SYSVOL or ADCS checks |
| `-o FILE` | HTML report path (default `scout_<domain>_<ts>.html`) |
| `--json` / `--csv` | Also write JSON / CSV findings |
| `--operator` / `--scope` | Cover-page metadata |

## Output

- `scout_<domain>_<ts>.html` — the primary interactive deliverable.
- `--json` / `--csv` — findings for diffing or tracking across scans.

## Scope and authorization

SCOUT is for **authorized** security assessments only. It reads directory data
with the rights of the account you supply; it does not modify the directory.

## License

For internal use. See repository settings.
