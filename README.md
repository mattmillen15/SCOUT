# SCOUT

**Security Configuration Observation & Understanding Tool** — an offline Active
Directory security assessment for operators working from Linux.

SCOUT collects AD configuration over LDAP/LDAPS (and SMB/SYSVOL where reachable),
evaluates it against a broad rule set covering classic and modern escalation
paths, and produces an interactive single-file HTML report plus JSON and CSV.
It is built to run from a non-domain-joined box during an internal assessment.

## Features

- **Exposure-based scoring.** *Exposure* (0–100) is set by the easiest available
  path to Tier 0, so a hardened domain scores low and a one-step takeover scores
  high — it actually differentiates environments (with a plain-English verdict,
  e.g. "Domain compromisable"). *Hygiene debt* (0–100) grades misconfiguration/
  stale load by prevalence. Findings are organized by **operational category**
  (Privilege Escalation, Credential Access, Lateral Movement, Persistence,
  Recon & Exposure, Hygiene & Legacy), not a compliance taxonomy.
- **Attack Paths** — BloodHound-style control-path chains (attacker → control
  edge → … → Tier 0) with the exact tradecraft to walk each.
- **Privileged Accounts explorer** — click any privileged group to see its
  members with pwd age, last logon, enabled/admin status and flags (stale,
  kerberoastable, never-expires), plus the principals holding control over Tier-0.
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
  exploitation commands, remediation and a terminal-style evidence block; an
  inline attack-path visual on relevant findings; severity/operation filters,
  search, light/dark theme and print-to-PDF. Plus JSON and CSV exports.

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
| `--no-smb` / `--no-adcs` / `--no-paths` | Skip SMB/SYSVOL, ADCS, or control-path analysis |
| `--accurate-logon` | Reconcile `lastLogon` across every DC for privileged-inactivity findings |
| `-o FILE` | HTML report path (default `scout_<domain>_<ts>.html`) |
| `--json` / `--csv` | Also write JSON / CSV findings |
| `--operator` / `--scope` | Cover-page metadata |

### NetExec module

`integrations/nxc/scout.py` runs the engine as a NetExec `ldap` module, reusing
nxc's authenticated connection (LDAP-only — no SMB/SYSVOL):

```bash
cp integrations/nxc/scout.py ~/.nxc/modules/scout.py
export SCOUT_PATH=$PWD/scout.py
nxc ldap <dc> -u user -p pass -M scout            # writes scout_<domain>.html
nxc ldap <dc> -u user -p pass -M scout -o NO_PATHS=true JSON=true
```

## Output

- `scout_<domain>_<ts>.html` — the primary interactive deliverable.
- `--json` / `--csv` — findings for diffing or tracking across scans.

## Scope and authorization

SCOUT is for **authorized** security assessments only. It reads directory data
with the rights of the account you supply; it does not modify the directory.

## License

For internal use. See repository settings.
