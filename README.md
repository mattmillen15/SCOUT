# SCOUT

![SCOUT HTML report](docs/img/scout_example_report.png)

Security Configuration Observation & Understanding Tool — an offline Active
Directory security assessment that runs from a non-domain-joined Linux host.

SCOUT collects AD configuration over LDAP/LDAPS and SMB/SYSVOL, evaluates it
against a rule set covering privilege escalation, credential access, lateral
movement, persistence, and hygiene, and writes an interactive single-file HTML
report plus optional JSON and CSV.

## BETA WARNING
**This tool is currently in a BETA phase. This is largely AI generated, and there are errors, logic flaws, severity discrepencies, etc that need to be addressed. The more data the better. If you find something that is missing or run into an edge case / error -- submit an issue or PR.**

## Usage

```bash
# Password
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' --dc-ip 10.0.0.10

# Pass-the-hash
./scout.py -d corp.local -u jdoe -H :<NThash> --dc-ip 10.0.0.10

# Kerberos: request a TGT from the password (use when LDAP signing or channel
# binding is enforced)
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' -k --dc-ip 10.0.0.10

# Pass-the-hash / AES key
./scout.py -d corp.local -u jdoe -H :<NThash> -k --dc-ip 10.0.0.10
./scout.py -d corp.local -u jdoe --aes-key <hex> --dc-ip 10.0.0.10

# Reuse an existing ccache
KRB5CCNAME=jdoe.ccache ./scout.py -d corp.local --dc-ip 10.0.0.10
./scout.py -d corp.local --ccache jdoe.ccache --dc-ip 10.0.0.10

# Extra outputs and report metadata
./scout.py -d corp.local -u jdoe -p 'P@ssw0rd' --dc-ip 10.0.0.10 \
    --json --csv --operator "Red Team" --scope "Internal — HQ"
```

When a bind returns `strongerAuthRequired` (signing/channel binding enforced) and
usable credentials are present, SCOUT upgrades to Kerberos.

### NetExec

`integrations/nxc/scout.py` runs the engine as a NetExec `ldap` module. Directory
data reuses nxc's authenticated LDAP connection (no second bind); SMB/SYSVOL
checks open a separate SMB connection using the same credentials.

```bash
# Deploy
cp integrations/nxc/scout.py ~/.nxc/modules/scout.py
export SCOUT_PATH=/path/to/SCOUT/scout.py   # or pass -o PATH=/path/to/scout.py

# Run
nxc ldap <dc> -u user -p pass -M scout                 # writes scout_<domain>.html
nxc ldap <dc> -u user -H :<NThash> -k -M scout
nxc ldap <dc> -u user -p pass -M scout -o NO_SMB=true JSON=true
```

Module options (`-o KEY=value`):

| Option | Purpose |
| --- | --- |
| `PATH` | Path to scout.py (else `$SCOUT_PATH`, else `./scout.py`) |
| `OUTPUT` | HTML report path |
| `JSON` | JSON output path (`true` for default name) |
| `NO_SMB` | Skip SMB/SYSVOL checks |
| `NO_PATHS` | Skip control-path analysis |
| `NO_ADCS` | Skip ADCS checks |

### Options

| Option | Purpose |
| --- | --- |
| `-k`, `--kerberos` | Request a TGT and bind with Kerberos |
| `--ccache FILE` | Reuse an existing ccache (also honors `KRB5CCNAME`) |
| `--save-ccache [FILE]` | Save the obtained TGT for reuse |
| `--aes-key HEX` | Kerberos AES key |
| `--ldaps` | Use LDAPS (636) |
| `--dc-host FQDN` | DC FQDN for the Kerberos SPN (auto-resolved otherwise) |
| `--no-smb` / `--no-adcs` / `--no-paths` | Skip SMB/SYSVOL, ADCS, or control-path analysis |
| `--accurate-logon` | Reconcile `lastLogon` across every DC for privileged-inactivity findings |
| `-o FILE` | HTML report path (default `scout_<domain>_<ts>.html`) |
| `--json` / `--csv` | Also write JSON / CSV findings |
| `--operator` / `--scope` | Report cover metadata |

The HTML report is always written (`scout_<domain>_<ts>.html` by default, or `-o`);
`--json` / `--csv` add machine-readable findings for diffing across scans.
