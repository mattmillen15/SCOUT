# SCOUT — development notes

Context for maintainers (human or AI) working on SCOUT. Keep this file current
when the architecture or roadmap changes; keep it short and factual.

## Layout

Everything lives in a single script, `scout.py`, by design — it has to drop onto
an assessment box with only `pip install` deps. Major pieces, top to bottom:

- **Constants & rule metadata** — `RULES` (id → `(title, category, points,
  severity)`), `RULE_DOCS` (per-rule description/why/technical/exploit/
  remediation/refs), `RULE_MATURITY` (id → CMMI level 1–5, with a severity-based
  default), `RULE_MITRE` (id → ATT&CK techniques), `RULE_SCALE` (id →
  `(points_per_object, cap)` for graduated scoring).
- **`ADConnection`** — auth + LDAP transport (ldap3 fast path, impacket Kerberos
  path). See "Authentication" below.
- **`ADData`** — one collection pass over LDAP (domain, users, computers, groups
  incl. recursive + primary-group privileged membership, DCs/RODCs, trusts,
  GPOs, sites, PSOs, ADCS, DNS).
- **`CheckEngine`** — all rule logic, grouped `_check_anomaly/_privileged/_stale/
  _trust/_gpo_sysvol/_acl/_extra/_modern`. Each check calls `self._add(rule_id,
  details, affected)`.
- **`SYSVOLChecker`, `ACLAnalyzer`, `SMBChecker`** — SMB/SYSVOL, ACL/DACL and
  SMB-signing checks (impacket).
- **`RiskScorer`** — category caps + global = max; `maturity()` = lowest level
  among failing rules.
- **`HTMLReporter`** — single-file interactive report (`_KC_CSS`/`_KC_JS` module
  strings hold the inline theme/JS; no external assets).
- **`main()`** — arg parsing, orchestration, HTML/JSON/CSV output.

## Authentication

The important design point: against a DC that enforces *LDAP signing* and/or
*LDAPS channel binding (EPA)*, SCOUT requests a Kerberos TGT itself
(`impacket.krb5.kerberosv5.getKerberosTGT`) from the supplied password / NT hash
(overpass-the-hash) / AES key, writes it to a ccache, and binds with
`impacket` `kerberosLogin` (GSS-SPNEGO). Over plain LDAP/389 the Kerberos bind
satisfies the signing requirement and there is no TLS channel, so EPA does not
apply. ldap3 NTLM/SIMPLE remains the fast path for un-hardened DCs, with an
automatic upgrade to Kerberos on `strongerAuthRequired`. The obtained ccache is
exported via `KRB5CCNAME` so the SMB/SYSVOL Kerberos logins reuse it.

`impacket` 0.9.24's native LDAPS is TLS 1.0 only and lacks CBT, which is why the
recommended hardened-DC path is Kerberos-over-389 rather than LDAPS.

## Scoring & maturity

- Per category: `min(100, sum of triggered points)`; global score = the worst of
  the four categories.
- Graduated scoring: rules in `RULE_SCALE` scale points with affected-object
  count up to a cap (so 1 vs 5,000 stale objects don't score the same).
- Maturity: each rule has a level 1–5; achieved level = the lowest level still
  gated by a failing rule. One unfixed level-1 issue pins the domain at level 1.

## Adding a rule

1. Add an entry to `RULES`.
2. Add `RULE_DOCS[id]` (description/why/exploit/remediation/refs) and, where it
   applies, `RULE_MITRE[id]` and a `RULE_MATURITY[id]` override.
3. Emit it from a check method via `self._add(id, details, affected)`. Prefer
   reusing already-collected `ADData`; only extend collection if necessary.
4. If it is count-driven, add it to `RULE_SCALE`.

## Known limitations

- No transitive ACL control-path graph (BloodHound-style closure); only fixed
  high-value objects and a few broad-principal ACL checks.
- ADCS coverage is ESC1/2/3/4/8 + key strength. ESC5/6/7/9/10 need CA-side data
  (CA flags, CA security descriptor) not collected over LDAP today.
- Some host-local controls (RestrictRemoteSAM, DSRM logon, NTLM auditing) are
  inferred from GPO state in SYSVOL, not read from the host registry.
- `sIDHistory`/SID/time decoding can differ between the ldap3 and impacket
  backends; checks normalise defensively but full normalisation is pending.

## Roadmap

Ordered roughly by value:

1. Transitive ACL control-path analysis ("who can become Domain Admin").
2. ADCS ESC6/ESC7 (CA flags + CA security descriptor) and ESC9/10 cert mapping.
3. gMSA / dMSA managed-password read-ACL checks; KDS root key exposure.
4. Deeper Entra/AAD-Connect inspection (PHS/PTA/Seamless SSO, sync-account priv).
5. OU + `gPLink` inventory: GPO link/inheritance, orphaned/unlinked GPOs.
6. Backend-agnostic normalisation of SID/time attributes; per-query failure
   surfacing in the report (so "clean" can't mean "unscanned").
7. `lastLogon` (per-DC) reconciliation with `lastLogonTimestamp` for accuracy.
8. Port the assessment to a NetExec (`nxc ldap`) module that reuses the engine.
9. Trust scope/transitivity classification and a reachable-domains map.

## Design notes

The scoring model is a per-category 0–100 danger score with the global score
taken as the worst category, plus a separate CMMI maturity level (the maturity
ladder follows the Carnegie Mellon / ANSSI model: 1 = Initial … 5 = Optimizing).
SCOUT is a self-contained tool with its own rule catalogue, checks and report —
extend it freely.
