# SCOUT — development notes

Context for maintainers (human or AI) working on SCOUT. Keep this file current
when the architecture or roadmap changes; keep it short and factual.

## Layout

Everything lives in a single script, `scout.py`, by design — it has to drop onto
an assessment box with only `pip install` deps. Major pieces, top to bottom:

- **Constants & rule metadata** — `RULES` (id → `(title, category, points,
  severity)`), `RULE_DOCS` (per-rule description/why/technical/exploit/
  remediation/refs), `RULE_MITRE` (id → ATT&CK techniques), `RULE_SCALE` (id →
  `(points_per_object, cap)`), `EXPOSURE_WEIGHTS` / `HYGIENE_WEIGHTS` (the two
  scoring axes), `OP_CATEGORY` (id → operational category used for report
  grouping/filtering), and `SUPPRESSED_RULES` (non-actionable rules dropped at
  `_add`). The internal A/P/S/T `category` is now used only as a fallback for
  `op_category()`; scoring no longer keys off it.
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
- **`RiskScorer`** — two axes: `exposure()` (easiest path to Tier 0, from
  `EXPOSURE_WEIGHTS`) and `hygiene()` (prevalence-graded debt, from
  `HYGIENE_WEIGHTS`), plus `verdict()` (plain-English exposure band).
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

## Scoring

Two axes, deliberately not a single saturating gauge (which always pinned at
100):

- **Exposure (0–100)** = the highest `EXPOSURE_WEIGHTS` value among triggered
  rules (your *easiest* path to Tier 0), plus a small breadth bonus. A hardened
  domain scores low; a one-step takeover (GPP/DCSync/ESC1) scores ~95–100.
- **Hygiene debt (0–100)** = sum of `HYGIENE_WEIGHTS` contributions; `pct_users`/
  `pct_comps` entries scale by the fraction of enabled objects affected.
- **Verdict** = `RiskScorer.verdict(exposure)` — a plain-English band word
  ("Domain compromisable" … "No direct path"), shown instead of a letter grade.
- `RULE_SCALE` still graduates per-finding `points` (used for finding sort).

There is intentionally no maturity/CMMI score and no letter grade — both tested
as not useful for an offensive engagement.

## Adding a rule

1. Add an entry to `RULES`.
2. Add `RULE_DOCS[id]` (description/why/exploit/remediation/refs); add
   `RULE_MITRE[id]`, an `EXPOSURE_WEIGHTS[id]` (if it's an attack path) and/or
   `HYGIENE_WEIGHTS[id]`, and an `OP_CATEGORY[id]` for report grouping.
3. Emit it from a check method via `self._add(id, details, affected)`. Prefer
   reusing already-collected `ADData`; only extend collection if necessary.
4. Keep it actionable — if it isn't something an operator would act on during an
   engagement, add it to `SUPPRESSED_RULES` instead (or don't add it).

## Known limitations

- `ControlPathAnalyzer` does a real transitive closure (membership + GenericAll/
  GenericWrite/WriteDacl/WriteOwner/Owner/DCSync edges, seeded from Tier-0). It
  bulk-reads SDs for groups + adminCount users and per-object for the domain
  root/GPOs; it does NOT yet read every user/computer SD, so paths that route
  through control over an arbitrary non-admin object can be missed. GPO control
  is modelled as "→ Tier 0" (approximation; doesn't yet check the GPO's link).
- ADCS coverage is ESC1/2/3/4/7/8/9 + key strength. ESC6 (EDITF_ATTRIBUTE-
  SUBJECTALTNAME2) and ESC10/11 are CA/DC registry settings not exposed over
  LDAP, so they can't be confirmed read-only.
- Some host-local controls (RestrictRemoteSAM, DSRM logon, NTLM auditing) are
  inferred from GPO state in SYSVOL, not read from the host registry.
- `sIDHistory`/SID/time decoding can differ between the ldap3 and impacket
  backends; checks normalize defensively but full normalization is pending.
- SCCM/WSUS coverage is the *exposure* surface readable from AD/SYSVOL (site
  servers, MP/site codes, HTTP WUServer). Full exploitation (NAA recovery, PXE
  secrets, relay) needs host/network interaction and is out of scope for a
  read-only LDAP pass — the finding points the operator at the right tooling.

## Roadmap

Ordered roughly by value:

1. Extend control-path closure to all user/computer SDs (bulk, paged) and add
   real GPO-link resolution so GPO→host→Tier-0 edges are precise.
2. gMSA / dMSA managed-password read-ACL checks; KDS root key exposure.
3. Deeper Entra/AAD-Connect inspection (PHS/PTA/Seamless SSO, sync-account priv).
5. OU + `gPLink` inventory: GPO link/inheritance, orphaned/unlinked GPOs.
6. Backend-agnostic normalisation of SID/time attributes; per-query failure
   surfacing in the report (so "clean" can't mean "unscanned").
7. `lastLogon` (per-DC) reconciliation with `lastLogonTimestamp` for accuracy.
8. Port the assessment to a NetExec (`nxc ldap`) module that reuses the engine.
9. Trust scope/transitivity classification and a reachable-domains map.

## Design notes

SCOUT is a self-contained, operator-oriented tool with its own rule catalog,
checks, scoring (Exposure + Hygiene + verdict) and report. Findings are
organized by operational category (Privilege Escalation, Credential Access,
Lateral Movement, Persistence, Recon & Exposure, Hygiene & Legacy) rather than a
compliance taxonomy, and watered-down/non-actionable rules are suppressed by
design. Extend it freely — keep findings actionable and scored for real
offensive risk.
