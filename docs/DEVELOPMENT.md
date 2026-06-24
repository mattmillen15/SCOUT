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

Three numbers, deliberately *not* one saturating gauge for everything:

- **Exposure (0–100, higher = worse)** = the highest `EXPOSURE_WEIGHTS` value
  among triggered rules (your *easiest* path to Tier 0), plus a small breadth
  bonus. A hardened domain scores low; a one-step takeover (GPP/DCSync/ESC1)
  scores ~95–100. This is the axis the "Top Priorities — ranked by
  exploitability" list sorts on.
- **Hygiene debt (0–100, higher = worse)** = sum of `HYGIENE_WEIGHTS`
  contributions; `pct_users`/`pct_comps` entries scale by the fraction of
  enabled objects affected.
- **Posture score (0–100, higher = BETTER) + A–F grade** = the headline, à la
  Insight Recon ("77 · C · Moderate Risk"). `RiskScorer.posture()` = `100 −
  severity-weighted finding deductions (per-severity caps) − exposure penalty`,
  so it *differentiates* (a clean domain = A; a few mediums = C; crits / a live
  Tier-0 path = F) instead of pinning. `RiskScorer.grade()` maps it to A/B/C/D/F
  + a risk word + color.
- **Verdict** = `RiskScorer.verdict(exposure)` — the plain-English exposure band
  ("Domain compromisable" … "No direct path"), still shown alongside.
- `RULE_SCALE` graduates per-finding `points` (used for finding sort).

History note: a *single saturating* A–F gauge was removed once because it pinned
at the extremes. The current grade is a **deduction model with caps**, which
behaves like Insight Recon's and was re-added deliberately (the maturity/CMMI
table remains computed but unused). See `ROADMAP.md` for the full Insight-Recon
parity plan.

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
  bulk-reads SDs for groups and for *every* user and computer (one paged
  `(objectClass=user)` query covers both), plus the domain root and all GPOs. GPO
  → Tier-0 edges are resolved via `gPLink` (domain root + OUs): a GPO only reaches
  Tier-0 when it is linked to a DC-affecting container. Reading all object SDs is
  the slowest stage; `--no-paths` skips the whole analysis. It emits a node
  registry (type/enabled/pwd-age/logon-age/stale/SID + group members) that drives
  the clickable graph + drawer in the report.
- ADCS coverage is ESC1/2/3/4/7/8/9 + key strength. ESC1/2/3/9 are gated on
  whether a broad/low-priv principal can actually enroll (parsed from the
  template SD) to avoid EA/DA-only false positives. ESC6 (EDITF_ATTRIBUTE-
  SUBJECTALTNAME2) and ESC10/11 are CA/DC registry settings not exposed over
  LDAP, so they can't be confirmed read-only.
- Managed accounts: gMSA/dMSA password-read ACL (`msDS-GroupMSAMembership`) and
  KDS root-key readability (GoldenGMSA) are checked. Entra/AAD-Connect coverage
  is the on-prem-readable surface only — the MSOL_ sync account (DCSync-capable)
  and the Seamless SSO `AZUREADSSOACC$` key age; PHS/PTA enablement itself is a
  cloud/host setting and can't be confirmed from a read-only LDAP pass.
- Some host-local controls (RestrictRemoteSAM, DSRM logon, NTLM auditing) are
  inferred from GPO state in SYSVOL, not read from the host registry.
- `sIDHistory`/SID/time decoding can differ between the ldap3 and impacket
  backends; checks normalize defensively but full normalization is pending.
- SCCM/WSUS coverage is the *exposure* surface readable from AD/SYSVOL (site
  servers, MP/site codes, HTTP WUServer). Full exploitation (NAA recovery, PXE
  secrets, relay) needs host/network interaction and is out of scope for a
  read-only LDAP pass — the finding points the operator at the right tooling.

## Roadmap

Status as of the control-path overhaul:

1. **Done.** Control-path closure reads all user/computer SDs (bulk, paged) and
   resolves `gPLink` so GPO→Tier-0 edges are precise (only DC-linked GPOs).
2. **Done.** gMSA/dMSA managed-password read-ACL (`P-GMSAReadable`) and KDS
   root-key readability (`A-KDSRootKey`, GoldenGMSA).
3. **Partial.** Entra/AAD-Connect: MSOL_ sync account (`A-AADConnectSync`,
   DCSync-capable) and Seamless SSO key staleness (`A-SeamlessSSO`) are detected
   from on-prem AD. PHS/PTA enablement is a cloud/host setting, not confirmable
   from a read-only LDAP pass — deliberately out of scope.
5. **Done.** OU + `gPLink` inventory drives GPO-link resolution above and surfaces
   orphaned/unlinked GPOs (`S-OrphanedGPO`).
6. **Mostly done.** `to_text()` decodes the impacket backend's bytes so SID/time/
   string values normalise across backends, and the report now surfaces per-query
   collection failures ("Collection notes") so "clean" can't mean "unscanned".
   Full per-attribute SID/time normalisation across edge cases is ongoing.
7. **Done (opt-in).** `--accurate-logon` reconciles the replicated
   `lastLogonTimestamp` (up to ~14 days stale) against the non-replicated
   `lastLogon` on every DC for the privileged-inactivity findings, clearing false
   "inactive"/"never logged on" admins. Off by default (extra per-DC binds).
8. **Done.** `integrations/nxc/scout.py` is a NetExec `ldap` module that adopts
   nxc's already-authenticated impacket LDAP connection
   (`ADConnection.adopt_impacket()`) and runs the engine, writing SCOUT's HTML/
   JSON report. Directory data reuses nxc's LDAP connection; SMB/SYSVOL checks
   open a separate SMB connection from the same credentials (`NO_SMB=true` to
   skip). `make_args()` provides a fully defaulted args namespace for embedders.
   Validated against a live DC: `nxc ldap <dc> -u u -p p -M scout`.
9. **Done.** `classify_trust()` classifies every trust (scope: intra-forest /
   forest / external / realm; transitivity; direction; SID-filtering; selective
   auth; TGT delegation) into a reachable-domains "Trust map" in the report, with
   per-trust cross-domain risk notes.

## Design notes

SCOUT is a self-contained, operator-oriented tool with its own rule catalog,
checks, scoring (Exposure + Hygiene + verdict) and report. Findings are
organized by operational category (Privilege Escalation, Credential Access,
Lateral Movement, Persistence, Recon & Exposure, Hygiene & Legacy) rather than a
compliance taxonomy, and watered-down/non-actionable rules are suppressed by
design. Extend it freely — keep findings actionable and scored for real
offensive risk.
