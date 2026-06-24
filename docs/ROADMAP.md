# SCOUT roadmap — Insight Recon parity

This roadmap was built by going through **insightrecon.com** line by line and
mapping every claim/feature to SCOUT. SCOUT is an *offline, operator-run* Linux
tool (read-only LDAP/SMB from a non-domain-joined box); Insight Recon is a
point-and-click Windows scanner with a hosted web report. We are matching the
**report, prioritization, and finding-depth** — not the hosted-SaaS delivery.

Status legend: **[done]** shipped in this pass · **[partial]** some of it ships ·
**[planned]** on the roadmap · **[n/a]** out of scope by design (and why).

---

## 1. Prioritization & scoring — "Findings you can actually act on"

| Insight Recon (verbatim / paraphrase)                                   | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| "Top Priorities — **Ranked by exploitability**"                          | **[done]**   | New **Priorities** section ranks deduped findings by `EXPOSURE_WEIGHTS` (attacker effort-to-Tier-0), with an exploitability bar, severity, effort, affected count, and a one-line attacker note. |
| "Findings are ordered by real attacker impact, not a generic score."     | **[done]**   | Exploitability rank = exposure weight, not raw points/severity. |
| "**Quick Wins** … fastest risk cuts"                                     | **[done]**   | New Quick Wins panel: high-impact findings whose remediation effort is *Low*. |
| Risk score badge "**77 OF 100**" + grade "**C · Moderate Risk**"         | **[done]**   | New **Posture score (0–100, higher = stronger)** + **A–F grade** hero. Reverses the old "no letter grade" stance (see DEVELOPMENT.md). Exposure + Hygiene kept as the two contributing meters. |
| "Higher score means a stronger AD posture."                              | **[done]**   | `RiskScorer.posture()` is inverted-risk: 100 − severity-weighted deductions − exposure penalty. |
| Severity breakdown badges: "1 Crit / 9 High / 8 Mod / 8 Low"             | **[done]**   | Compact severity chips row in the hero. |
| "**Remediation Effort**: Moderate" per finding                           | **[done]**   | `rule_effort()` → Low / Moderate / High; shown as a badge in the finding panel and an Effort column in the findings table. |
| "**Risk Posture Score over time**" trend chart                           | **[planned]**| Needs persisted scan history. See §6. |

## 2. Coverage — "135+ checks. All signal, no noise."

| Insight Recon                                                            | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| 135+ checks                                                              | **[done]**   | SCOUT ships **212** rules across A/P/S/T. |
| ESC1–16 (ADCS): vulnerable templates, enrollment rights, EDITF_ATTRIBUTESUBJECTALTNAME, enrollment-agent abuse, weak DC cert mappings, CA access-control gaps | **[done, read-only subset]** | ESC1/2/3/4/**5**/7/8/9/**13**/**14**/**15** + key strength. ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC10/11 (DC/CA registry & RPC), ESC16 (CA-wide SID-extension disable) are **host/registry-only** and not confirmable from a read-only LDAP pass — out of scope by design (the report points the operator at `certipy find` for those). |
| AAA: Kerberoast, AS-REP, NTLMv1/LM, RC4/DES, reversible pwds, no-password accts, weak cert mappings | **[done]** | All covered. |
| PAM: DCSync, AdminSDHolder, dangerous ACLs, unconstrained/constrained/RBCD, shadow credentials, SID history, stale admins | **[partial]** | All covered **except shadow credentials (msDS-KeyCredentialLink / Whisker)** — **[planned]**. |
| DSI: LAPS coverage, gMSA exposure, DC backups, SMB signing, LDAP signing, Spooler on DC, legacy OS on DC, SMBv1 | **[done]** | Covered. ("DC backups" surfaced via metadata; refine [planned].) |
| PCM: pwd/lockout policy, passwords in GPOs, anonymous AD access, LLMNR, trust encryption, dangerous trust attrs, functional level | **[done]** | Covered. |

## 3. Finding depth — "Every finding tells the full story."

| Insight Recon                                                            | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| "**Hacker Insight**" attacker-context block                              | **[done]**   | Existing `why` / `technical` / **Exploitation** (copy-able commands) blocks. |
| "**Recommendation**" + remediation guide link                            | **[done]**   | Existing `remediation` block + `refs`. |
| Affected-items **table**: Account / Display Name / Enabled / Created / Last Logon / Password Set | **[done]** | New rich affected-object table (resolves sAMAccountName → object) replacing the flat evidence list for account/computer findings. |
| "**Export CSV**" on the affected-items table                             | **[done]**   | Inline per-table CSV export button (client-side). Global `--csv`/`--json` already existed. |
| "**First Seen**: Jun 15, 2026" per finding                               | **[done]**   | `--baseline` propagates per-finding `first_seen` across scans; shown in the finding panel. |
| Compliance mapping: **MITRE ATT&CK**, **MITRE Mitigations**, **CIS Controls**, **STIG** | **[done]** | ATT&CK + **MITRE Mitigations + CIS Controls v8 + NIST CSF + STIG** chips. STIG entries are *control-area references* (the relevant DISA STIG control), not version-pinned V-IDs, which shift every quarterly release. |
| "PowerShell and ADUC fix steps written for your environment"             | **[done]**   | Copy-able **PowerShell remediation** block per finding, with `{domain}`/`{dc}` substituted to the assessed environment. |

## 4. Report structure & GUI — "their GUI looks better"

| Insight Recon section                                                    | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| Header: tool name / "SECURITY ASSESSMENT" / DOMAIN / GENERATED date      | **[done]**   | Slim header + dossier already carry these; tightened. |
| Executive **Overview** with score badge + severity breakdown             | **[done]**   | New hero band (grade + score + chips + meters + donut). |
| **Priorities** section                                                   | **[done]**   | Added (Top Priorities + Quick Wins). Added to nav. |
| **Detailed Findings** (filterable)                                       | **[done]**   | Existing filterable/searchable table; added Effort column + framework chips. |
| **Trends & Changes**                                                     | **[done]**   | `--baseline` diff renders a "Changes since last scan" section (New/Fixed/Modified/Unchanged + NEW badges). Risk-over-time sparkline still **[planned]** (§6.2). |
| Configuration / Environment / Accounts & Groups / Infrastructure / PKI & Certificates / Group Policy sub-sections | **[done]** | Inventory (env/config), Privileged (accounts & groups), Attack Paths, **dedicated PKI / AD CS** section (CAs + template attack-surface table) and **dedicated Group Policy** section (weaponizable GPOs, Tier-0 link map, orphaned, GPP passwords). |
| Visual polish (clean cards, ring/badge score, chips)                     | **[done]**   | Re-themed in SCOUT's field/army palette — same look, our colors. |
| "Web report you can share … hand it to leadership or a client as is"     | **[done]**   | Single-file HTML, print-to-PDF. |

## 5. Scanning / delivery model

| Insight Recon                                                            | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| "Point, click, scan. No console."                                        | **[n/a]**    | SCOUT is a CLI for Linux operators by design. |
| Read-only, no production impact, single machine                          | **[done]**   | Read-only LDAP/SMB, single box. |
| Queries LDAP, SMB, RPC, HTTPS                                            | **[partial]**| LDAP/LDAPS + SMB/SYSVOL. RPC/HTTPS probing (e.g. live ESC8 web-enrollment, RPC coercion confirm) **[planned]**. |
| "On demand or on a schedule"                                             | **[planned]**| Scheduling is a host/cron concern; a `--baseline`-aware scheduled mode pairs with §6. |
| Live **scan progress** indicator (per-stage % + counts)                  | **[planned]**| Improve terminal progress (per-stage status lines + object counts). |

## 6. Trends & change tracking — "Prove you're actually getting better."

Insight Recon: "Risk Posture Score over time", "New / Remediated / Modified / Unchanged", "Fixed since last scan".

1. **[done] `--baseline prev.json`** — diffs current findings against a prior SCOUT
   JSON; computes **New / Fixed / Unchanged / Modified** (by rule_id + affected-set),
   renders a "Changes since last scan" section + nav entry + NEW badges, and
   propagates **First Seen** per finding (carried in `--json`, survives many scans).
2. **[planned] Scan history store** — append each run's `{ts, posture, exposure,
   hygiene, sev_counts}` to a local `scout_history.json`; render a
   **risk-posture-over-time** sparkline in the hero.
3. **[partial] Per-finding lifecycle** — `first_seen` shipped; last_seen / age /
   "remediated since" still to do.

## 7. Cloud / Entra — "A Microsoft 365 and Entra ID version is in the works"

| Insight Recon                                                            | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| On-prem AD first; M365/Entra ID next                                     | **[partial]**| On-prem Entra surface (`A-AADConnectSync`, `A-SeamlessSSO`) detected. Full Entra/M365 assessment (Graph-based) **[planned, large]** — separate mode, not read-only LDAP. |

---

## Shipped — Insight-Recon parity v1

- Posture **score (0–100) + A–F grade** hero, severity chips, contributing meters.
- **Priorities** section: Top Priorities *ranked by exploitability* + **Quick Wins**.
- **Remediation effort** (Low/Moderate/High) on every finding + findings-table column.
- **Rich affected-object tables** (enabled / created / pwd-set / last-logon / flags) + **inline CSV export**.
- **Framework mappings**: CIS Controls v8 + NIST CSF + MITRE Mitigations chips (alongside existing ATT&CK).
- GUI re-polish in SCOUT's field/army theme to match Insight Recon's cleaner card/badge layout.

## Shipped — parity v2 (roadmap follow-ups)

- **Trends / `--baseline` diff**: "Changes since last scan" section (New/Fixed/Modified/Unchanged), NEW badges, per-finding **First Seen**.
- **ADCS ESC5 / ESC13 / ESC15** detection (CA-object ACL, issuance-policy→privileged-group link, schema-V1 application-policy injection / CVE-2024-49019).
- **STIG control-area references** added to the Frameworks chips.
- **Per-finding PowerShell remediation**, substituted for the assessed environment.

## Shipped — parity v3 (PKI/GPO attack paths + operator findings)

- **Dedicated PKI / AD CS section** — CA table (host + abusable-as ESCx) and a
  template attack-surface table (schema, auth-EKU, enrollee-supplies-subject,
  manager-approval, which ESCx it trips), abusable templates first.
- **Dedicated Group Policy section** — weaponizable GPOs (writable by a non-Tier-0
  principal → code exec in scope), GPO→Tier-0 link map, orphaned GPOs, GPP passwords.
- **ESC14** — weak explicit certificate mappings (`altSecurityIdentities`).
- **A-PasswordInDescription** — credentials stashed in `description`/`info` attributes
  (classic, high-yield, every authenticated user can read it).
- **P-LAPSReadable** — LAPS local-admin password actually readable by the scanning
  principal (delegated-read misconfig → lateral movement; plaintext surfaced).

## Next up (highest leverage first)

1. **Risk-posture-over-time** sparkline + local scan-history store — §6.2.
2. Version-pinned **STIG V-IDs** against a chosen STIG release — §3.
3. **Scan-progress UX** + scheduled/baseline mode — §5.
4. Per-finding **lifecycle** (last_seen / age / remediated-since) — §6.3.

## Candidate operator findings (noted, not yet implemented)

Legitimate pentester findings worth adding next — all read-only-LDAP-confirmable
unless flagged:

- **Foreign Security Principals in privileged groups** — external/cross-forest SIDs
  with Tier-0 membership (lateral path across a trust). Clean LDAP finding.
- **Certifried (CVE-2022-26923)** — explicit "MAQ>0 + a machine-enrollable
  auth template" combination (we flag the pieces separately today).
- **`userPassword` / `unixUserPassword` populated** — some apps write cleartext here;
  fold into the credential-in-attributes sweep (needs collecting those attrs).
- **Expanded coercion vectors** — DFSCoerce (MS-DFSNM) / EFSRPC beyond Spooler+WebClient
  (we have `A-DC-Coerce`); the RPC ones need a live probe, so flag-as-surface only.
- **ZeroLogon (CVE-2020-1472) / noPac (CVE-2021-42278/42287)** — high-impact but
  **active tests**, not confirmable read-only; surface the *candidate* DCs and point
  the operator at the right tool rather than assert.
- **Pre-Windows 2000 / inactive computer takeover** — stale computer objects with
  resettable/known passwords (partially via `A-Pre2kComputer`).

> Declined: a dedicated *shadow-credentials* (`msDS-KeyCredentialLink`) finding —
> the escalation (write access to the attribute) is already a control-path / dangerous-ACL
> edge; merely listing accounts that have a key credential set is informational (mostly
> Windows Hello), so it isn't worth a standalone critical finding.
</content>
</invoke>
