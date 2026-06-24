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
| ESC1–16 (ADCS): vulnerable templates, enrollment rights, EDITF_ATTRIBUTESUBJECTALTNAME, enrollment-agent abuse, weak DC cert mappings, CA access-control gaps | **[partial]** | Have ESC1/2/3/4/7/8/9 + key strength. **ESC5/6/10/11/13–16 planned** — several (ESC6/10/11) are CA/DC registry settings not exposed over read-only LDAP; we will add the LDAP-confirmable ones (ESC5 object-ACL, ESC13 issuance-policy→group, ESC15 schema-v1 EKU). |
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
| "**First Seen**: Jun 15, 2026" per finding                               | **[planned]**| Needs baseline/history (see §6). |
| Compliance mapping: **MITRE ATT&CK**, **MITRE Mitigations**, **CIS Controls**, **STIG** | **[partial]** | ATT&CK techniques already mapped; added **MITRE Mitigations + CIS Controls v8 + NIST CSF** chips. **STIG V-ID** mapping **[planned]** (deferred rather than fabricate IDs offline). |
| "PowerShell and ADUC fix steps written for your environment"             | **[partial]**| Remediation steps exist; enriching with copy-able, environment-substituted PowerShell/`ADUC` snippets **[planned]**. |

## 4. Report structure & GUI — "their GUI looks better"

| Insight Recon section                                                    | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| Header: tool name / "SECURITY ASSESSMENT" / DOMAIN / GENERATED date      | **[done]**   | Slim header + dossier already carry these; tightened. |
| Executive **Overview** with score badge + severity breakdown             | **[done]**   | New hero band (grade + score + chips + meters + donut). |
| **Priorities** section                                                   | **[done]**   | Added (Top Priorities + Quick Wins). Added to nav. |
| **Detailed Findings** (filterable)                                       | **[done]**   | Existing filterable/searchable table; added Effort column + framework chips. |
| **Trends & Changes**                                                     | **[planned]**| See §6. |
| Configuration / Environment / Accounts & Groups / Infrastructure / PKI & Certificates / Group Policy sub-sections | **[partial]** | We have Inventory (env/config), Privileged (accounts & groups), Attack Paths, and cert-template inventory. **Dedicated PKI and GPO views [planned].** |
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

## 6. Trends & change tracking — "Prove you're actually getting better." **[planned this pass]**

Insight Recon: "Risk Posture Score over time", "New / Remediated / Modified / Unchanged", "Fixed since last scan". Plan:

1. **`--baseline prev.json`** — diff current findings against a prior SCOUT JSON;
   compute **New / Fixed / Unchanged / Modified** (by rule_id + affected-set) and
   render a "Changes since last scan" panel + **First Seen** per finding.
2. **Scan history store** — append each run's `{ts, posture, exposure, hygiene,
   sev_counts}` to a local `scout_history.json`; render a **risk-posture-over-time**
   sparkline in the hero.
3. **Per-finding lifecycle** — first_seen / last_seen / age, "remediated since".

## 7. Cloud / Entra — "A Microsoft 365 and Entra ID version is in the works"

| Insight Recon                                                            | SCOUT status | Notes |
|--------------------------------------------------------------------------|--------------|-------|
| On-prem AD first; M365/Entra ID next                                     | **[partial]**| On-prem Entra surface (`A-AADConnectSync`, `A-SeamlessSSO`) detected. Full Entra/M365 assessment (Graph-based) **[planned, large]** — separate mode, not read-only LDAP. |

---

## Shipped in this pass (Insight-Recon parity v1)

- Posture **score (0–100) + A–F grade** hero, severity chips, contributing meters.
- **Priorities** section: Top Priorities *ranked by exploitability* + **Quick Wins**.
- **Remediation effort** (Low/Moderate/High) on every finding + findings-table column.
- **Rich affected-object tables** (enabled / created / pwd-set / last-logon / flags) + **inline CSV export**.
- **Framework mappings**: CIS Controls v8 + NIST CSF + MITRE Mitigations chips (alongside existing ATT&CK).
- GUI re-polish in SCOUT's field/army theme to match Insight Recon's cleaner card/badge layout.

## Next up (highest leverage first)

1. **Trends & changes** (`--baseline` diff + First Seen) — §6.1.
2. **Shadow credentials** (`msDS-KeyCredentialLink`) detection — §2 PAM gap.
3. **ADCS ESC5/13/15** (LDAP-confirmable) — §2 ADCS gap.
4. **STIG V-ID** mapping + environment-substituted **PowerShell** remediation — §3.
5. **Dedicated PKI & Group Policy report sections** — §4.
6. **Scan-progress UX** + scheduled/baseline mode — §5.
</content>
</invoke>
