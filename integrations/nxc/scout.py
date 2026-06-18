"""
NetExec (nxc) LDAP module — runs the SCOUT AD assessment engine over an
already-authenticated nxc LDAP connection and writes SCOUT's interactive HTML
(+ optional JSON) report. Roadmap item 8.

Install:
    cp integrations/nxc/scout.py ~/.nxc/modules/scout.py
    # tell the module where scout.py lives (once):
    export SCOUT_PATH=/path/to/SCOUT/scout.py

Usage:
    nxc ldap <dc> -u user -p pass -M scout
    nxc ldap <dc> -u user -H :<nthash> -k -M scout -o OUTPUT=/tmp/r.html NO_PATHS=true
    nxc ldap <dc> -u user -p pass -M scout -o PATH=/path/to/SCOUT/scout.py

This reuses nxc's authenticated impacket LDAP connection (no second bind). It is
an LDAP-only assessment: SMB/SYSVOL checks (GPP cpassword, SMB signing) are not
run here — use nxc's own modules for those.
"""
import os
import sys
import importlib.util
import contextlib
import io

# Newer NetExec requires a `category`; older releases don't have CATEGORY at all.
try:
    from nxc.helpers.misc import CATEGORY as _CATEGORY
    _SCOUT_CATEGORY = _CATEGORY.ENUMERATION
except Exception:
    _SCOUT_CATEGORY = "Enumeration"


class NXCModule:
    name = "scout"
    description = "Run the SCOUT AD security assessment and write its HTML/JSON report"
    supported_protocols = ["ldap"]
    category = _SCOUT_CATEGORY
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        PATH      Path to scout.py (else $SCOUT_PATH, else ./scout.py).
        OUTPUT    HTML report path (default scout_<domain>.html in cwd).
        JSON      JSON output path ("true" for default name, or a path).
        NO_PATHS  "true" to skip the control-path graph closure (faster).
        NO_ADCS   "true" to skip ADCS certificate-template checks.
        """
        self.path = module_options.get("PATH") or os.environ.get("SCOUT_PATH") or "scout.py"
        self.output = module_options.get("OUTPUT")
        self.json = module_options.get("JSON")
        self.no_paths = str(module_options.get("NO_PATHS", "false")).lower() == "true"
        self.no_adcs = str(module_options.get("NO_ADCS", "false")).lower() == "true"

    def _load_scout(self, context):
        path = os.path.abspath(os.path.expanduser(self.path))
        if not os.path.isfile(path):
            context.log.fail(f"scout.py not found at '{path}' — set PATH= or $SCOUT_PATH")
            return None
        sys.path.insert(0, os.path.dirname(path))
        spec = importlib.util.spec_from_file_location("scout", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def on_login(self, context, connection):
        scout = self._load_scout(context)
        if scout is None:
            return

        domain = getattr(connection, "domain", "") or getattr(connection, "targetDomain", "")
        dc_ip = getattr(connection, "host", "") or getattr(connection, "target", "")
        args = scout.make_args(domain=domain, dc_ip=dc_ip,
                               no_smb=True, no_paths=self.no_paths, no_adcs=self.no_adcs,
                               no_color=True, verbose=False)

        ad = scout.ADConnection(args)
        try:
            ad.adopt_impacket(connection.ldap_connection)
        except Exception as e:
            context.log.fail(f"SCOUT: could not adopt nxc LDAP connection: {e}")
            return
        context.log.display(f"SCOUT: assessing {domain or dc_ip} (base {ad.base_dn})")

        # SCOUT's collection/analysis print operator-style progress to stdout;
        # capture it so nxc's output stays clean, then surface a summary.
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                data = scout.ADData(ad, args)
                data.collect()
                scout.ACLAnalyzer(ad, data, args).run()
                if not self.no_paths:
                    scout.ControlPathAnalyzer(ad, data, args).run()
                engine = scout.CheckEngine(data, args)
                engine.run_all()
                findings = engine.findings
                scores = scout.RiskScorer(findings, data).score()
        except Exception as e:
            context.log.fail(f"SCOUT: assessment failed: {e}")
            if context.log.level <= 10:  # debug
                context.log.debug(buf.getvalue())
            return

        # Report files
        safe_dom = (domain or dc_ip or "domain").replace("/", "_")
        out = self.output or f"scout_{safe_dom}.html"
        try:
            html = scout.HTMLReporter(domain, dc_ip, findings, scores, data,
                                      auth_mode="nxc/LDAP").render()
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(html)
        except Exception as e:
            context.log.fail(f"SCOUT: report render/write failed: {e}")
            return

        if self.json:
            import json as _json
            jpath = self.json if self.json.lower() != "true" else f"scout_{safe_dom}.json"
            with open(jpath, "w", encoding="utf-8") as jf:
                _json.dump({
                    "domain": domain, "dc_ip": dc_ip, "scores": scores,
                    "findings": [{"rule_id": f.rule_id, "title": f.title,
                                  "severity": f.severity, "operation": scout.op_category(f.rule_id, f.category),
                                  "points": f.points, "details": f.details, "affected": f.affected}
                                 for f in findings],
                }, jf, indent=2)
            context.log.highlight(f"JSON: {jpath}")

        # Summary to nxc
        sev = {}
        for f in findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        context.log.highlight(
            f"Exposure {scores.get('exposure', 0)}/100 ({scores.get('verdict', '')}) · "
            f"Hygiene {scores.get('hygiene', 0)}/100 · {len(findings)} findings "
            f"(CRIT {sev.get('CRITICAL', 0)} · HIGH {sev.get('HIGH', 0)})")
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(findings, key=lambda x: order.get(x.severity, 9))[:12]:
            context.log.highlight(f"  [{f.severity}] {f.rule_id}: {f.title}")
        context.log.highlight(f"Report: {out}")
