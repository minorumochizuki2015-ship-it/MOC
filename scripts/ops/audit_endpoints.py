#!/usr/bin/env python3
"""
Audit endpoints for ORCH dashboard: agent APIs and key health routes.
Writes a human-readable report to ORCH/REPORTS/AGENTS_API_AUDIT.md and a JSON summary.

Usage:
  python scripts/ops/audit_endpoints.py [BASE_URL]

Examples:
  python scripts/ops/audit_endpoints.py            # defaults to http://127.0.0.1:5001
  python scripts/ops/audit_endpoints.py http://localhost:5001

Notes:
  - The audit targets a single base URL (default port 5001) to avoid confusion from multiple instances.
  - A brief summary line is appended to ORCH/REPORTS/NonStop_Audit.md for dashboard visibility.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
REPORT_MD = BASE_DIR / "ORCH" / "REPORTS" / "AGENTS_API_AUDIT.md"
REPORT_JSON = BASE_DIR / "ORCH" / "REPORTS" / "agents_api_audit_summary.json"
NONSTOP_MD = BASE_DIR / "ORCH" / "REPORTS" / "NonStop_Audit.md"
HEARTBEAT_JSON = BASE_DIR / "ORCH" / "STATE" / "LOCKS" / "heartbeat.json"

# Optional LF-safe writer for LOCKS files
try:
    from src.tools.eol_utils import write_json_lf  # type: ignore
except Exception:
    write_json_lf = None  # fallback below


def fetch(url: str, method: str = "GET", data: dict | None = None, timeout: int = 8):
    result = {
        "url": url,
        "method": method,
        "ok": False,
        "status": None,
        "error": None,
        "body": None,
    }
    try:
        if data is not None:
            payload = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method=method,
            )
        else:
            req = urllib.request.Request(url, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            result["ok"] = True
            result["status"] = r.status
            result["body"] = body
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["error"] = f"HTTPError: {e.reason}"
        try:
            result["body"] = e.read().decode("utf-8")
        except Exception:
            pass
    except Exception as e:
        result["error"] = f"Error: {e}"
    return result


def write_report(md_path: Path, json_path: Path, results: list[dict]):
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    # Summarize
    summary = {
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "totals": {
            "count": len(results),
            "ok": sum(1 for r in results if r.get("ok")),
            "errors": sum(1 for r in results if not r.get("ok")),
        },
        "by_url": results,
    }
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = []
    lines.append("# AGENTS API Audit Report\n")
    lines.append(f"Generated: {summary['generated_at']}\n")
    lines.append(
        f"Total checks: {summary['totals']['count']} | OK: {summary['totals']['ok']} | Errors: {summary['totals']['errors']}\n"
    )
    lines.append("\n## Results\n")
    for r in results:
        status = r.get("status")
        ok = r.get("ok")
        err = r.get("error")
        lines.append(
            f"- [{'OK' if ok else 'ERR'}] {r['method']} {r['url']} status={status} error={err or ''}"
        )
    lines.append("\n## Notes\n")
    lines.append(
        "- If errors indicate 404 on /status or /api/system-health, verify that the running instance includes those routes and that you are calling the correct port."
    )
    lines.append(
        "- UI does not yet include an Agent Management tab; backend APIs can be used via HTTP until UI is added."
    )
    md_path.write_text("\n".join(lines), encoding="utf-8")

    # Append brief summary to NonStop_Audit.md
    try:
        ts = summary["generated_at"]
        line = f"- [{ts}] Endpoint audit: total={summary['totals']['count']}, ok={summary['totals']['ok']}, errors={summary['totals']['errors']}\n"
        prev = (
            NONSTOP_MD.read_text(encoding="utf-8") if NONSTOP_MD.exists() else "# NonStop Audit\n\n"
        )
        NONSTOP_MD.write_text(prev + "\n" + line, encoding="utf-8")
    except Exception:
        pass

    # Update audit heartbeat (LOCKS/heartbeat.json)
    try:
        ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        obj = {}
        if HEARTBEAT_JSON.exists():
            try:
                obj = json.loads(HEARTBEAT_JSON.read_text(encoding="utf-8")) or {}
            except Exception:
                obj = {}
        obj["AUDIT"] = ts
        # Preserve last work time if present; do not overwrite other keys
        if write_json_lf:
            write_json_lf(HEARTBEAT_JSON, obj, ensure_ascii=False, indent=2)
        else:
            HEARTBEAT_JSON.parent.mkdir(parents=True, exist_ok=True)
            with open(HEARTBEAT_JSON, "w", encoding="utf-8", newline="\n") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
    except Exception:
        # Heartbeat update is non-critical; ignore errors
        pass


def main():
    # Determine base URL (default to 127.0.0.1:5001)
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5001"
    if not base.startswith("http"):
        base = f"http://{base}"

    results = []

    # Agent API on selected base
    results.append(fetch(base + "/api/agents/list"))
    results.append(
        fetch(
            base + "/api/agents/register",
            method="POST",
            data={
                "id": "AG-AUDIT",
                "role": "qa-expert",
                "capabilities": ["audit", "report"],
                "status": "registered",
            },
        )
    )
    results.append(
        fetch(
            base + "/api/agents/heartbeat",
            method="POST",
            data={
                "id": "AG-AUDIT",
                "status": "active",
                "metrics": {"cpu": 3, "mem": 11},
            },
        )
    )
    results.append(
        fetch(
            base + "/api/agents/report",
            method="POST",
            data={
                "id": "AG-AUDIT",
                "summary": "audit registration & heartbeat ok",
                "details": {"phase": "init"},
            },
        )
    )
    results.append(fetch(base + "/api/agents/list"))

    # Key endpoints on the same base
    results.append(fetch(base + "/status"))
    results.append(fetch(base + "/api/system-health"))
    results.append(fetch(base + "/api/work/progress"))

    write_report(REPORT_MD, REPORT_JSON, results)
    print(f"Audit report written: {REPORT_MD}")
    print(f"Audit summary written: {REPORT_JSON}")


if __name__ == "__main__":
    sys.exit(main())
