#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path


def _import_analyzer(root: Path):
    # Ensure both source and portable dist are available on sys.path
    base = root / ".trae/apk_analysis_system"
    portable = base / "dist" / "apk-analysis-system-1.0.0-portable"
    sys.path.insert(0, str(base))
    if portable.exists():
        sys.path.insert(0, str(portable))
    try:
        from core.enhanced_apk_analyzer import EnhancedAPKAnalyzer
    except Exception:
        from core.utils.enhanced_apk_analyzer import EnhancedAPKAnalyzer
    return EnhancedAPKAnalyzer


def _md(report: dict) -> str:
    a = report.get("static_analysis", {})
    u = report.get("unity_analysis", {})
    i = report.get("il2cpp_analysis", {})
    perms = (a.get("manifest", {}) or {}).get("permissions", [])
    endpoints = a.get("endpoints", [])
    libs = a.get("native_libs", [])
    classes = (i.get("il2cpp", {}) or {}).get("classes", []) or u.get("dll_classes", [])
    lines = [
        f"# APK設計書（自動生成）",
        f"- 生成時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 入力APK: {report.get('apk_path','')}",
        "## 1. メタ情報",
        f"- パッケージ: {a.get('package_name','')}",
        f"- バージョン: {a.get('version_name','')} ({a.get('version_code','')})",
        "## 2. 権限",
        *(f"- {p}" for p in perms),
        "## 3. 依存/ネイティブライブラリ",
        *(f"- {x}" for x in libs[:100]),
        "## 4. ネットワーク/エンドポイント",
        *(f"- {e}" for e in endpoints[:100]),
        "## 5. IL2CPP/Unity概要",
        f"- global-metadata.dat: {report.get('resolved_metadata','')}",
        f"- クラス数: {len(classes)}",
        "## 6. リスクと注意事項",
        "- 文字列解析: Il2CppDumper未導入時はbasic parser結果（要留意）",
        "## 7. 付録（サイズ・ハッシュ等はJSON参照）",
    ]
    return "\n".join(lines)


def main():
    root = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(r"C:\Users\User\Trae\Game_project")
    )
    apk = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else (root / "Trae/Build/Android/TraeGame.apk")
    )
    out_ui = root / "observability/ui/report"
    out_ui.mkdir(parents=True, exist_ok=True)
    out_log = root / "data/logs/current"
    out_log.mkdir(parents=True, exist_ok=True)
    out_mcp = root / "observability/mcp"
    out_mcp.mkdir(parents=True, exist_ok=True)
    # CIではMCPのみへ証跡を書き、ローカルログ(data/logs/current)は抑止
    is_ci = bool(os.getenv("CI"))
    t0 = time.time()

    def _sha256(p: Path) -> str:
        try:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for b in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(b)
            return h.hexdigest()
        except Exception:
            return ""

    # メタデータDIR（未設定なら既定）
    os.environ.setdefault(
        "ENHANCED_ANALYSIS_METADATA_DIR",
        str(
            root
            / "Trae/Build/Android/TraeGame_extracted/assets/bin/Data/Managed/Metadata"
        ),
    )
    # 事前検査
    if not apk.exists():
        ts = time.strftime("%Y%m%d_%H%M%S")
        err = {"error": "apk_not_found", "apk": str(apk), "ts": ts}
        if not is_ci:
            (out_log / f"analysis_error_{apk.stem}_{ts}.json").write_text(
                json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        (out_mcp / f"analysis_error_{apk.stem}_{ts}.json").write_text(
            json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        # Append to MCP manifest (JSONL)
        try:
            manifest = out_mcp / "manifest.jsonl"
            record = {
                "ts": ts,
                "apk": str(apk),
                "status": "apk_not_found",
                "exit_code": 2,
                "outputs": [],
                "apk_sha256": "",
                "duration_ms": int((time.time() - t0) * 1000),
                "commit": os.getenv("GITHUB_SHA", ""),
            }
            with open(manifest, "a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass
        print(f"[ERROR] APK not found: {apk}", file=sys.stderr)
        sys.exit(2)

    Analyzer = _import_analyzer(root)
    ana = Analyzer()
    try:
        res = ana.analyze_apk_enhanced(str(apk))
    except Exception as e:
        ts = time.strftime("%Y%m%d_%H%M%S")
        err = {
            "error": "analyze_failed",
            "apk": str(apk),
            "exception": repr(e),
            "traceback": traceback.format_exc(),
            "ts": ts,
        }
        if not is_ci:
            (out_log / f"analysis_error_{apk.stem}_{ts}.json").write_text(
                json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        (out_mcp / f"analysis_error_{apk.stem}_{ts}.json").write_text(
            json.dumps(err, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        # Append to MCP manifest (JSONL)
        try:
            manifest = out_mcp / "manifest.jsonl"
            record = {
                "ts": ts,
                "apk": str(apk),
                "status": "analyze_failed",
                "exit_code": 1,
                "outputs": [],
                "apk_sha256": _sha256(apk) if apk.exists() else "",
                "duration_ms": int((time.time() - t0) * 1000),
                "commit": os.getenv("GITHUB_SHA", ""),
            }
            with open(manifest, "a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass
        print(f"[ERROR] analyze failed: {e}", file=sys.stderr)
        sys.exit(1)
    # 解析結果に追加メモ
    res["apk_path"] = str(apk)
    res["resolved_metadata"] = str(ana.get_global_metadata_path())
    ts = time.strftime("%Y%m%d_%H%M%S")
    json_path = out_ui / f"analysis_{apk.stem}_{ts}.json"
    md_path = out_ui / f"design_{apk.stem}_{ts}.md"
    json_path.write_text(
        json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md_path.write_text(_md(res), encoding="utf-8")
    # 監査用にも複製
    if not is_ci:
        (out_log / f"analysis_{apk.stem}_{ts}.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    # Append success to MCP manifest (JSONL)
    try:
        manifest = out_mcp / "manifest.jsonl"
        record = {
            "ts": ts,
            "apk": str(apk),
            "status": "success",
            "exit_code": 0,
            "outputs": [str(json_path), str(md_path)],
            "resolved_metadata": str(res.get("resolved_metadata", "")),
            "apk_sha256": _sha256(apk),
            "duration_ms": int((time.time() - t0) * 1000),
            "commit": os.getenv("GITHUB_SHA", ""),
        }
        with open(manifest, "a", encoding="utf-8") as mf:
            mf.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(str(json_path))
    print(str(md_path))
    sys.exit(0)


if __name__ == "__main__":
    main()
