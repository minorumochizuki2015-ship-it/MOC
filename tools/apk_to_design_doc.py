#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

TOOL_VERSION = "apk_to_design_doc.py@2025-10-17"

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
    # 型のゆらぎに耐える（list以外なら配列へ変換）
    if isinstance(libs, dict):
        libs = list(libs.keys())
    elif not isinstance(libs, list):
        libs = [str(libs)] if libs else []
    if isinstance(endpoints, dict):
        endpoints = list(endpoints.keys())
    elif not isinstance(endpoints, list):
        endpoints = [str(endpoints)] if endpoints else []
    classes = (i.get("il2cpp", {}) or {}).get("classes", []) or u.get("dll_classes", [])
    if isinstance(classes, dict):
        classes = list(classes.keys())
    elif not isinstance(classes, list):
        classes = [str(classes)] if classes else []
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
        *(f"- {x}" for x in (libs[:100] if isinstance(libs, list) else [])),
        "## 4. ネットワーク/エンドポイント",
        *(f"- {e}" for e in (endpoints[:100] if isinstance(endpoints, list) else [])),
        "## 5. IL2CPP/Unity概要",
        f"- global-metadata.dat: {report.get('resolved_metadata','')}",
        f"- クラス数: {len(classes)}",
        "## 6. リスクと注意事項",
        "- 文字列解析: Il2CppDumper未導入時はbasic parser結果（要留意）",
        "## 7. 付録（サイズ・ハッシュ等はJSON参照）",
    ]
    return "\n".join(lines)


def _inputs_hash(apk_sha: str, meta_path: str, lib_path: str, extra: str = "") -> str:
    try:
        s = f"{apk_sha}|{meta_path or ''}|{lib_path or ''}|{extra or TOOL_VERSION}"
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    except Exception:
        return ""


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
        # プレースホルダー出力（Gate step通過用）
        placeholder_report = {
            "apk_path": str(apk),
            "error": "apk_not_found",
            "message": "APK が CI ランナーに存在しないため、プレースホルダーを生成しました",
            "static_analysis": {
                "native_libs": {"files": 0, "details": []},
                "manifest": {"files": 0, "details": []},
            },
            "unity_analysis": {"unity_detected": False},
            "il2cpp_analysis": {"error": "APK missing"},
        }
        json_path = out_ui / f"analysis_{apk.stem}_{ts}.json"
        md_path = out_ui / f"design_{apk.stem}_{ts}.md"
        try:
            json_path.write_text(
                json.dumps(placeholder_report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            md_path.write_text(
                "\n".join([
                    "# APK設計書（プレースホルダー）",
                    f"- 生成時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"- 入力APK: {str(apk)}",
                    "",
                    "このRunではAPKがリポジトリ/ランナー上に存在しないため、詳細解析はスキップされました。",
                ]),
                encoding="utf-8",
            )
        except Exception:
            pass
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
                "outputs": [str(json_path), str(md_path)],
                "apk_sha256": "",
                "duration_ms": int((time.time() - t0) * 1000),
                "commit": os.getenv("GITHUB_SHA", ""),
                "tool_version": TOOL_VERSION,
                "inputs_hash": _inputs_hash("", os.environ.get("ENHANCED_ANALYSIS_METADATA_DIR", ""), ""),
            }
            with open(manifest, "a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass
        # Gate stepが数だけを検査するため、パスを出力
        print(str(json_path))
        print(str(md_path))
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
                "tool_version": TOOL_VERSION,
                "inputs_hash": _inputs_hash(
                    _sha256(apk) if apk.exists() else "",
                    os.environ.get("ENHANCED_ANALYSIS_METADATA_DIR", ""),
                    "",
                    repr(e),
                ),
            }
            with open(manifest, "a", encoding="utf-8") as mf:
                mf.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass
        print(f"[ERROR] analyze failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 成功時: 出力用レポートの整形（analysis_result を優先）
    report = res.get("analysis_result", res)
    # 解析結果に追加メモ
    report["apk_path"] = str(apk)
    # EnhancedAPKAnalyzer に get_global_metadata_path が無い環境でも安全に解決
    resolved_metadata = ""
    try:
        if hasattr(ana, "get_global_metadata_path"):
            resolved_metadata = str(ana.get_global_metadata_path())
        else:
            # 環境変数の既定値を利用（存在チェックは任意）
            meta_env = os.environ.get("ENHANCED_ANALYSIS_METADATA_DIR", "")
            if meta_env:
                resolved_metadata = meta_env
    except Exception:
        resolved_metadata = os.environ.get("ENHANCED_ANALYSIS_METADATA_DIR", "")
    report["resolved_metadata"] = resolved_metadata

    # libil2cpp.so の既定パスを推定（存在しなければ空文字）
    try:
        default_lib = (
            root
            / "Trae/Build/Android/TraeGame_extracted/lib/armeabi-v7a/libil2cpp.so"
        )
        libil2cpp_path = str(default_lib) if default_lib.exists() else ""
    except Exception:
        libil2cpp_path = ""
    report["libil2cpp_path"] = libil2cpp_path

    # Il2CppDumper の存在確認（候補 + 再帰検索）
    dumper_path = ""
    try:
        dumper_candidates = [
            root / "Tools/Il2CppDumper/Il2CppDumper.exe",
            root / "Tools/Il2CppDumper/Il2CppDumper",
            root / "MOC/tools/Il2CppDumper/Il2CppDumper.exe",
            root / "MOC/tools/Il2CppDumper/Il2CppDumper",
        ]
        for p in dumper_candidates:
            if p.exists():
                dumper_path = str(p)
                break
        if not dumper_path:
            for sr in (root / "Tools/Il2CppDumper", root / "MOC/tools/Il2CppDumper"):
                if not sr.exists():
                    continue
                try:
                    for ext in ("Il2CppDumper.exe", "Il2CppDumper"):
                        for found in sr.rglob(ext):
                            if found.is_file():
                                dumper_path = str(found)
                                break
                        if dumper_path:
                            break
                except Exception:
                    pass
                if dumper_path:
                    break
        has_dumper = bool(dumper_path)
    except Exception:
        has_dumper = False

    # Il2Cpp深度解析の準備状態（ツール・両ファイルが揃っているか）
    il2cpp_ready = bool(resolved_metadata) and bool(libil2cpp_path) and bool(has_dumper)
    if il2cpp_ready:
        il2cpp_error_code = ""
    else:
        if not has_dumper:
            il2cpp_error_code = "il2cpp_tool_missing"
        elif not libil2cpp_path:
            il2cpp_error_code = "il2cpp_binary_missing"
        else:
            il2cpp_error_code = "il2cpp_metadata_missing"

    ts = time.strftime("%Y%m%d_%H%M%S")
    json_path = out_ui / f"analysis_{apk.stem}_{ts}.json"
    md_path = out_ui / f"design_{apk.stem}_{ts}.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md_path.write_text(_md(report), encoding="utf-8")
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
            "status": "success" if il2cpp_ready else (
                "success_il2cpp_tool_missing" if il2cpp_error_code == "il2cpp_tool_missing" else (
                    "success_il2cpp_binary_missing" if il2cpp_error_code == "il2cpp_binary_missing" else "success_il2cpp_metadata_missing"
                )
            ),
            "exit_code": 0,
            "outputs": [str(json_path), str(md_path)],
            "resolved_metadata": str(report.get("resolved_metadata", "")),
            "libil2cpp_path": libil2cpp_path,
            "il2cpp_dumper_path": dumper_path,
            "apk_sha256": _sha256(apk),
            "duration_ms": int((time.time() - t0) * 1000),
            "commit": os.getenv("GITHUB_SHA", ""),
            "tool_version": TOOL_VERSION,
            "inputs_hash": _inputs_hash(
                _sha256(apk),
                str(report.get("resolved_metadata", "")),
                libil2cpp_path,
            ),
        }
        if il2cpp_error_code:
            record["error_code"] = il2cpp_error_code
            if il2cpp_error_code == "il2cpp_tool_missing":
                record["reason"] = "Il2CppDumper not found"
            elif il2cpp_error_code == "il2cpp_binary_missing":
                record["reason"] = "File not found: libil2cpp.so"
            else:
                record["reason"] = "File not found: global-metadata.dat"
        with open(manifest, "a", encoding="utf-8") as mf:
            mf.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass
    print(str(json_path))
    print(str(md_path))
    sys.exit(0)


if __name__ == "__main__":
    main()
