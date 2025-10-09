#!/usr/bin/env python3
"""
locks_eol_guard.py

目的:
- ORCH/STATE/LOCKS 配下の JSON/テキストファイルに CRLF が存在する場合、即座に LF に正規化する監視ガード。
- 外部プロセスが CRLF で再生成するケースへの暫定対策として動作し、生成側恒久修正が入るまでの安全網を提供。

使い方:
  python scripts/ops/locks_eol_guard.py --interval 1.0

オプション:
  --interval <sec> : 監視ポーリング間隔（秒）。デフォルト 1.0。
  --once           : 1回だけスキャンして終了（CIプリステップ等で利用）。

仕様:
- .json と .txt を対象。
- バイナリ安全のため、バイト読み取りで CRLF (\r\n) を LF (\n) に置換。
- 置換後に内容が変化した場合のみ書き戻し（UTF-8、newline='\n'）。
- 権限エラーや書き込み失敗はログ出力して継続。

注意:
- 監視対象が高頻度更新の場合、置換タイミングで競合が発生する可能性あり。その場合は生成側の修正（newline='\n'）を優先。
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

LOCKS_DIR = Path("ORCH/STATE/LOCKS")
TARGET_EXTS = {".json", ".txt"}
LOGGER: logging.Logger | None = None


def _has_crlf(data: bytes) -> bool:
    return b"\r\n" in data


def _normalize_crlf_to_lf(data: bytes) -> tuple[bytes, int]:
    """CRLFをLFへ置換し、置換回数も返す。"""
    count = data.count(b"\r\n")
    data = data.replace(b"\r\n", b"\n")
    return data, count


def normalize_file(path: Path) -> tuple[bool, dict]:
    """path の CRLF を LF に正規化。変更があれば (True, info) を返す。

    info: {
        'path': str,
        'timestamp': str,
        'prev_size': int,
        'new_size': int,
        'delta_size': int,
        'replaced_count': int
    }
    """
    try:
        info = {
            'path': str(path),
            'timestamp': datetime.now().isoformat(),
            'prev_size': 0,
            'new_size': 0,
            'delta_size': 0,
            'replaced_count': 0,
        }
        if not path.exists():
            return False, info
        raw = path.read_bytes()
        info['prev_size'] = len(raw)
        if not _has_crlf(raw):
            return False, info
        fixed, replaced = _normalize_crlf_to_lf(raw)
        info['replaced_count'] = replaced
        if fixed == raw:
            return False, info
        # UTF-8 + newline='\n' で書き戻し
        # バイナリから文字列への安全な変換を試みる（失敗時はバイナリのまま）
        try:
            text = fixed.decode("utf-8")
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        except UnicodeDecodeError:
            # バイナリで書き戻し（改行は既に LF 化済み）
            path.write_bytes(fixed)
        try:
            info['new_size'] = path.stat().st_size
        except Exception:
            info['new_size'] = len(fixed)
        info['delta_size'] = info['new_size'] - info['prev_size']
        return True, info
    except Exception as e:
        print(f"[locks_eol_guard] normalize failed for {path}: {e}", file=sys.stderr)
        return False, {}


def scan_once() -> int:
    """LOCKS配下を1回スキャンして正規化。変更数を返す。"""
    if not LOCKS_DIR.exists():
        return 0
    changed = 0
    for entry in LOCKS_DIR.iterdir():
        if entry.is_file() and entry.suffix.lower() in TARGET_EXTS:
            ok, info = normalize_file(entry)
            if ok:
                changed += 1
                if LOGGER:
                    LOGGER.info(
                        "normalized: path=%s replaced=%d prev=%d new=%d delta=%d ts=%s",
                        info.get('path'),
                        info.get('replaced_count', 0),
                        info.get('prev_size', 0),
                        info.get('new_size', 0),
                        info.get('delta_size', 0),
                        info.get('timestamp'),
                    )
    return changed


def _write_heartbeat(heartbeat_file: Path) -> None:
    try:
        heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
        # 軽量な心拍情報を記録（ISO時刻のみ）
        with open(heartbeat_file, "w", encoding="utf-8") as f:
            f.write(datetime.now().isoformat())
    except Exception:
        # 心拍書き込み失敗は致命的ではないため握りつぶす
        pass


def run_guard(interval: float, heartbeat_file: Path | None = None) -> None:
    print(f"[locks_eol_guard] Watching {LOCKS_DIR} every {interval:.2f}s for CRLF -> LF normalization")
    last_mtimes = {}
    # 起動時にもハートビートを発行
    if heartbeat_file:
        _write_heartbeat(heartbeat_file)
    while True:
        try:
            # フルスキャン + mtime比較で軽量化
            for entry in LOCKS_DIR.iterdir():
                if not entry.is_file() or entry.suffix.lower() not in TARGET_EXTS:
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except FileNotFoundError:
                    continue
                prev = last_mtimes.get(entry)
                if prev is None or mtime != prev:
                    # 変更検知時に正規化
                    ok, info = normalize_file(entry)
                    if ok:
                        print(f"[locks_eol_guard] normalized: {entry}")
                        if LOGGER:
                            LOGGER.info(
                                "normalized: path=%s replaced=%d prev=%d new=%d delta=%d ts=%s",
                                info.get('path'),
                                info.get('replaced_count', 0),
                                info.get('prev_size', 0),
                                info.get('new_size', 0),
                                info.get('delta_size', 0),
                                info.get('timestamp'),
                            )
                    last_mtimes[entry] = mtime
        except Exception as e:
            print(f"[locks_eol_guard] scan error: {e}", file=sys.stderr)
        # 心拍（イベントが無くても更新）
        if heartbeat_file:
            _write_heartbeat(heartbeat_file)
        time.sleep(interval)


def _setup_logger(log_file: Path) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("locks_eol_guard")
    logger.setLevel(logging.INFO)
    # Avoid duplicate handlers on re-run
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == str(log_file) for h in logger.handlers):
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="LOCKS EOL Guard (CRLF -> LF)")
    parser.add_argument("--interval", type=float, default=1.0, help="polling interval seconds")
    parser.add_argument("--once", action="store_true", help="run single scan and exit")
    parser.add_argument("--log-file", type=str, default=str(Path("data/logs/current/locks_eol_guard.log")), help="path to log file")
    parser.add_argument("--heartbeat-file", type=str, default=str(Path("data/logs/current/locks_eol_guard.heartbeat")), help="path to heartbeat file")
    args = parser.parse_args(argv)

    # 監視対象の存在確認
    if not LOCKS_DIR.exists():
        try:
            LOCKS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[locks_eol_guard] cannot create {LOCKS_DIR}: {e}", file=sys.stderr)
            return 2

    # ロガー初期化
    global LOGGER
    LOGGER = _setup_logger(Path(args.log_file))

    if args.once:
        changed = scan_once()
        print(f"[locks_eol_guard] scan once done, changed={changed}")
        return 0

    try:
        run_guard(args.interval, Path(args.heartbeat_file) if args.heartbeat_file else None)
    except KeyboardInterrupt:
        print("[locks_eol_guard] stopped by user")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())