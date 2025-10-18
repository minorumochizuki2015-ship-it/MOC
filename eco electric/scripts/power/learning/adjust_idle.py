#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Learning module: Safely adjust idle_minutes_ac/dc based on telemetry.

Features per audit requirements:
- Unified logging via cfg.logs.base → data/logs/current/learning.log (fallback: artifacts/power/learning.log)
- Externalized bounds (min/max/deadband), min_samples, ignore_recent_minutes
- Only adjust when deviation exceeds deadband, capped by ±max_adjust_minutes
- Atomic write with tmp verification and bak backup; optional rollback-on-fail

Usage:
  py -3 scripts/power/learning/adjust_idle.py --apply
"""
import argparse
import csv
import json
import os
import statistics
import sys
from datetime import datetime, timedelta

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
POWER_DIR = os.path.join(REPO_ROOT, "artifacts", "power")  # telemetry base
CFG_PATH = os.path.join(REPO_ROOT, "config", "power_profile.json")
LOG_PATH = None  # will be set from cfg.logs.base


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        if LOG_PATH:
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            # fallback
            os.makedirs(POWER_DIR, exist_ok=True)
            fallback = os.path.join(POWER_DIR, "learning.log")
            with open(fallback, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass
    print(line)


def read_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_config_atomic(path: str, data: dict, tmp_suffix: str = ".tmp", bak_suffix: str = ".bak"):
    # backup
    bak = path + bak_suffix
    try:
        if os.path.exists(path):
            if os.path.exists(bak):
                os.remove(bak)
            os.replace(path, bak)
    except Exception as e:
        log(f"WARN: backup failed: {e}")
    # write tmp and verify
    tmp = path + tmp_suffix
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    try:
        with open(tmp, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as e:
        log(f"ERROR: tmp parse failed: {e}")
        raise
    os.replace(tmp, path)


def parse_bool(s: str) -> bool:
    return str(s).strip().lower() in ("true", "1", "yes")


def load_telemetry(window_days: int, ignore_recent_minutes: int):
    rows = []
    # main + rotated files
    main_csv = os.path.join(POWER_DIR, "telemetry.csv")
    files = []
    if os.path.exists(main_csv):
        files.append(main_csv)
    now = datetime.now()
    for i in range(window_days):
        d = (now - timedelta(days=i + 1)).strftime("%Y%m%d")
        p = os.path.join(POWER_DIR, f"telemetry_{d}.csv")
        if os.path.exists(p):
            files.append(p)
    cutoff = datetime.now() - timedelta(minutes=ignore_recent_minutes)
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                r = csv.DictReader(f)
                for row in r:
                    ts = row.get("timestamp")
                    if ts:
                        try:
                            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            if dt >= cutoff:
                                continue
                        except Exception:
                            pass
                    rows.append(row)
        except Exception as e:
            log(f"WARN: failed to read {fp}: {e}")
    return rows


def extract_idle_samples(rows, on_ac: bool) -> list:
    samples = []
    for row in rows:
        line_status = row.get("line_status", "")
        is_online = line_status == "Online"
        if is_online != on_ac:
            continue
        try:
            can_idle = parse_bool(row.get("canIdle", "false"))
            cpu_pct = float(row.get("cpu_pct", "0"))
            cpu_th = float(row.get("cpu_th", "100"))
            idle_sec = float(row.get("input_idle_sec", "0"))
        except Exception:
            continue
        if not can_idle:
            continue
        if cpu_pct <= cpu_th and idle_sec > 0:
            samples.append(idle_sec / 60.0)
    return samples


def clamp_adjust(current: float, target: float, max_adjust: int, deadband_min: float) -> int:
    """
    Move threshold toward target within ±max_adjust, with deadband of ±deadband_min.
    Returns delta minutes (int), positive=increase threshold, negative=decrease.
    """
    if target == 0:
        return 0
    if (current - deadband_min) <= target <= (current + deadband_min):
        return 0
    if target < current - deadband_min:
        delta = min(max_adjust, int(round(current - target)))
        return +delta
    else:
        delta = min(max_adjust, int(round(target - current)))
        return -delta


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Apply changes to config")
    parser.add_argument(
        "--rollback-on-fail", action="store_true", help="Rollback config from .bak on failure"
    )
    parser.add_argument("--config", default=CFG_PATH)
    args = parser.parse_args()

    # config
    cfg = read_config(args.config)
    # logging path
    global LOG_PATH
    logs_base = None
    try:
        logs_base = cfg.get("logs", {}).get("base")
    except Exception:
        logs_base = None
    if logs_base:
        LOG_PATH = os.path.join(REPO_ROOT, logs_base, "learning.log")
    else:
        LOG_PATH = os.path.join(POWER_DIR, "learning.log")
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    learning = cfg.get("learning", {})
    enabled = bool(learning.get("enabled", False))
    window_days = int(learning.get("window_days", 7))
    max_adjust = int(learning.get("max_adjust_minutes", 3))

    bounds_cfg = cfg.get("learning_bounds", {})
    ac_bounds = bounds_cfg.get("idle_minutes_ac", {"min": 1, "max": 30, "deadband_min": 2})
    dc_bounds = bounds_cfg.get("idle_minutes_dc", {"min": 1, "max": 20, "deadband_min": 2})
    min_samples = int(bounds_cfg.get("min_samples", 50))
    ignore_recent_minutes = int(bounds_cfg.get("ignore_recent_minutes", 30))

    write_atomic_cfg = cfg.get(
        "write_atomic", {"enabled": True, "tmp_suffix": ".tmp", "bak_suffix": ".bak"}
    )
    tmp_suffix = write_atomic_cfg.get("tmp_suffix", ".tmp")
    bak_suffix = write_atomic_cfg.get("bak_suffix", ".bak")

    if not enabled:
        log("learning.enabled=false: no-op")
        return 0

    rows = load_telemetry(window_days, ignore_recent_minutes)
    if not rows:
        log("ERROR: no telemetry rows available; abort")
        return 1

    ac_samples = extract_idle_samples(rows, on_ac=True)
    dc_samples = extract_idle_samples(rows, on_ac=False)
    sample_count_total = len(ac_samples) + len(dc_samples)
    if sample_count_total < min_samples:
        log(f"INFO: Not enough samples ({sample_count_total} < {min_samples}); no adjust.")
        return 0

    current_ac = float(cfg.get("idle_minutes_ac", 10))
    current_dc = float(cfg.get("idle_minutes_dc", 5))

    med_ac = float(statistics.median(ac_samples)) if ac_samples else 0.0
    med_dc = float(statistics.median(dc_samples)) if dc_samples else 0.0

    adj_ac = clamp_adjust(current_ac, med_ac, max_adjust, float(ac_bounds.get("deadband_min", 2)))
    adj_dc = clamp_adjust(current_dc, med_dc, max_adjust, float(dc_bounds.get("deadband_min", 2)))
    proposed_ac = int(max(1, round(current_ac + adj_ac)))
    proposed_dc = int(max(1, round(current_dc + adj_dc)))
    # clamp to bounds
    proposed_ac = max(int(ac_bounds.get("min", 1)), min(int(ac_bounds.get("max", 30)), proposed_ac))
    proposed_dc = max(int(dc_bounds.get("min", 1)), min(int(dc_bounds.get("max", 20)), proposed_dc))

    log(
        f"AC: current={current_ac}m median={med_ac:.2f}m adjust={adj_ac} → proposed={proposed_ac}m (samples={len(ac_samples)})"
    )
    log(
        f"DC: current={current_dc}m median={med_dc:.2f}m adjust={adj_dc} → proposed={proposed_dc}m (samples={len(dc_samples)})"
    )

    changed = (proposed_ac != int(current_ac)) or (proposed_dc != int(current_dc))
    if not changed:
        log("No change within deadband/margin; config remains the same.")
        return 0

    if args.apply:
        new_cfg = dict(cfg)
        new_cfg["idle_minutes_ac"] = proposed_ac
        new_cfg["idle_minutes_dc"] = proposed_dc
        try:
            write_config_atomic(args.config, new_cfg, tmp_suffix=tmp_suffix, bak_suffix=bak_suffix)
            log("Config updated successfully.")
            return 0
        except Exception as e:
            log(f"ERROR: failed to write config: {e}")
            if args.rollback_on_fail:
                try:
                    bak = args.config + bak_suffix
                    if os.path.exists(bak):
                        os.replace(bak, args.config)
                    log("Rolled back to backup.")
                except Exception as e2:
                    log(f"WARN: rollback failed: {e2}")
            return 2
    else:
        log("Dry-run: Use --apply to write proposed changes.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
