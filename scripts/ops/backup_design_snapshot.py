import datetime
import json
import os
import shutil
import subprocess


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def copy_tree(src: str, dst: str):
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    elif os.path.isfile(src):
        ensure_dir(os.path.dirname(dst))
        shutil.copy2(src, dst)


def get_git_head():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_root = os.path.join(root, "backups", f"design_backup_{ts}")
    ensure_dir(backup_root)

    # Target paths/files to snapshot (UI影響範囲と主要設定)
    targets = [
        (os.path.join(root, "templates"), os.path.join(backup_root, "templates")),
        (os.path.join(root, "src"), os.path.join(backup_root, "src")),
        (os.path.join(root, "config"), os.path.join(backup_root, "config")),
        (
            os.path.join(root, "orch_dashboard.py"),
            os.path.join(backup_root, "orch_dashboard.py"),
        ),
        (
            os.path.join(root, "pyproject.toml"),
            os.path.join(backup_root, "pyproject.toml"),
        ),
        (
            os.path.join(root, "requirements.txt"),
            os.path.join(backup_root, "requirements.txt"),
        ),
        (
            os.path.join(root, "NonStop_Audit.md"),
            os.path.join(backup_root, "NonStop_Audit.md"),
        ),
    ]

    for src, dst in targets:
        if os.path.exists(src):
            copy_tree(src, dst)

    meta = {
        "timestamp": ts,
        "git_head": get_git_head(),
        "note": "Design snapshot prior to major UI changes.",
        "paths": [
            dst
            for _, dst in targets
            if os.path.exists(os.path.join(root, _ if isinstance(_, str) else ""))
        ],
    }
    with open(os.path.join(backup_root, "README.md"), "w", encoding="utf-8") as f:
        f.write(
            "This backup was created before major UI design changes. Restore by copying files back to project root.\n"
        )
    with open(os.path.join(backup_root, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"Backup completed: {backup_root}")


if __name__ == "__main__":
    main()
