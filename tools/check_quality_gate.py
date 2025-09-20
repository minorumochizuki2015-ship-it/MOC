# UTF-8
import json
import pathlib
import subprocess
import sys
from datetime import datetime


def run_command(cmd):
    """コマンド実行"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def check_git_checkpoint():
    """Gitチェックポイント確認"""
    success, stdout, stderr = run_command("git log --oneline -1")
    if success and stdout.strip():
        return True, "Gitチェックポイント確認済み"
    return False, "Gitチェックポイント未作成"

def check_backup():
    """バックアップ確認"""
    backup_dir = pathlib.Path("backups")
    if backup_dir.exists() and list(backup_dir.glob("*.backup_*")):
        return True, "バックアップ確認済み"
    return False, "バックアップ未作成"

def check_tests():
    """テスト実行"""
    # Python実行ファイルの決定
    py = r".venv/Scripts/python.exe" if pathlib.Path(r".venv/Scripts/python.exe").exists() else sys.executable
    
    # 単体テスト
    success, stdout, stderr = run_command(f"{py} -m pytest -q")
    if not success:
        return False, f"単体テスト失敗: {stderr}"
    
    # 型チェック
    success, stdout, stderr = run_command(f"{py} -m mypy src/")
    if not success:
        return False, f"型チェック失敗: {stderr}"
    
    return True, "全テスト合格"

def check_ui_test():
    """UIテスト実行"""
    # Python実行ファイルの決定
    py = r".venv/Scripts/python.exe" if pathlib.Path(r".venv/Scripts/python.exe").exists() else sys.executable
    
    success, stdout, stderr = run_command(f"{py} main_modern.py --test-ui")
    if not success:
        return False, f"UIテスト失敗: {stderr}"
    return True, "UIテスト合格"

def main():
    """品質ゲートチェック"""
    print("=== 品質ゲートチェック ===")
    
    checks = [
        ("Gitチェックポイント", check_git_checkpoint),
        ("バックアップ", check_backup),
        ("テスト実行", check_tests),
        ("UIテスト", check_ui_test),
    ]
    
    results = []
    all_passed = True
    
    for name, check_func in checks:
        passed, message = check_func()
        results.append({
            "name": name,
            "passed": passed,
            "message": message
        })
        status = "✅" if passed else "❌"
        print(f"{status} {name}: {message}")
        if not passed:
            all_passed = False
    
    # 結果をログに保存
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "all_passed": all_passed,
        "results": results
    }
    
    log_file = pathlib.Path("data/logs/current/quality_gate.jsonl")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_data, ensure_ascii=False) + "\n")
    
    if not all_passed:
        print("\n❌ 品質ゲート失敗: 実装を禁止します")
        sys.exit(1)
    else:
        print("\n✅ 品質ゲート合格: 実装を許可します")

if __name__ == "__main__":
    main()
