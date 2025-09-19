#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker起動テストスクリプト
実地環境でのDocker起動機能をテストします
"""

import os
import subprocess
import time
from pathlib import Path


def check_docker_available():
    """Dockerが利用可能かチェック"""
    try:
        # まずdockerコマンドが存在するかチェック
        result = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            print("❌ Dockerコマンドが見つかりません")
            return False

        # Dockerデーモンが実際に動作しているかチェック
        result = subprocess.run(
            ["docker", "ps"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print("✅ Docker Desktopは既に起動しています")
            return True
        else:
            print("❌ Dockerデーモンが起動していません")
            return False
    except Exception as e:
        print(f"❌ Dockerチェックエラー: {e}")
        return False


def find_docker_desktop():
    """Docker Desktopのパスを検索"""
    docker_paths = [
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
        r"C:\Users\{}\AppData\Local\Docker\Docker Desktop.exe".format(
            os.getenv("USERNAME", "")
        ),
        r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
        r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Docker Desktop\Docker Desktop.lnk".format(
            os.getenv("USERNAME", "")
        ),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Docker Desktop\Docker Desktop.lnk",
    ]

    for path in docker_paths:
        if Path(path).exists():
            print(f"✅ Docker Desktop発見: {path}")
            return path

    print("❌ Docker Desktopが見つかりません")
    return None


def start_docker_desktop(docker_path):
    """Docker Desktopを起動"""
    try:
        print(f"🚀 Docker Desktop起動中: {docker_path}")

        # 複数の方法で起動を試行
        methods = [
            lambda: subprocess.Popen([docker_path], shell=True),
            lambda: subprocess.Popen(
                [docker_path], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE
            ),
            lambda: subprocess.run([docker_path], shell=True, check=False),
        ]

        for i, method in enumerate(methods):
            try:
                print(f"  方法 {i+1} を試行中...")
                method()
                print(f"✅ 方法 {i+1} で起動成功")
                return True
            except Exception as e:
                print(f"⚠️ 方法 {i+1} 失敗: {e}")
                continue

        print("❌ すべての起動方法が失敗しました")
        return False

    except Exception as e:
        print(f"❌ Docker起動エラー: {e}")
        return False


def wait_for_docker(max_seconds=180):
    """Docker起動を待機"""
    print(f"⏳ Docker Desktop起動待機中... (最大{max_seconds}秒)")

    for i in range(max_seconds):
        time.sleep(1)
        if check_docker_available():
            print("✅ Docker Desktop起動完了")
            return True

        # 進捗表示（15秒ごと）
        if i % 15 == 0 and i > 0:
            print(f"⏳ Docker Desktop起動中... ({i+1}/{max_seconds}秒)")

    print("⚠️ Docker Desktop起動タイムアウト")
    return False


def main():
    """メイン関数"""
    print("=" * 60)
    print("Docker起動テストスクリプト")
    print("=" * 60)

    # 1. Docker状態チェック
    print("\n[1] Docker状態チェック")
    if check_docker_available():
        print("Docker Desktopは既に起動しています。テスト完了。")
        return

    # 2. Docker Desktopパス検索
    print("\n[2] Docker Desktopパス検索")
    docker_path = find_docker_desktop()
    if not docker_path:
        print("Docker Desktopが見つかりません。手動でインストールしてください。")
        return

    # 3. Docker Desktop起動
    print("\n[3] Docker Desktop起動")
    if not start_docker_desktop(docker_path):
        print("Docker Desktop起動に失敗しました。")
        return

    # 4. 起動待機
    print("\n[4] 起動待機")
    if wait_for_docker():
        print("\n✅ テスト完了: Docker Desktopが正常に起動しました")
    else:
        print("\n❌ テスト失敗: Docker Desktopの起動に時間がかかりすぎています")


if __name__ == "__main__":
    main()
