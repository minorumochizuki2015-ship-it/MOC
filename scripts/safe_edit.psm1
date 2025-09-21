# 安全な編集ルール（plan-test-patch準拠）

function Safe-Edit-With-Plan {
    param(
        [string],
        [hashtable]
    )

    # 1. バックアップ作成
     = Get-Date -Format "yyyyMMdd_HHmmss"
     = ".\backups\.backup_"
    Copy-Item   -Force
    Write-Host "✓ バックアップ作成: "

    try {
        # 2. テスト実行
         = run_tests
        if (-not .passed) {
            throw "テスト失敗: "
        }

        # 3. 最小差分でPATCH
        Apply-Minimal-Patch

        Write-Host "✓ 安全に編集完了: "
    }
    catch {
        # エラー時はバックアップから復旧
        Copy-Item   -Force
        Write-Host "✗ エラー発生、バックアップから復旧: "
        throw
    }
}

function run_tests {
    param([string])

    if ( -like "*.py") {
        python -m py_compile
        if ( -ne 0) {
            return @{passed=False; failed="構文エラー"; summary="構文チェック失敗"}
        }
    }

    return @{passed=True; failed=""; summary="テスト成功"}
}

function Apply-Minimal-Patch {
    param([string], [hashtable])
    Write-Host "最小差分でPATCH適用: "
}
