# Trae連動サンプル
# Traeのproject_rules.mdで使用

# 例: 成功ケース
& "$env:USERPROFILE\GoverningCore_v5_Slice\scripts\ops\push-to-intake.ps1" `
    -Title "API設計ドキュメント作成" `
    -Prompt "Create API documentation for user authentication endpoints" `
    -Output "## User Authentication API`n`n### POST /auth/login`n- Description: User login`n- Parameters: username, password`n- Returns: JWT token" `
    -Source "Trae" `
    -Domain "write" `
    -TaskType "draft" `
    -Success $true `
    -SuccessReason "明確で構造化されたドキュメント" `
    -UsedMethods "RESTful API設計原則" `
    -Refs "docs/api-spec.md, src/auth/controller.py" `
    -Tags "trae,api,documentation"

# 例: 失敗ケース
# & "$env:USERPROFILE\GoverningCore_v5_Slice\scripts\ops\push-to-intake.ps1" `
#     -Title "データベース設計" `
#     -Prompt "Design database schema for e-commerce system" `
#     -Output "設計が複雑すぎて完成できませんでした" `
#     -Source "Trae" `
#     -Domain "code" `
#     -TaskType "spec" `
#     -Success $false `
#     -FailureReason "要件が不明確で設計方針が定まらない" `
#     -UsedMethods "正規化, リレーショナル設計" `
#     -Tags "trae,database,design,failed"

