# Cursor連動サンプル
# CursorのTasks/Commandで使用

# 例: 成功ケース（自動パイプライン有効）
& "$env:USERPROFILE\GoverningCore_v5_Slice\scripts\ops\push-to-intake.ps1" `
    -Title "Python関数作成" `
    -Prompt "Write a Python function to add two numbers" `
    -Output "def add_numbers(a, b):`n    return a + b" `
    -Source "Cursor" `
    -Domain "code" `
    -TaskType "edit" `
    -Success $true `
    -SuccessReason "シンプルで読みやすい関数" `
    -UsedMethods "SRP" `
    -Refs "src/math.py" `
    -Tags "cursor,math,function"

# 例: 失敗ケース
# & "$env:USERPROFILE\GoverningCore_v5_Slice\scripts\ops\push-to-intake.ps1" `
#     -Title "複雑なアルゴリズム実装" `
#     -Prompt "Implement a complex sorting algorithm" `
#     -Output "実装できませんでした" `
#     -Source "Cursor" `
#     -Domain "code" `
#     -TaskType "edit" `
#     -Success $false `
#     -FailureReason "アルゴリズムの理解が不十分" `
#     -UsedMethods "アルゴリズム設計" `
#     -Tags "cursor,algorithm,failed"
