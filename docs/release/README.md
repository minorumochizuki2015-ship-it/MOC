リリースパッケージ（共有用）

目的
- リリースやAI共有に必要な成果物（ドキュメント、CI定義、レポート）を1つのフォルダ/ZIPにまとめます。

生成方法（Windows/PowerShell）
- コマンド: `powershell -ExecutionPolicy Bypass -File scripts/ops/build_release.ps1`

出力構成（例）
- release/2025MMDD-HHMMSS/
  - docs/（WORKING_RULES, MILESTONES, チェックリスト）
  - ci/（.github/workflows/ci.yml）
  - reports/
    - coverage.xml / htmlcov/
    - sbom.xml（CycloneDX）
    - diff-cover.html（差分カバレッジ）
- release/latest.zip（上記をZIP化）

備考
- SBOMやdiff-coverはツール未導入時は自動でスキップします。
- 追加の成果物が必要な場合は scripts/ops/build_release.ps1 を編集してください。