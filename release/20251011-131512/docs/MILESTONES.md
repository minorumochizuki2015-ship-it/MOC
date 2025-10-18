# マイルストーン（2025-10-11 時点）

基準日: 2025-10-11

## M1（2025-10-15）SBOM + ライセンス検証
- CycloneDX で SBOM 生成、依存ライセンスの互換性チェック

## M2（2025-10-18）CODEOWNERS 整備
- .github/CODEOWNERS 追加、主要ディレクトリと責任者を紐付け

## M3（2025-10-20）Secrets スキャンを CI に統合
- secrets 検出（正規表現 + 高感度ルール）の自動化

## M4（2025-10-22）Coverage レポート公開
- coverage.xml を成果物化、diff-cover 導入（PRごとの差分品質）

## M5（2025-10-25）Rollback/Canary 整備
- ロールバックスクリプト、Canary テストシナリオとメトリクス基準

## M6（2025-10-28）Provenance/署名
- cosign 署名、SLSA 風 Provenance JSON 生成

## M7（2025-11-01）型チェック強化
- mypy strict 100% パス