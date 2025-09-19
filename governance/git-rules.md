# Git ガバナンスルール

## ブランチ戦略

### ブランチ構成
- **main**: 本番環境（保護設定必須）
- **dev**: 開発統合ブランチ
- **feature/***: 機能開発ブランチ
- **hotfix/***: 緊急修正ブランチ
- **release/***: リリース準備ブランチ

## 保護設定（リポ設定で必須化）

### main ブランチ保護
- 直push禁止・force push禁止・リニアヒストリ
- **署名コミット/タグ必須**（GPG/SSH/Keylessいずれか）
- 必須ステータスチェック（下記CIを全通過）

## コミット規約

### Conventional Commits
```
feat: 新機能追加
fix: バグ修正
docs: ドキュメント更新
style: コードスタイル修正
refactor: リファクタリング
test: テスト追加・修正
chore: その他の変更
```

### 署名要件
- すべてのコミットに **Signed-off-by** を付与
- GPG/SSH/Keyless署名を必須化

## PR要件

### 必須項目
- `templates/pull_request_template.md` を使用
- **`diff-plan.json` 添付**（Planの出力）
- 変更は**最小差分（unified diff）**
- 設計/影響/ロールバック明記
- **`apply_signed_diff` 経由で生成された差分のみ**を許可

## タグ/リリース

### バージョニング
- `vX.Y.Z` で **annotated tag**
- CHANGELOG 更新必須
- `release/*`→`main`→`dev` の順でマージ

## 大容量ファイル

### Git LFS設定
```
*.gguf filter=lfs diff=lfs merge=lfs -text
*.onnx filter=lfs diff=lfs merge=lfs -text
*.bin filter=lfs diff=lfs merge=lfs -text
*.model filter=lfs diff=lfs merge=lfs -text
```

## 緊急時対応

### ロールバック手順
- `revert` + `restore.(ps1|sh)`
- PRで手順ログを添付

## ガバナンス連携

### 設定ファイル検証
- `glide.guard.yaml / allowlist.yaml / budget.yaml`
- **JSON Schema検証をCI必須**
- 不一致はmerge不可
