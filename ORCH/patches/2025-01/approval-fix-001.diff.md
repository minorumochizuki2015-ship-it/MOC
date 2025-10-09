# 承認機能修正パッチ

## 概要
JavaScriptとPythonのAPIエンドポイント不一致により発生していた承認ボタンエラーを修正。

## 問題
- JavaScript: `/api/approval/{id}/update` を呼び出し
- Python: `/api/approvals/approve` のみ実装
- エンドポイント不一致により404エラーが発生

## 修正内容
orch_dashboard.pyに新しいAPIエンドポイントを追加

## テスト結果
- ダッシュボードサーバー正常起動: ✓
- 新しいAPIエンドポイント登録: ✓
- ブラウザでのダッシュボード表示: ✓

## 検証項目
- [x] PTP=pass
- [x] Forbidden=none
- [x] EOL=UTF-8 LF
- [x] Diff=minimal
- [x] Protected=untouched
