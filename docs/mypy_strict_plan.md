# mypy 厳格化ロードマップ

本ドキュメントは、型チェック（mypy）の厳格化を段階導入する計画を示します。CI を段階的に blocker 化することで、開発速度と品質のバランスをとります。

## 目標
- 段階的に `strict=True` を適用し、推論できない箇所を削減
- 優先モジュールから着手し、CI での失敗を段階的に許容→禁止へ移行

## 現状
- 監査結果より mypy エラーが多い（Best Effort 実行）
- まずはホットスポット（セキュリティ／ロック管理／オーケストレータ）から整備

## フェーズ計画

### Phase 1（準備・設定）
- ガイドライン整備（このドキュメント）
- 非ブロッキング CI（現行）を維持しつつ、優先モジュールへ `strict=True` の試験適用

対象（優先度高）:
- `src/security.py`
- `src/lock_manager.py`
- `src/orchestrator.py`

施策:
- 関数シグネチャの型注釈追加
- Any の削減、Optional の明示化
- TypedDict / Protocol の活用

### Phase 2（拡張）
- `src/workflow_engine.py`、`src/monitoring_system.py` 等へ拡張
- テスト補助型の整備（fixtures, stubs）

### Phase 3（CI blocker 化）
- `mypy.ini` の `warn_unused_ignores`, `no_implicit_optional` 等を有効化
- 重要モジュールは CI blocker（失敗時 fail）へ移行

## 推奨設定例（段階的）

`mypy.ini` にモジュール単位で適用する例:
```ini
[mypy]
pretty = True
show_error_codes = True
warn_unused_ignores = True

[mypy-src.security]
strict = True

[mypy-src.lock_manager]
strict = True

[mypy-src.orchestrator]
strict = True
```

## 運用ルール
- PR 単位で対象モジュールの mypy エラーを解消
- CI では `continue-on-error: true` を維持しつつ、フェーズ3にて対象モジュールの失敗を blocker 化

## 更新履歴
- 2025-10-10: 初版作成（段階計画・設定例の提示）
# mypy --strict Zero-Warning Plan (2025-10-11 更新)

## 現状分析（2025-10-11）
- **総エラー数**: 358件（予想14件から大幅増加）
- **主要エラータイプ**:
  - `no-untyped-def`: 136件（関数の型注釈不足）
  - `no-untyped-call`: 64件（型注釈なし関数の呼び出し）
  - `type-arg`: 42件（ジェネリック型の型引数不足）
  - `assignment`: 28件（型不適合な代入）
  - `union-attr`: 14件（Union型の属性アクセス）

## 優先対象ファイル（エラー数順）
1. `src/lock_manager.py` - セキュリティ重要
2. `src/realtime_dashboard.py` - パフォーマンス重要
3. `src/security.py` - セキュリティ重要
4. `src/monitoring_system.py` - 運用重要
5. `src/monitor.py` - 運用重要
6. `src/orchestrator.py` - コア機能
7. `src/dispatcher.py` - コア機能
8. `src/dashboard.py` - UI重要

## 段階的修正戦略

### Phase 1: セキュリティ・コア（優先度：高）
対象: `src/security.py`, `src/lock_manager.py`, `src/orchestrator.py`
- 関数シグネチャの型注釈追加（`no-untyped-def`対応）
- 外部ライブラリ呼び出しの型注釈（`no-untyped-call`対応）
- ジェネリック型の型引数明示（`type-arg`対応）

### Phase 2: 監視・ダッシュボード（優先度：中）
対象: `src/monitoring_system.py`, `src/realtime_dashboard.py`, `src/dashboard.py`
- Union型の適切な処理（`union-attr`対応）
- 変数の型注釈追加（`var-annotated`対応）

### Phase 3: ワークフロー・API（優先度：中）
対象: `src/workflows_api.py`, `src/workflow_dsl.py`, `src/dispatcher.py`
- 型不適合代入の修正（`assignment`対応）
- 属性定義の明確化（`attr-defined`対応）

### Phase 4: 共有モジュール（優先度：低）
対象: `app/shared/logging_config.py`, `app/shared/error_handling.py`
- 外部ライブラリのstub追加（`import-untyped`対応）

## 修正ガイドライン
- **no-untyped-def**: 関数に`-> ReturnType`を追加
- **no-untyped-call**: 呼び出し先に型注釈追加またはstub作成
- **type-arg**: `List[str]`, `Dict[str, Any]`等の型引数明示
- **assignment**: 型キャストまたは型ガード使用
- **union-attr**: `isinstance()`チェックまたは`assert`追加

## 実装計画
1. **Week 1**: Phase 1完了（セキュリティ・コア）
2. **Week 2**: Phase 2完了（監視・ダッシュボード）
3. **Week 3**: Phase 3-4完了（残り全て）
4. **Week 4**: CI統合・検証

## Milestone linkage
- v1.2 success criteria: `mypy --strict 0 errors`, `pytest 100%`, `diff-cover ≥ 80%`, Logging unification

## 関連パス
- C:/Users/User/Trae/ORCH-Next/.github/workflows/ci.yml
- C:/Users/User/Trae/ORCH-Next/mypy.ini
- C:/Users/User/Trae/ORCH-Next/docs/mypy_strict_plan.md
- C:/Users/User/Trae/ORCH-Next/src/
- C:/Users/User/Trae/ORCH-Next/app/