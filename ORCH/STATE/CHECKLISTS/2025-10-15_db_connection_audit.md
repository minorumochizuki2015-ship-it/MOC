# DB接続監査精査・是正結果（2025-10-15）

## 1) 監査結果の精査・確認

- security.py: `:memory:` は永続接続、ファイルDBは都度接続。主要メソッドは `closing(self._connect())` + `with conn:` の二段構えでトランザクション境界が明示。ET/UTCの保存・比較は一貫。現状の実装を正とする。
- lock_manager.py: `extend_lock` でカーソル操作が `with conn:` の外に出ていたため、更新系がトランザクション外となる危険を確認（監査指摘通り）。
- dispatcher.py / monitor.py: 接続ヘルパーで WAL/NORMAL/busy_timeout を設定済。各操作は `closing + with conn` パターンで整合。
- database_optimizer.py: 接続は `closing + with conn` だが PRAGMA 設定が未実施。監査提案通り、各接続に PRAGMA を挿入する改善余地あり。
- 重複クラス: `src/security.py` と `src/security_manager.py` に SecurityManager が併存。前者はDB版、後者はインメモリ版でAPIも異なる。インポートの実態（tests/unit/test_security.py は DB版、tests/test_security_integration.py はインメモリ版）も確認済み。

## 2) 是正内容（差分適用済み）

### P0（即時）
1. lock_manager.extend_lock のトランザクション外カーソル利用を修正。
   - パッチ: `ORCH-Next/src/lock_manager.py` にて、`new_expires_at` の算出と `UPDATE` 実行を `with conn:` ブロック内へ移動。

2. 接続スキームの統一（src配下）。
   - grep結果: `ORCH-Next/src` では `with sqlite3.connect(` の直接利用は残存なし（tests/scripts/docsのみ）。現状維持でOK。

### P1（短期）
3. database_optimizer.py に PRAGMA 追加。
   - 追加: `PRAGMA journal_mode=WAL;`, `PRAGMA synchronous=NORMAL;`, `PRAGMA busy_timeout=5000;`, `PRAGMA foreign_keys=ON;`（例外時は無視）。

4. SecurityManager 重複の整理方針を明示。
   - 決定: DB版を正（`src/security.py`）。インメモリ版（`src/security_manager.py`）はレガシーと位置付け、DeprecationWarning を発行し、`InMemorySecurityManager` エイリアスを追加。
   - 将来計画: インポート箇所の段階的移行（`src.security.SecurityManager` 又は `src.security_manager.InMemorySecurityManager` 明示化）。

## 3) 残タスク（再評価後の設定）

- [P1/Pending] 重複解消の最終化: どちらを正とするかの最終承認後、委譲クラスへ一本化（API互換確認）。
- [P2/Pending] ResourceWarning ゲート: `pytest -W error::ResourceWarning` をCIに導入（tests側で `with sqlite3.connect` を `closing + with conn` に統一検討）。
- [P2/Pending] スモークテスト: DB版/インメモリ版の両モードで認証・レート制限の基本動作確認。
- [P2/Pending] 競合下のE2E: busy_timeout/WALの有効性検証（dispatcher/lock_managerで並列アクセス）。

## 4) 実行証跡

- 修正コミット（パッチ適用）
  - ORCH-Next/src/lock_manager.py: extend_lock のトランザクション境界修正。
  - ORCH-Next/src/database_optimizer.py: 接続直後に PRAGMA を設定。
  - ORCH-Next/src/security_manager.py: レガシー明示（DeprecationWarning）と `InMemorySecurityManager` 追加。

- 検索証跡
  - `with sqlite3.connect(` の残存確認: `ORCH-Next/src` では検出なし。tests/scripts/docs にのみ存在。

### 付記（/preview 拡張のDB影響評価）
- 影響なし（/preview の変更は静的ファイルとHTML書き換えに限定され、DB 接続・トランザクション境界に変更はない）

## 5) 受入基準（暫定）

- P0: lock_manager.extend_lock の修正が適用され、更新系が確実に `with conn:` 内で実行されること。
- P1: database_optimizer.py の PRAGMA 追加済み。実行時に例外なく接続可能であること。
- P2: CIで ResourceWarning を検出しない（将来導入）。基本スモークテストが緑。

## 6) 実行コマンド（参考）

```powershell
# 残存パターン検出（src配下）
git grep -n "with sqlite3.connect(" -- src

# テスト（警告を失敗化）
python -m pytest -q -W error::ResourceWarning

# 併走検証（例・ロック取得競合の簡易負荷）
python - <<'PY'
import concurrent.futures, time
from src.lock_manager import LockManager, LockPriority, LockRequest
lm = LockManager(db_path="data/locks.db", enable_cleanup_thread=False)
def worker(i):
    req = LockRequest(resource="R", owner=f"w{i}", priority=LockPriority.MEDIUM, ttl_seconds=5)
    return lm.acquire_lock(req, timeout=2) is not None
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    print(sum(ex.map(worker, range(20))))
PY
```

---
更新者: Audit/SQLite Remediation
更新日時: 2025-10-15T00:00:00Z