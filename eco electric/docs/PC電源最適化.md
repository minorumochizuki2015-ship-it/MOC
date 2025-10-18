PC電源最適化（自動節約モード／アクティブ復帰）

目的
- 使用不可（入力なし・低CPU）時に省電力へ自動切替し、活動再開時には性能を戻すことで、総合的な電力消費を削減します。

導入ファイル
- scripts/power/auto_power_profile.ps1（自動切替ロジック本体）
- config/power_profile.json（しきい値・切替先プラン）
- scripts/power/install_task.ps1（ログオン時自動起動のスケジュールタスク登録）

アルゴリズム概要
- 入力アイドル時間: WinAPI（GetLastInputInfo）で最終入力からの経過秒を取得
- CPU使用率: Get-Counter('Processor(_Total)% Processor Time')で平均%を取得
- 電源状態: .NETのPowerStatus（AC接続/バッテリー）で判定
- 切替判断: 以下を満たすと省電力（SCHEME_MIN）へ切替
  - アイドル秒 >= 閾値（AC: idle_minutes_ac、DC: idle_minutes_dc）
  - CPU使用率 <= cpu_threshold_percent
- 活動検知: いずれか不成立でバランス（SCHEME_BALANCED）へ復帰
- ドウェル制御: dwell_sec（最小滞在秒）より前の再切替を禁止してフラッピング防止

設定例（config/power_profile.json）
{
  "schema_version": 1,
  "check_interval_sec": 15,
  "idle_minutes_ac": 5,
  "idle_minutes_dc": 2,
  "cpu_threshold_percent": 15,
  "dwell_sec": 60,
  "on_ac_active_scheme": "SCHEME_BALANCED",
  "on_idle_scheme": "SCHEME_MIN"
}

使い方
1) しきい値の確認・調整
   - config/power_profile.json を好みに合わせて編集（例: バッテリー時は idle_minutes_dc を1分にする、CPUしきい値を10%にする等）。
2) 手動テスト（ドライラン）
   - PowerShell: powershell -ExecutionPolicy Bypass -File .\scripts\power\auto_power_profile.ps1 -DryRun
   - artifacts\power\run.log に判定ログが出ます（DryRunは切替を実施しません）。
3) 本運用開始
   - PowerShell: powershell -ExecutionPolicy Bypass -File .\scripts\power\auto_power_profile.ps1
   - 数分放置で省電力へ切替され、入力やCPU上昇でバランスへ復帰します。
4) 自動起動（ログオン時）
   - PowerShell: powershell -ExecutionPolicy Bypass -File .\scripts\power\install_task.ps1
   - タスクスケジューラに「AutoPowerProfile」が登録されます。

注意・補足
- powercfg の切替は一般権限でも可能ですが、環境により管理者権限が必要になる場合があります。
- しきい値は筐体や用途に合わせて調整してください。高負荷作業（動画編集等）が多い場合は dwell_sec を長めにしてください。
- 例外運用（ホワイトリスト）やGPU使用率連動などが必要であれば、拡張版の要件をご指示ください。

検証ポイント
- タスクマネージャーでCPU/GPU使用率の低下、ファン回転の抑制を確認
- powercfg -getactivescheme の表示が所望のプランに切り替わることを確認
- artifacts\power\run.log に「省電力へ切替」「バランスへ復帰」の記録が残ることを確認

更新履歴
- 2025-10-09: 初版作成（自動切替スクリプトと設定の導入、タスク登録手順の整備）