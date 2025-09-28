# Unity セットアップガイド

## 🎯 目標
生成されたUnityプロジェクトを開くためのUnity環境をセットアップします。

## 📋 セットアップ手順

### 1. Unity Hub のダウンロード・インストール

#### ダウンロード
- **公式サイト**: https://unity.com/download
- **直接ダウンロード**: Unity Hub インストーラーをダウンロード
- **対応OS**: Windows 10/11

#### インストール手順
1. ダウンロードしたインストーラーを実行
2. インストールウィザードに従って進む
3. デフォルト設定でOK
4. インストール完了後、Unity Hubを起動

### 2. Unity Editor のインストール

#### Unity Hub での操作
1. Unity Hubを開く
2. 左メニューから「Installs」を選択
3. 「Install Editor」ボタンをクリック
4. **推奨バージョン**: Unity 2022.3 LTS（Long Term Support）
5. 必要なモジュールを選択：
   - **Android Build Support**（モバイル開発用）
   - **Windows Build Support**（デスクトップ用）
   - **Visual Studio Community**（IDE）

#### インストール時間
- 約15-30分（インターネット速度による）
- 必要ディスク容量：約8-12GB

### 3. Unity アカウント作成・ログイン

#### アカウント作成
1. Unity Hubで「Sign in」をクリック
2. 新規アカウント作成または既存アカウントでログイン
3. **Personal License**（無料）を選択

### 4. プロジェクトを開く

#### 生成されたプロジェクトの場所
```
C:\Users\User\Trae\MOC\data\clone_generation\UnityProject\
```

#### 開く手順
1. Unity Hubの「Projects」タブを選択
2. 「Open」ボタンをクリック
3. 上記のプロジェクトフォルダを選択
4. 「Open」で確定

## 🎮 プロジェクト内容

### 生成されたファイル
- **MainScene.unity**: メインゲームシーン
- **Player.prefab**: プレイヤーオブジェクト
- **GameManager.cs**: ゲーム管理システム
- **PlayerController.cs**: プレイヤー制御
- **UIManager.cs**: UI管理

### 操作方法
- **移動**: WASDキー
- **ジャンプ**: スペースキー
- **ゲーム開始**: Playボタン（Unity Editor内）

## 🔧 トラブルシューティング

### よくある問題
1. **Unity Hubが起動しない**
   - 管理者権限で実行
   - Windows Defenderの除外設定

2. **プロジェクトが開けない**
   - Unity Editorのバージョン確認
   - プロジェクトパスに日本語が含まれていないか確認

3. **ライセンスエラー**
   - Personal Licenseの再取得
   - オフライン環境の場合はオンライン認証

## 📞 サポート

### 公式リソース
- **Unity Learn**: https://learn.unity.com/
- **Unity Documentation**: https://docs.unity3d.com/
- **Unity Community**: https://unity.com/community

### 推定所要時間
- **ダウンロード**: 10-20分
- **インストール**: 20-40分
- **セットアップ**: 5-10分
- **合計**: 約1-1.5時間

---
*生成日時: 2025年09月29日*
*プロジェクト: MOC Unity Clone*