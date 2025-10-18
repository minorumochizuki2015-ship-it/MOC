# CI最適化計画書 (2025-10-11)

## 目標
- GitHub Actions CIの実行時間短縮とキャッシュ効率向上
- mypy HTMLレポート生成の追加
- Windows環境での.venv作成と依存関係管理の最適化
- アーティファクト管理の改善

## 現状分析

### 既存の最適化
- ✅ Ubuntu: pip cache (`~/.cache/pip`)
- ✅ Windows: pip cache (`~\AppData\Local\pip\Cache`)
- ✅ アーティファクト分離（coverage, SBOM, diff-cover, security）

### 改善対象

#### 1. キャッシュ最適化
**問題:**
- mypy cache未活用
- pre-commit cache未活用
- Python環境の重複インストール

**解決策:**
- mypy cache追加 (`~/.mypy_cache`, `~\AppData\Local\mypy_cache`)
- pre-commit cache追加
- venv cache検討

#### 2. mypy HTMLレポート
**問題:**
- 現在はコンソール出力のみ
- エラー詳細の可視化不足

**解決策:**
- `--html-report` オプション追加
- HTMLレポートのアーティファクト化

#### 3. Windows .venv作成
**問題:**
- 直接pip installで依存関係管理
- 仮想環境の一貫性不足

**解決策:**
- Windows jobでも.venv作成
- 仮想環境内での実行統一

## 実装計画

### Phase 1: キャッシュ拡張（優先度：高）

#### Ubuntu job
```yaml
- name: Cache mypy
  uses: actions/cache@v3
  with:
    path: ~/.mypy_cache
    key: ${{ runner.os }}-mypy-${{ hashFiles('**/*.py') }}
    restore-keys: |
      ${{ runner.os }}-mypy-

- name: Cache pre-commit
  uses: actions/cache@v3
  with:
    path: ~/.cache/pre-commit
    key: ${{ runner.os }}-pre-commit-${{ hashFiles('.pre-commit-config.yaml') }}
    restore-keys: |
      ${{ runner.os }}-pre-commit-
```

#### Windows job
```yaml
- name: Cache mypy (Windows)
  uses: actions/cache@v3
  with:
    path: ~\AppData\Local\mypy_cache
    key: ${{ runner.os }}-mypy-${{ hashFiles('**/*.py') }}
    restore-keys: |
      ${{ runner.os }}-mypy-
```

### Phase 2: mypy HTMLレポート（優先度：高）

#### Ubuntu job
```yaml
- name: Type check with HTML report
  run: |
    mkdir -p mypy-reports
    python -m mypy --strict --show-error-codes --html-report mypy-reports app src

- name: Upload mypy HTML report
  uses: actions/upload-artifact@v4
  with:
    name: mypy-html-report
    path: mypy-reports/
    if-no-files-found: warn
```

#### Windows job
```yaml
- name: Type check with HTML report (Windows)
  run: |
    New-Item -ItemType Directory -Force -Path mypy-reports
    .\.venv\Scripts\python -m mypy --strict --show-error-codes --html-report mypy-reports app src

- name: Upload mypy HTML report (Windows)
  uses: actions/upload-artifact@v4
  with:
    name: mypy-html-report-${{ matrix.python-version }}
    path: mypy-reports/
    if-no-files-found: warn
```

### Phase 3: Windows .venv統一（優先度：中）

#### 現在の問題
```yaml
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    if (Test-Path "requirements.txt") { pip install -r requirements.txt }
    if (Test-Path "requirements-dev.txt") { pip install -r requirements-dev.txt }
```

#### 改善後
```yaml
- name: Create virtual environment
  run: |
    python -m venv .venv
    .\.venv\Scripts\python -m pip install --upgrade pip

- name: Cache virtual environment
  uses: actions/cache@v3
  with:
    path: .venv
    key: ${{ runner.os }}-venv-${{ matrix.python-version }}-${{ hashFiles('**/requirements*.txt') }}
    restore-keys: |
      ${{ runner.os }}-venv-${{ matrix.python-version }}-

- name: Install dependencies
  run: |
    if (Test-Path "requirements.txt") { .\.venv\Scripts\pip install -r requirements.txt }
    if (Test-Path "requirements-dev.txt") { .\.venv\Scripts\pip install -r requirements-dev.txt }
```

### Phase 4: 並列化とジョブ依存関係最適化（優先度：低）

#### 現在の問題
- security jobがbuild-and-testに依存していない
- 一部のステップが逐次実行

#### 改善案
- lintとtype checkの並列化
- test matrixの効率化

## 期待効果

### 実行時間短縮
- **mypy cache**: 2-3分短縮（初回以降）
- **pre-commit cache**: 1-2分短縮
- **venv cache**: 1-2分短縮（Windows）

### 可視性向上
- **mypy HTMLレポート**: エラー詳細の可視化
- **アーティファクト整理**: レポート類の一元管理

### 一貫性向上
- **Windows .venv**: Ubuntu環境との統一
- **依存関係管理**: 仮想環境での一貫実行

## 実装手順

### Week 1: Phase 1-2実装
1. キャッシュ拡張（mypy, pre-commit）
2. mypy HTMLレポート追加

### Week 2: Phase 3実装
1. Windows .venv作成
2. venv cache追加

### Week 3: 検証・調整
1. 実行時間測定
2. キャッシュヒット率確認
3. アーティファクト品質確認

## 関連パス
- C:/Users/User/Trae/ORCH-Next/.github/workflows/ci.yml
- C:/Users/User/Trae/ORCH-Next/requirements.txt
- C:/Users/User/Trae/ORCH-Next/requirements-dev.txt
- C:/Users/User/Trae/ORCH-Next/.pre-commit-config.yaml

## マイルストーン連携
- v1.3準備項目: **CI最適化**, SBOM/license自動化, CODEOWNERS/secrets scanning