// commitlint.config.js - Conventional Commits設定
module.exports = {
    extends: ['@commitlint/config-conventional'],
    rules: {
        // ヘッダーの最大長（72文字）
        'header-max-length': [2, 'always', 72],
        // タイプの大文字小文字
        'type-case': [2, 'always', 'lower-case'],
        // タイプの列挙値
        'type-enum': [
            2,
            'always',
            [
                'feat',     // 新機能
                'fix',      // バグ修正
                'docs',     // ドキュメント
                'style',    // コードスタイル
                'refactor', // リファクタリング
                'test',     // テスト
                'chore',    // その他
                'ci',       // CI/CD
                'perf',     // パフォーマンス
                'build',    // ビルド
                'revert'    // リバート
            ]
        ],
        // スコープの大文字小文字
        'scope-case': [2, 'always', 'lower-case'],
        // 件名の大文字小文字（緩和）
        'subject-case': [1, 'always', 'lower-case'],
        // 件名の末尾ピリオド禁止
        'subject-full-stop': [2, 'never', '.'],
        // 件名の空行禁止
        'subject-empty': [2, 'never'],
        // 件名の最大長（緩和）
        'subject-max-length': [1, 'always', 72],
        // 本文の行の最大長
        'body-max-line-length': [2, 'always', 100],
        // フッターの最大長
        'footer-max-line-length': [2, 'always', 100]
    }
};
