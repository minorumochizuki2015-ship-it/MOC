module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'docs', 'style', 'refactor', 'perf', 'test', 'chore', 'ci', 'build', 'revert']],
    'type-case': [2, 'always', 'lower-case'],
    'type-empty': [2, 'never'],
    'subject-case': [0], // 緩和
    'subject-empty': [2, 'never'],
    'subject-full-stop': [0], // 緩和
    'header-max-length': [2, 'always', 100],
    'body-leading-blank': [0] // 緩和
  }
};
