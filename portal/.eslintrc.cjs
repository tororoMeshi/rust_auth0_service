// .eslintrc.cjs
module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: [
    'eslint:recommended',
    'plugin:vue/vue3-recommended',
    'plugin:nuxt/recommended', // Nuxt プロジェクトの場合
    'prettier', // Prettier との競合を防ぐ
  ],
  parser: 'vue-eslint-parser',
  parserOptions: {
    parser: '@babel/eslint-parser',
    requireConfigFile: false,
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    /**
     * Vue コンポーネント名は基本的に2語以上必須
     * 例: LoginError.vue → name: 'LoginError' を追加することでエラー回避
     * 単語数が少ないときも name プロパティ必須
     */
    'vue/multi-word-component-names': 'error',

    /**
     * 未使用変数を禁止
     * ただし、変数名が '_' または '_xxx' の場合は警告しない（引数や一時変数に使える）
     * 例: function myFunc(_unused, value) { ... }
     */
    'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
  },
};
