// .eslintrc.cjs
module.exports = {
  root: true,
  env: { browser: true, es2021: true, node: true },
  extends: [
    'eslint:recommended',
    'plugin:vue/vue3-recommended',
    'prettier', // ← prettierと競合するルールを無効化（任意）
  ],
  parser: 'vue-eslint-parser',
  parserOptions: {
    parser: '@babel/eslint-parser',
    requireConfigFile: false,
    ecmaVersion: 2021,
    sourceType: 'module',
  },
  plugins: ['vue'],
  rules: {
    // お好みで
    // 'vue/multi-word-component-names': 'off',
  },
  ignorePatterns: ['dist/'], // 念のため
};
