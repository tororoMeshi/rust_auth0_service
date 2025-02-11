# Stage 1: Build the Nuxt.js application
FROM node:23-bookworm AS builder

WORKDIR /app

# package.json と package-lock.json をコピーし依存関係をインストール
COPY package*.json ./
RUN npm install
# cookie パッケージが package.json に含まれていない場合は、ここでインストール
RUN npm install cookie

# ソースコードを全てコピーしてビルド
COPY . .
RUN npm run build

# Stage 2: 実行用イメージの作成
FROM node:23-bookworm-slim

WORKDIR /app

# ビルド済みのアプリケーションをコピー
COPY --from=builder /app ./

# Nuxt.js のサーバーは通常 3000 番ポートで起動するので EXPOSE
EXPOSE 3000

# 環境変数 HOST を 0.0.0.0 に設定（コンテナ内で外部からアクセスできるように）
ENV HOST=0.0.0.0

# アプリケーションを起動
CMD ["npm", "start"]
