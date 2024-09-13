# ベースイメージ
FROM rust:latest as builder

# 作業ディレクトリの設定
WORKDIR /usr/src/app

# ソースコードのコピー
COPY . .

# リリースビルド
RUN cargo build --release

# 実行用のスリムなイメージを作成
FROM debian:bookworm-slim

# 必要なライブラリのインストール
RUN apt-get update \
    && apt-get install -y pkg-config libssl-dev ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 作業ディレクトリの設定
WORKDIR /usr/src/app

# ビルドしたバイナリをコピー
COPY --from=builder /usr/src/app/target/release/rust-auth0-service /usr/local/bin/rust-auth0-service

# ポートの公開
EXPOSE 8080

# 環境変数を設定
COPY .env /usr/src/app/.env

# コンテナ起動時に実行するコマンド
CMD ["rust-auth0-service"]
