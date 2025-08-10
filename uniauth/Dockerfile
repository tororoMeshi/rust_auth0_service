# ベースイメージ
FROM rust:latest AS builder

# 作業ディレクトリの設定
WORKDIR /app

# ソースコードのコピー
COPY . .

# リリースビルド
RUN cargo build --release

# 実行用のスリムなイメージを作成
FROM gcr.io/distroless/cc-debian12:nonroot

# 作業ディレクトリの設定
WORKDIR /app

# ビルドしたバイナリをコピー
COPY --from=builder /app/target/release/uniauth /app/uniauth

# ポートの公開
EXPOSE 8080

# コンテナ起動時に実行するコマンド
CMD ["/app/uniauth"]