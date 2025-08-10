FROM rust:1.87 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/release/portal_backend /app/
CMD ["/app/portal_backend"]
