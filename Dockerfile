FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/target/release/s3rs /usr/local/bin/s3rs
ENV S3RS_DATA_DIR=/data S3RS_LISTEN=0.0.0.0:9000
VOLUME /data
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/s3rs"]
