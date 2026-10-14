# Build and runtime images share a Debian release so the binary's glibc matches.
FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
COPY --from=build /src/target/release/s3rs /usr/local/bin/s3rs
ENV S3RS_DATA_DIR=/data S3RS_LISTEN=0.0.0.0:9000
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/s3rs"]
