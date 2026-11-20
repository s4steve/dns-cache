# bookworm to match distroless debian12 glibc
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/dns-cache /usr/local/bin/dns-cache
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/dns-cache", "/etc/dns-cache/config.toml"]
