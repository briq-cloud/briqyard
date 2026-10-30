# The briq credential gateway: one static binary (Rust, rustls with ring, no OpenSSL), the CA on a
# volume at /data. The public roots are compiled in (webpki-roots), so the image needs nothing else.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc make
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin credential-gateway --example stress --example upstream \
 && cp target/release/credential-gateway /credential-gateway \
 && cp target/release/examples/stress /bench-client \
 && cp target/release/examples/upstream /bench-server

FROM busybox:1.37-musl AS probe
FROM gcr.io/distroless/static-debian12
COPY --from=build /credential-gateway /credential-gateway
COPY --from=build /bench-client /bench-client
COPY --from=build /bench-server /bench-server
COPY --from=probe /bin/busybox /busybox
ENV GATEWAY_PORT=3128 GATEWAY_STATE_DIR=/data
EXPOSE 3128
HEALTHCHECK --interval=10s --timeout=5s CMD ["/credential-gateway", "health"]
ENTRYPOINT ["/credential-gateway"]
