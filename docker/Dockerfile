FROM debian:12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ca-certificates \
    libssl-dev \
    libcurl4-openssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cmake -DCMAKE_BUILD_TYPE=Release . && \
    make -j$(nproc) && \
    strip --strip-unneeded bin/semantics-av

FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libcurl4 \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 1000 -s /sbin/nologin semantics-av && \
    mkdir -p /var/lib/semantics-av/models /run/semantics-av && \
    chown -R semantics-av:semantics-av /var/lib/semantics-av /run/semantics-av

COPY --from=builder /build/bin/semantics-av /usr/local/bin/
COPY --from=builder /build/_deps/semantics_av_core-src/lib/*.so* /usr/local/lib/

RUN ldconfig

VOLUME ["/var/lib/semantics-av"]

ENV SEMANTICS_AV_HTTP_HOST=0.0.0.0 \
    SEMANTICS_AV_HTTP_PORT=9216 \
    SEMANTICS_AV_CONTAINER=true

USER semantics-av

EXPOSE 9216

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:9216/api/v1/health || exit 1

ENTRYPOINT ["semantics-av"]
CMD ["daemon", "run"]