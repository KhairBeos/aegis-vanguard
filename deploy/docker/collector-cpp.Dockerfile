FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
        cmake \
        ninja-build \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN rm -rf /src/build \
    && cmake --preset debug-collector \
    && cmake --build --preset build-debug-collector --target aegis_collector_agent

CMD ["/src/build/debug-collector/collector/src/aegis_collector_agent", "/app/config/prod/collector.yaml"]
