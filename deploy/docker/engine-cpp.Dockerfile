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
    && cmake --preset debug-engine \
    && cmake --build --preset build-debug-engine --target aegis_engine

CMD ["/src/build/debug-engine/engine/src/aegis_engine"]
