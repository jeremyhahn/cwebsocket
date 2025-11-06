FROM python:3.11-bookworm

# Build environment for cwebsocket and Autobahn wstest inside the container only
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config \
        libssl-dev libev-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Generate build system and compile
ENV CFLAGS="-fcommon"
RUN ./autogen.sh && ./configure && make -j"$(nproc)"

# Default command does nothing; targets will override with `make` commands
CMD ["bash"]
