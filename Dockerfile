FROM python:3.11-bookworm

# Build environment for cwebsocket and Autobahn wstest inside the container only
# Includes all QA and analysis tools: valgrind, cppcheck, flawfinder, clang, lcov
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config \
        libssl-dev libev-dev zlib1g-dev \
        valgrind \
        cppcheck \
        flawfinder \
        clang \
        clang-tools \
        lcov \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Generate build system and compile
ENV CFLAGS="-fcommon"
RUN ./autogen.sh && ./configure && make -j"$(nproc)"

# Default command does nothing; targets will override with `make` commands
CMD ["bash"]
