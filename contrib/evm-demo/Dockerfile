# syntax=docker/dockerfile:1
#
# Container for the narrated end-to-end EVM-on-Stacks demo.
#
# It builds the `stacks-node` test harness (which includes the `evm_demo`
# integration test), builds a pinned `bitcoind` from source, and runs the
# demo: a live regtest Nakamoto network (bitcoind + 5 signers + miner) booted
# to Epoch 3.3, driven through EvmPublish / EvmContractCall / clarity-read.
#
#   podman build -t evm-demo -f contrib/evm-demo/Dockerfile .
#   podman run --rm -it evm-demo              # three-pane tmux demo
#
# tmux needs a TTY, so use -it here. The stdout/stderr split happens inside
# the container (see tmux-demo.sh), so the pseudo-TTY merging the container's
# own streams no longer matters.
#
# Root is used only for system setup (building/installing bitcoind and
# creating an unprivileged user); it is dropped with `USER` *before* the
# source is copied and the project is built, so compilation and the demo
# itself never run as root.
#
# NOTE: the first build compiles Bitcoin Core and the whole Rust workspace
# (stackslib + revm + the node test harness). Expect a long build and
# ~16 GB RAM.

# Pinned to match rust-toolchain.toml (1.96.0), so no extra toolchain is
# downloaded at build time.
FROM rust:1.96-slim-bookworm

# --- root: build & install a pinned bitcoind from source -------------------
WORKDIR /bitcoin
ARG BITCOIN_VERSION=28.1
ARG BITCOIN_SHA512=859c5f0b2f927969766d3ebde64173469e5810694ba317629fac64c66311d847698ae093dbf585e327cf4e75983b722ff45a23ed3fe6f1f13752db4cf6846aa9
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      build-essential libtool autotools-dev automake pkg-config bsdmainutils \
      python3 libsqlite3-dev libevent-dev libboost-dev curl wget ca-certificates \
      tmux jq less procps \
 && rm -rf /var/lib/apt/lists/*
RUN wget -q "https://github.com/bitcoin/bitcoin/archive/refs/tags/v${BITCOIN_VERSION}.tar.gz" \
 && echo "${BITCOIN_SHA512}  v${BITCOIN_VERSION}.tar.gz" | sha512sum -c --strict \
 && tar -xzf "v${BITCOIN_VERSION}.tar.gz" \
 && cd "bitcoin-${BITCOIN_VERSION}" \
 && ./autogen.sh \
 && ./configure --disable-gui \
 && make -j "$(nproc)" \
 && make install \
 && cd / && rm -rf /bitcoin \
 && bitcoind --version | head -n1

# --- root: create an unprivileged user and hand it the build dirs ----------
RUN useradd -ms /bin/bash dev \
 && mkdir -p /src /target \
 && chown -R dev:dev /src /target /usr/local/cargo /usr/local/rustup
ENV CARGO_TARGET_DIR=/target

# --- drop root: build & run as `dev` ---------------------------------------
USER dev
WORKDIR /src

# Copy the source (owned by `dev`) and precompile the demo test so
# `podman run` starts near-instantly.
COPY --chown=dev:dev . .
RUN cargo test -p stacks-node --no-run

ENV BITCOIND_TEST=1
ENV RUST_BACKTRACE=1
# Three-pane tmux demo (walkthrough | node logs / RPC shell). Override with
# `--entrypoint bash` for a plain shell, or run run-demo.sh for the
# single-stream version.
ENTRYPOINT ["bash", "/src/contrib/evm-demo/tmux-demo.sh"]
