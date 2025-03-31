# ######################################
# 1st image
# ######################################
FROM ubuntu:20.04 AS backend

#
RUN apt-get update \
   && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      wget \
      pkg-config \
      build-essential \
      curl \
      git \
      libssl-dev \
      clang

#
ARG VERSION=latest
ARG DEBUG=false
# COPY backend /build/src
COPY conker/src /build/src
# COPY Cargo.toml /build/
COPY conker/Cargo.toml /build/Cargo.toml

#
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
&& apt-get clean && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.cargo/bin:$PATH"

RUN cd /build && \
   cargo build --release

# # ######################################
# # 2nd image
# # ######################################
FROM reckey/conker-cvm-base:latest
ARG VERSION=latest
RUN echo $VERSION > /SERVER_VERSION

# add script for install docker
COPY install_docker.sh /

# install backend
RUN mkdir -p /workplace/app/conker/backend \
    && mkdir -p /workplace/app/conker/backend/certs \
    && mkdir -p /workplace/app/conker/backend/ca \
    && mkdir -p /workplace/app/conker/backend/logs \
    && mkdir -p /workplace/app/conker/backend/conf

COPY --from=backend /build/target/release/conker /workplace/app/conker/backend/conker.bin

# for tdx attest
RUN echo "port=4050" > /etc/tdx-attest.conf 

COPY app.yml /workplace/apploader/conf


