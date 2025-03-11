FROM ubuntu:20.04 as build
    
RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       wget \
       pkg-config \
       unzip \
       git     \
       make    \
       cmake   \
       gcc     \
       cargo   \
       libssl-dev \
       software-properties-common \
       libcurl4-openssl-dev \
       build-essential \
       libjansson-dev \
       libcbor-dev 
    ARG VERSION=latest
RUN echo $VERSION > /VERSION

COPY ./ /root

#  RA-TLS DCAP libraries:
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null \
    && wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -\
    && apt-get update \
    && apt-get install -y \
       libsgx-dcap-quote-verify-dev \
       libsgx-dcap-ql-dev \
       libsgx-uae-service \
       libtdx-attest-dev \
       libsgx-dcap-default-qpl-dev 

RUN git clone https://github.com/inclavare-containers/rats-tls.git /rats-tls\
    && cd /rats-tls \
    && git checkout cf5e911a480f7120da480f046417a209e222e101 \
    && sed -i s@sgx_quote_3.h@sgx_quote_4.h@g src/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c \
    && sed -i s@if\ 0@if\ 1@g src/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c \
    && cmake -DRATS_TLS_BUILD_MODE="tdx" -DBUILD_SAMPLES=on -H. -Bbuild \
    && make -C build install \
    && cp -a /rats-tls/src/include/rats-tls/claim.h /usr/local/include/rats-tls/

RUN cd /root \
    && make all


FROM ubuntu:20.04

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       libssl-dev \
       libcurl4-openssl-dev \
       software-properties-common \
       wget \
       libcbor-dev 

#  RA-TLS DCAP libraries
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null \
    && wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -\
    && apt-get update \
    && apt-get install -y \
       libsgx-dcap-quote-verify \
       libsgx-dcap-ql \
       libsgx-uae-service \
       libtdx-attest \
       libsgx-dcap-default-qpl

RUN mkdir -p /workplace/app \
    && mkdir -p /usr/local/lib/rats-tls

ARG VERSION=latest
RUN echo $VERSION > /VERSION
COPY docker/sgx_default_qcnl.conf /etc
COPY --from=build  /root/secret_broker_server /workplace/app
COPY --from=build  /usr/local/lib/rats-tls  /usr/local/lib/rats-tls
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/rats-tls

WORKDIR /workplace/app
ENTRYPOINT ["/workplace/app/secret_broker_server"]
CMD []

