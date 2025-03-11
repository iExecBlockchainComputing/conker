FROM ubuntu:20.04 as build

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       wget
ARG VERSION=latest
RUN echo $VERSION > /VERSION

COPY tmp /gotest

RUN wget --progress=bar:force -c https://dl.google.com/go/go1.19.7.linux-amd64.tar.gz -O - | tar -xz -C /usr/local

RUN cd /gotest \
    && PATH=$PATH:/usr/local/go/bin \
       go build -o gotest


FROM ubuntu:20.04

RUN mkdir -p  /usr/share/zoneinfo/
COPY zoneinfo /usr/share/zoneinfo
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

RUN mkdir -p  /usr/share/zoneinfo/ \
    && mkdir -p /workplace/app/certs \
    && mkdir -p /workplace/app/ca \
    && mkdir -p /workplace/app/logs \
    && mkdir -p /workplace/app/conf \
    && mkdir -p /workplace/app/views

ARG VERSION=latest
RUN echo $VERSION > /VERSION

COPY --from=build /gotest/gotest /workplace/app/gotest
COPY conf/ /workplace/app/conf

WORKDIR /workplace/app
ENTRYPOINT ["./gotest"]

