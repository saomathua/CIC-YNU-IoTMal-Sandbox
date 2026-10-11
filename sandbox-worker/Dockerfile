FROM ubuntu:22.04

# nftables and its libraries are pinned to the versions the CT-01 expected
# ruleset (isolation/expected-ruleset.json) was generated and reviewed with.
# A new version must be re-tested and the expected file re-reviewed; if the
# pinned versions disappear from the archive the build fails instead of drifting.
ARG NFTABLES_VERSION=1.0.2-1ubuntu3.1
ARG LIBNFTNL_VERSION=1.2.1-1build1
ARG LIBJANSSON_VERSION=2.13.1-1.1build3

RUN apt-get update && \
    apt-get --no-install-recommends -y install \
        qemu-system-arm qemu-system-mips qemu-system-x86 \
        python3-dev python3-pip \
        net-tools iproute2 uml-utilities iptables \
        nftables=${NFTABLES_VERSION} libnftables1=${NFTABLES_VERSION} \
        libnftnl11=${LIBNFTNL_VERSION} libjansson4=${LIBJANSSON_VERSION} \
        procps sysstat \
        file \
        ca-certificates && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./config ./config
COPY ./router ./router
COPY ./service ./service
COPY ./util ./util
COPY ./isolation ./isolation
COPY ./ARM ./ARM
COPY ./MIPS ./MIPS
COPY ./MIPSEL ./MIPSEL
COPY ./x86 ./x86

COPY server.py ./poller.py ./run.sh ./

RUN mkdir data

ENTRYPOINT ["/bin/bash", "run.sh"]
