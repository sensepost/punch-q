FROM ubuntu:20.04 as build

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-dev \
    git \
    curl \
    tar \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

ENV RDURL="https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/messaging/mqdev/redist" \
    RDTAR="IBM-MQC-Redist-LinuxX64.tar.gz" \
    VRMF=9.2.2.0

RUN mkdir -p /opt/mqm && cd /opt/mqm \
 && curl -LO "$RDURL/$VRMF-$RDTAR" \
 && tar -zxf ./*.tar.gz \
 && rm -f ./*.tar.gz

RUN mkdir /src \
    && cd /src \
    && git clone https://github.com/sensepost/punch-q.git

WORKDIR /src/punch-q
RUN mkdir wheels \
    && pip3 wheel -w wheels/ -r requirements.txt

# --
FROM ubuntu:20.04

ENV LD_LIBRARY_PATH=/opt/mqm/lib64

COPY --from=build /opt/mqm /opt/mqm
COPY --from=build /src/punch-q /src/punch-q

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

# Cleanup some files we dont need here
RUN cd /opt/mqm \
  && rm -Rf gskit8/lib java samp bin inc

WORKDIR /src/punch-q
RUN pip3 install . -f wheels/ \
  && rm -Rf /src

VOLUME [ "/data" ]

ENTRYPOINT [ "/usr/local/bin/punch-q" ]

