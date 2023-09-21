FROM ubuntu

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip python3-apt git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/po1/apts3 /root/apts3 \
    && pip install /root/apts3 \
    && rm -rf /root/apts3

ENTRYPOINT apts3
