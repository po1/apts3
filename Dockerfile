FROM ubuntu

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip python3-apt git \
    && rm -rf /var/lib/apt/lists/*

COPY . /tmp/apts3
RUN pip install /tmp/apts3

ENTRYPOINT ["/usr/local/bin/apts3"]
