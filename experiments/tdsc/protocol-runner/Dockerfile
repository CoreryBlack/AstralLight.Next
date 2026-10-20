ARG BASE_IMAGE
FROM ${BASE_IMAGE}

RUN apk add --no-cache bash curl jq mariadb-client python3 redis

COPY run-protocol.sh /usr/local/bin/run-protocol
COPY run-performance.py /usr/local/bin/run-performance.py
RUN chmod 0755 /usr/local/bin/run-protocol /usr/local/bin/run-performance.py

ENTRYPOINT ["/usr/local/bin/run-protocol"]
