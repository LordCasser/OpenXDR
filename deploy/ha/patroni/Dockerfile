FROM postgres:16-alpine

ARG PATRONI_VERSION=4.1.4
RUN apk add --no-cache curl py3-pip \
    && pip3 install --break-system-packages --no-cache-dir \
        "patroni[etcd3]==${PATRONI_VERSION}" psycopg2-binary

COPY entrypoint.sh /usr/local/bin/openxdr-patroni-entrypoint
USER postgres
ENTRYPOINT ["openxdr-patroni-entrypoint"]
