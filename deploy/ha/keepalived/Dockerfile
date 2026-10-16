FROM alpine:3.22

RUN apk add --no-cache keepalived wget
ENTRYPOINT ["keepalived", "--dont-fork", "--log-console", "--use-file", "/etc/keepalived/keepalived.conf"]
