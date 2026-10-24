# Stagenet-only mirror image: Tor (v3 onion, port 80) + nginx (plain HTTP/1.1 on 127.0.0.1:8080).
# Plain HTTP over the onion is the design's first-install path (D1: browsers do not speak HTTP/2
# without TLS); the onion transport is the confidentiality layer.
FROM alpine:3.21
RUN apk add --no-cache tor nginx
COPY entrypoint.sh /usr/local/bin/mirror-entrypoint.sh
RUN chmod +x /usr/local/bin/mirror-entrypoint.sh
# /www is the served document root (mounted); /var/lib/tor persists the onion key (mounted).
EXPOSE 9050
ENTRYPOINT ["/usr/local/bin/mirror-entrypoint.sh"]
