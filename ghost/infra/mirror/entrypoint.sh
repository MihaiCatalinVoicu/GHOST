#!/bin/sh
# Mirror entrypoint: Tor first (it writes the onion hostname into $HS_DIR/hostname on first
# start), then nginx serving /www over plain HTTP on loopback:8080, exposed as the onion's port 80.
set -e
HS_DIR=/var/lib/tor/mirror
mkdir -p "$HS_DIR" /run/tor /www
chown -R tor:nogroup /var/lib/tor "$HS_DIR"
chmod 0700 "$HS_DIR"

cat > /etc/tor/mirror.torrc <<EOF
DataDirectory /var/lib/tor
SOCKSPort 127.0.0.1:9050
HiddenServiceDir $HS_DIR
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePort 443 127.0.0.1:8081
EOF

# Tor as the tor user; wait for the hostname file (generated from the persisted key set).
su -s /bin/sh tor -c "tor -f /etc/tor/mirror.torrc" &
for i in $(seq 1 60); do
  [ -s "$HS_DIR/hostname" ] && break
  sleep 1
done
if [ ! -s "$HS_DIR/hostname" ]; then
  echo "mirror: onion hostname did not appear" >&2
  exit 1
fi
echo "mirror: onion=$(cat "$HS_DIR/hostname")"

cat > /etc/nginx/nginx.conf <<'NGINX'
user nginx;
worker_processes 1;
pid /run/nginx.pid;
# No-log configuration (design §7.1, gate G-D10): the image links nginx's logs to the
# container's stdout/stderr, which Docker's json-file driver would store on disk.
error_log /dev/stderr crit;
events { worker_connections 128; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  access_log off;
  server {
    listen 127.0.0.1:8080;
    root /www;
    autoindex off;
    # Static mirrors answer GET/HEAD only; no server tokens, no validators, no conditional
    # responses: freshness is the manifest's job, not the mirror's (§7.1).
    server_tokens off;
    etag off;
    if_modified_since off;
    log_not_found off;
    location / { try_files $uri $uri/ =404; }
  }
  # The app fetches over HTTP/2 with prior knowledge (h2c) inside the onion stream
  # (D14: the client's hyper http2 stack, SETTINGS pinned and golden-tested); browsers and
  # ghost-verify use the HTTP/1.1 listener on port 80 of the same onion.
  server {
    listen 127.0.0.1:8081;
    http2 on;
    root /www;
    autoindex off;
    server_tokens off;
    etag off;
    if_modified_since off;
    log_not_found off;
    location / { try_files $uri $uri/ =404; }
  }
}
NGINX
exec nginx -g 'daemon off;'
