cat > /etc/nginx/nginx.conf <<NGINX
user nginx;
http {
  access_log /var/log/nginx/access.log;
  error_log stderr crit;
  server {
    listen 127.0.0.1:8080;
    listen 127.0.0.1:8081;
    server_tokens off;
    etag off;
    if_modified_since off;
    log_not_found off;
    location / { try_files $uri =404; }
  }
}
NGINX
