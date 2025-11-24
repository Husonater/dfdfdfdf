FROM owasp/modsecurity-crs:nginx-alpine
USER root
RUN apk update && apk add --no-cache iproute2 bash curl net-tools

# Logs & Permissions
RUN mkdir -p /var/log/nginx &&     ln -sf /dev/stdout /var/log/nginx/access.log &&     ln -sf /dev/stderr /var/log/nginx/error.log &&     chmod -R 777 /var/log/nginx /etc/nginx /var/run

# Copy Configs
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf

# Prevent Auto-Start (Manual Control)
ENTRYPOINT []
CMD ["sleep", "infinity"]
