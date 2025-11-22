FROM owasp/modsecurity-crs:nginx-alpine
USER root
RUN apk update && apk add --no-cache iproute2 bash
RUN mkdir -p /etc/nginx/modsecurity.d
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf
RUN chmod -R 0777 /etc/nginx/modsecurity.d || true
RUN chown -R nginx:nginx /etc/nginx/modsecurity.d || true
CMD ["sleep", "infinity"]
