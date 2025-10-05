FROM owasp/modsecurity-crs:nginx-alpine
# Standard-ModSecurity/Nginx-Image mit OWASP CRS
# Das Image bringt ModSecurity und Nginx bereits mit.
RUN mkdir -p /etc/nginx/modsecurity.d
# Kopiere die custom configs
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.d/modsecurity.conf
CMD ["nginx", "-g", "daemon off;"]
