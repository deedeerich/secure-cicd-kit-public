# Live deploy acceptance fixture (unhealthy). busybox httpd on port 80, nothing else.
FROM busybox:1.38.0@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
RUN mkdir -p /www && echo deploy-probe-unhealthy > /www/index.html
# No /www/health: the probe gets 404 -- a complete deployment of an unhealthy workload (DCR 7.8 C).
EXPOSE 80
CMD ["httpd", "-f", "-p", "80", "-h", "/www"]
