# Live deploy acceptance fixture (unhealthy). busybox httpd on port 80, nothing else.
FROM busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
RUN mkdir -p /www && echo deploy-probe-unhealthy > /www/index.html
# No /www/health: the probe gets 404 -- a complete deployment of an unhealthy workload (DCR 7.8 C).
EXPOSE 80
CMD ["httpd", "-f", "-p", "80", "-h", "/www"]
