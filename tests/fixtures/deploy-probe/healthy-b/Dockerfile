# Live deploy acceptance fixture (healthy-b). busybox httpd on port 80, nothing else.
FROM busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
RUN mkdir -p /www && echo deploy-probe-healthy-b > /www/index.html
RUN echo ok > /www/health
EXPOSE 80
CMD ["httpd", "-f", "-p", "80", "-h", "/www"]
