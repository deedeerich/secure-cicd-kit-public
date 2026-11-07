# Live deploy acceptance fixture (healthy-a). busybox httpd on port 80, nothing else.
FROM busybox:1.38.0@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
RUN mkdir -p /www && echo deploy-probe-healthy-a > /www/index.html
RUN echo ok > /www/health
EXPOSE 80
CMD ["httpd", "-f", "-p", "80", "-h", "/www"]
