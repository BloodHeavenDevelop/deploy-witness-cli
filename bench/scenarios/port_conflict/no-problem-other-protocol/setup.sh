# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
docker run -d --name squatter -p 18080:80/udp alpine:3.21 sleep 3600
