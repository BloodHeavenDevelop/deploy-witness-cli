# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
cat > old.yml <<'YML'
services:
  legacy:
    image: alpine:3.21
    command: ["sleep", "3600"]
    ports: ["18080:80"]
YML
docker compose -f old.yml -p bench up -d
rm old.yml
