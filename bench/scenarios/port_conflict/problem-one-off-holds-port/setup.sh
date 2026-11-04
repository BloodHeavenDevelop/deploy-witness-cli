# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
docker compose -f compose.yml -p bench run -d --service-ports --name bench-web-run web
