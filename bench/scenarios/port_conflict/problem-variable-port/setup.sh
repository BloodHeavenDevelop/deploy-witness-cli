# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
# The .env is written here rather than committed: the repository ignores every .env.
printf 'WEB_PORT=18080\n' > .env
docker run -d --name squatter -p 18080:80 alpine:3.21 sleep 3600
