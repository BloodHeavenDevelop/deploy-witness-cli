# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
mkdir -p /bench/other-checkout && cp compose.yml /bench/other-checkout/ && cd /bench/other-checkout && docker compose -p bench up -d
