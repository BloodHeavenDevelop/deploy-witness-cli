# Stages the situation inside the disposable engine; runs as root, cwd = this directory.
# The other checkout runs a different command, so the planned up replaces its container.
mkdir -p /bench/other-checkout && sed 's/3600/7200/' compose.yml > /bench/other-checkout/compose.yml && cd /bench/other-checkout && docker compose -p bench up -d
