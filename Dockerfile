# EnumGod - runs the Linux/bash modules, the analysis engine, and the report tools.
# (Windows .ps1 modules run on Windows hosts; this image covers the *nix + analysis side.)
#   docker build -t enumgod .
#   docker run --rm -v "$PWD/loot:/loot" enumgod bash run/run-all.sh -o /loot
#   docker run --rm -v "$PWD/loot:/loot" enumgod python3 research/eg_analyze.py /loot --out /loot/analysis
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash curl jq ldap-utils iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/enumgod
COPY . .
RUN chmod +x linux/*.sh network/*.sh cloud/*.sh directory/*.sh secrets/*.sh macos/*.sh run/*.sh tools/*.sh 2>/dev/null || true
# no ENTRYPOINT: pass the command you want (bash run/run-all.sh ... or python3 research/eg_analyze.py ...)
CMD ["bash", "-lc", "echo 'EnumGod image. Run: bash run/run-all.sh -o /loot  |  python3 research/eg_analyze.py /loot'"]
