#!/usr/bin/env bash
set -euo pipefail

# Rutas relativas a este script, aunque se ejecute desde otro directorio.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi

: "${V1_API_KEY:?Configura V1_API_KEY en .env o en tu entorno}"
: "${V1_REGION:?Configura V1_REGION en .env o en tu entorno}"

node -e 'const [a,b]=process.versions.node.split(".").map(Number); if (a<22||(a===22&&b<23)) { console.error("Se requiere Node.js >= 22.23.4 (file-security-sdk 1.4.8)"); process.exit(1) }'

npm ci --no-fund --no-audit
printf 'Iniciando la demo de File Security en http://localhost:%s\n' "${PORT:-8080}"
exec node app.js
