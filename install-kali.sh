#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Uso: bash install-kali.sh [opções]

Opções:
  --all-extras         Instala cryptography, pysnmp e Playwright.
  --skip-system-deps   Não instala pacotes apt (nmap, venv, libpcap).
  -h, --help           Mostra esta ajuda.

Variáveis:
  NETMAPPER_VENV_DIR   Diretório do ambiente virtual.
  NETMAPPER_BIN_DIR    Diretório dos comandos (padrão: ~/.local/bin).
EOF
}

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${NETMAPPER_VENV_DIR:-$ROOT_DIR/.venv-kali}"
BIN_DIR="${NETMAPPER_BIN_DIR:-$HOME/.local/bin}"
ALL_EXTRAS=0
SKIP_SYSTEM_DEPS=0

while (($# > 0)); do
    case "$1" in
        --all-extras)
            ALL_EXTRAS=1
            ;;
        --skip-system-deps)
            SKIP_SYSTEM_DEPS=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Opção desconhecida: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'Este instalador é exclusivo para Linux/Kali.\n' >&2
    exit 1
fi

if ((SKIP_SYSTEM_DEPS == 0)); then
    if ! command -v apt-get >/dev/null 2>&1; then
        printf 'apt-get não foi encontrado. Use --skip-system-deps e instale as dependências manualmente.\n' >&2
        exit 1
    fi

    needs_system_deps=0
    command -v python3 >/dev/null 2>&1 || needs_system_deps=1
    command -v nmap >/dev/null 2>&1 || needs_system_deps=1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import venv' >/dev/null 2>&1 || needs_system_deps=1
    fi
    if ((needs_system_deps)); then
        if [[ "${EUID}" -eq 0 ]]; then
            apt_runner=()
        elif command -v sudo >/dev/null 2>&1; then
            apt_runner=(sudo)
        else
            printf 'sudo é necessário para instalar dependências apt.\n' >&2
            exit 1
        fi
        "${apt_runner[@]}" apt-get update
        "${apt_runner[@]}" apt-get install -y nmap python3-venv python3-pip libpcap-dev
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'python3 não foi encontrado. Instale-o antes de continuar.\n' >&2
    exit 1
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    mkdir -p "$(dirname -- "$VENV_DIR")"
    python3 -m venv "$VENV_DIR"
fi

python_bin="$VENV_DIR/bin/python"
"$python_bin" -m pip install --upgrade pip
if ((ALL_EXTRAS)); then
    "$python_bin" -m pip install "$ROOT_DIR[all]"
else
    "$python_bin" -m pip install "$ROOT_DIR"
fi

mkdir -p "$BIN_DIR"
ln -sfn "$VENV_DIR/bin/netscan" "$BIN_DIR/netscan"
ln -sfn "$VENV_DIR/bin/Netscan" "$BIN_DIR/Netscan"
ln -sfn "$VENV_DIR/bin/netmapper-dashboard" "$BIN_DIR/netmapper-dashboard"

"$VENV_DIR/bin/netscan" --help >/dev/null

printf '\nNetMapper instalado para Kali Linux.\n'
printf 'Comando: %s/netscan\n' "$BIN_DIR"
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    printf 'Adicione ao PATH: export PATH="%s:$PATH"\n' "$BIN_DIR"
fi
printf 'Para descoberta ARP local, use sudo apenas no comando que precisar de raw socket.\n'
if ((ALL_EXTRAS)); then
    printf 'Playwright instalado; para screenshots, instale o navegador com:\n'
    printf '  %s -m playwright install chromium\n' "$python_bin"
fi
