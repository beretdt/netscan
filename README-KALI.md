# NetMapper no Kali Linux

Esta é a instalação específica para Kali Linux. Ela usa:

- `apt` para instalar Nmap, Python/venv e libpcap;
- um ambiente virtual separado em `.venv-kali`;
- comandos instalados em `~/.local/bin`;
- `sudo` somente quando uma operação de descoberta ARP precisar de raw socket.

## Baixar pelo terminal

```bash
sudo apt update
sudo apt install -y git openssh-client curl
```

### Opção A: SSH (recomendado)

Se ainda não houver uma chave SSH no Kali:

```bash
ssh-keygen -t ed25519 -C "beretdt@kali"
cat ~/.ssh/id_ed25519.pub
```

Adicione a chave exibida em
<https://github.com/settings/keys>. Depois valide e clone:

```bash
ssh -T git@github.com
git clone git@github.com:beretdt/netscan.git
cd netscan
bash install-kali.sh
```

### Opção B: GitHub CLI

O pacote `gh` pode não existir no apt do Kali. Instale o release oficial:

```bash
GH_VERSION="$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest \
  | sed -n 's/.*"tag_name": "v\([^"]*\)".*/\1/p' | head -n1)"
GH_ARCH="$(case "$(dpkg --print-architecture)" in amd64) echo amd64;; arm64) echo arm64;; armhf) echo armv6;; *) echo unsupported;; esac)"
test "$GH_ARCH" != unsupported
curl -fL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${GH_ARCH}.tar.gz" -o /tmp/gh.tar.gz
tar -xzf /tmp/gh.tar.gz -C /tmp
sudo install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${GH_ARCH}/bin/gh" /usr/local/bin/gh
gh auth login --hostname github.com --git-protocol https --web
gh repo clone beretdt/netscan
cd netscan
bash install-kali.sh
```

Se o diretório já foi copiado para o Kali, basta executar `bash install-kali.sh`
dentro dele.

O instalador instala o Nmap, cria `.venv-kali`, instala o pacote e cria os
comandos `netscan` e `Netscan` em `~/.local/bin`. Se esse diretório ainda não
estiver no `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
netscan --help
nmap --version
```

## Uso

Use somente alvos próprios ou explicitamente autorizados:

```bash
# Scan externo com Nmap
netscan scan 192.0.2.10 --ports 22,80,443 --json

# Descoberta passiva sem enviar consultas UDP
netscan passive --profile cache --json

# Dashboard Flask legado
netmapper-dashboard
```

Para ARP ativo na rede local, execute apenas o comando que precisa de raw
socket com privilégios adequados:

```bash
sudo "$PWD/.venv-kali/bin/netscan" 192.168.1.0/24
```

O dashboard pode ser executado diretamente com `netmapper-dashboard`.

O Nmap usa TCP connect por padrão neste projeto e normalmente não precisa de
root. `-O`, ARP ativo e alguns modos de captura podem exigir privilégios.

## Recursos opcionais

```bash
bash install-kali.sh --all-extras
"$PWD/.venv-kali/bin/python" -m playwright install chromium
```

O Nuclei, o subfinder e o SearchSploit continuam sendo binários separados e
somente são usados quando explicitamente solicitados.

## Reinstalação/atualização

```bash
git pull
bash install-kali.sh
```

Para instalar em outro local:

```bash
NETMAPPER_VENV_DIR="$HOME/.local/share/netmapper-kali/venv" \
NETMAPPER_BIN_DIR="$HOME/.local/bin" \
bash install-kali.sh
```
