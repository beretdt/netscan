# NetMapper no Kali Linux

Esta é a instalação específica para Kali Linux. Ela usa:

- `apt` para instalar Nmap, Python/venv e libpcap;
- um ambiente virtual separado em `.venv-kali`;
- comandos instalados em `~/.local/bin`;
- `sudo` somente quando uma operação de descoberta ARP precisar de raw socket.

## Baixar pelo terminal

```bash
git clone https://github.com/beretdt/netscan.git
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
