# NetMapper no Windows

Esta é a instalação específica para Windows. Ela usa:

- PowerShell para instalação e execução;
- um ambiente virtual separado em `.venv-windows`;
- Nmap instalado pelo WinGet;
- Npcap para o modo ARP local.

## Instalação

Abra o PowerShell na pasta do projeto e execute:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
```

Para baixar o projeto público pelo terminal:

```powershell
winget install --id GitHub.cli --exact
gh auth login --hostname github.com --git-protocol https --web
gh repo clone beretdt/netscan
Set-Location .\netscan
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
```

O instalador cria `.venv-windows`, instala o pacote Python e tenta instalar o
Nmap com:

```powershell
winget install --id Insecure.Nmap --exact
```

Abra um novo terminal depois da instalação para recarregar o `PATH`. Verifique:

```powershell
nmap --version
.\.venv-windows\Scripts\Netscan.exe --help
```

## Uso

Use somente alvos próprios ou explicitamente autorizados:

```powershell
.\.venv-windows\Scripts\Netscan.exe scan 192.0.2.10 --ports 80,443 --json
.\.venv-windows\Scripts\Netscan.exe passive --profile cache --json
```

Para o dashboard Flask legado:

```powershell
& .\.venv-windows\Scripts\netmapper-dashboard.exe
```

O modo ARP local exige Npcap e privilégios adequados. O Nmap usa TCP connect
por padrão neste projeto; detecção de OS, captura de camada 2 e ARP podem
exigir elevação.

## Recursos opcionais

```powershell
.\install-windows.ps1 -AllExtras
& .\.venv-windows\Scripts\python.exe -m playwright install chromium
```

O Nuclei, o subfinder e o SearchSploit continuam sendo binários separados e
somente são usados quando explicitamente solicitados.

## Reinstalação/atualização

```powershell
git pull
.\install-windows.ps1
```

Para instalar o ambiente em outro local:

```powershell
$env:NETMAPPER_VENV_DIR = "$HOME\AppData\Local\NetMapper\venv"
.\install-windows.ps1
```
