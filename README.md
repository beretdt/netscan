# NetMapper

Ferramenta Python com dashboard Flask e CLI `Netscan`/`netscan` para:

- **modo legado local ARP** com Scapy (`Netscan 192.168.1.0/24`);
- **scan externo com Nmap** (`Netscan -ext IP`, `Netscan -ext -vuln IP`);
- **descoberta passiva** baseada em cache ARP e consultas UDP locais opcionais;
- **correlação offline/local de CVEs** a partir de `product/version` em SQLite;
- **persistência de scans/hosts/ports/findings**, diff e relatórios.

O dashboard existente foi preservado em `app.py` e continua focado no modo ARP local.

## Instalação por plataforma

As instalações são separadas para evitar misturar ambientes e instruções de
captura de pacotes:

- [Kali Linux](README-KALI.md): `bash install-kali.sh`, `apt`, Nmap e `.venv-kali`;
- [Windows](README-WINDOWS.md): `.\install-windows.ps1`, WinGet, Nmap/Npcap e
  `.venv-windows`.

Clone público do projeto:

```bash
git clone https://github.com/beretdt/netscan.git
cd netscan
```

Para desenvolvimento manual em qualquer plataforma:

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m pip install -e .
```

O Nmap é obrigatório somente para os comandos de scan externo. Scapy para ARP
ativo também exige acesso a raw socket: privilégios adequados no Kali e Npcap
no Windows.

## Dependências opcionais

- `pip install -e .[crypto]` para parsing TLS mais rico com `cryptography`;
- `pip install -e .[snmp]` para o módulo SNMP opcional;
- `pip install -e .[screenshots]` e depois `playwright install` para screenshots;
- `nuclei` e `subfinder` são **binários externos** no `PATH`.
- `searchsploit` é opcional e usa somente o índice local quando `--searchsploit` é informado.

## Compatibilidade legada preservada

```powershell
Netscan 192.168.1.0/24
Netscan -ext 203.0.113.10
Netscan -ext -vuln 203.0.113.10
```

## Novos subcomandos

### 1) Scan externo com plugins e SQLite

Perfil básico = apenas descoberta Nmap. Os módulos mais ruidosos são **opt-in**.

```powershell
netscan scan 203.0.113.10
netscan scan 203.0.113.10 --profile enrich --tls --cve-local
netscan scan 203.0.113.10 --nuclei --default-creds --screenshot --scope-file scope.yaml
netscan scan 203.0.113.10 --cve-local --searchsploit --scope-file scope.yaml
```

Plugins disponíveis (`netscan plugins`) incluem:

- `nmap-service`: descoberta ativa via Nmap;
- `tls`: coleta subject/issuer/SAN/validade/SHA-256;
- `cve-local`: consulta **somente** SQLite local;
- `nmap-vuln`: NSE `vuln` do Nmap;
- `nuclei`: integração opcional via JSONL;
- `default-creds`: pequena lista opt-in para HTTP Basic/FTP;
- `screenshot`: Playwright opcional;
- `subdomains`: enumeração opt-in via `subfinder`;
- `arp-active`: ARP ativo local (opt-in, compatibilidade interna).

### 2) Descoberta passiva

Por padrão usa apenas **leitura de cache**. O perfil `lan` inclui consultas UDP locais.

```powershell
netscan passive
netscan passive --profile lan
netscan passive --profile lan --plugin snmp 192.168.1.10 192.168.1.20
netscan passive --profile lan --plugin snmp --snmp-community public,private 192.168.1.1
```

Diferença importante:

- **cache-read**: `proc-arp`, `ip-neigh`, `arp-a` (não enviam tráfego);
- **udp-query**: `mdns`, `ssdp`, `llmnr`, `nbns`, `snmp` (enviam consultas UDP explícitas).

### 3) Base CVE local/offline

A atualização é **explícita**. O feed **não é baixado durante o scan**. O importador aceita
feeds NVD 2.x e o formato legado NVD 1.1.

```powershell
netscan cve update --feed-file .\nvd-sample.json
netscan cve update --feed-url https://exemplo/feed.json.gz
netscan cve lookup "Apache httpd" 2.4.49
```

### 4) TLS

```powershell
netscan tls 203.0.113.10 --port 443
netscan tls 203.0.113.10 --port 443 --insecure
```

Sem `--insecure`, a validação TLS do alvo permanece ativa.

### 5) Screenshot web

Somente URLs derivadas de portas HTTP/HTTPS descobertas:

```powershell
netscan screenshot 203.0.113.10
netscan screenshot 203.0.113.10 --scan-id 7 --output-dir .\screenshots
```

### 6) Subdomínios

Somente quando explicitamente solicitado e dentro do escopo autorizado:

```powershell
netscan subdomains example.com --scope-file scope.yaml
```

### 7) Diff e relatórios

```powershell
netscan diff 10 12
netscan report 12 --format json
netscan report 12 --format md --output report.md
netscan report 12 --format html --output report.html
```

## Escopo opcional

Se `scope.yaml` for fornecido via `--scope-file`, os comandos ativos externos rejeitam alvos fora de `allowed` ou dentro de `denied`.
Use `scope.yaml.example` como base.

O arquivo pode conter também metadados de engagement/janela; o enforcement usa somente
as listas `allowed` e `denied`. A opção também está disponível no modo legado:

```powershell
netscan -ext 203.0.113.10 --scope-file scope.yaml
```

Cada scan salvo cria registros SQLite para scans, hosts, portas, findings, certificados
TLS e artefatos de screenshot. O caminho padrão é `netmapper.sqlite3` e pode ser
alterado com `--database`.

## Segurança / ruído

- `default-creds` é **opt-in**, usa lista pequena configurável e não faz brute force amplo;
- `nmap-vuln`, `nuclei`, `default-creds`, `screenshot` e `subdomains` podem gerar logs/tráfego;
- `passive --profile lan` envia consultas UDP locais, embora evite ARP broadcast agressivo;
- execute apenas em ativos autorizados.

## Dashboard Flask

```powershell
python app.py
```

A interface web atual continua disponível em `http://127.0.0.1:5000`.

## Validação offline sugerida

```powershell
.\.venv\Scripts\python -m compileall .
.\.venv\Scripts\python -m unittest discover -s tests -v
.\.venv\Scripts\Netscan.exe --help
```
