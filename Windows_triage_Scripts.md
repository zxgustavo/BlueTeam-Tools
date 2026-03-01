# 🛡️ Windows Forensics & Incident Response

Este guia contém comandos essenciais de PowerShell para triagem inicial de incidentes em sistemas Windows. O foco é a coleta rápida de artefatos de memória, rede e persistência.

## 📋 Pré-requisitos
> **Nota:** Para a coleta de logs de segurança e manipulação de serviços, o PowerShell deve ser executado como **Administrador**.

---

## 1. Investigação de Processos (Memória)
Identificação de processos suspeitos, consumo anômalo de recursos e verificação de IDs de sistema.

```powershell
# Lista os 10 processos com maior consumo de CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Análise: Verificamos se processos legítimos (como svchost.exe) possuem PIDs anômalos ou se processos de usuário estão rodando na Sessão 0.

## 2. Monitoramento de Rede (Conexões Ativas)
Mapeamento de conexões estabelecidas para detectar comunicação com servidores de Comando e Controle (C2) ou movimentação lateral.
# Lista conexões TCP estabelecidas e o processo responsável  
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Sort-Object RemoteAddress

Análise: Investigamos conexões em portas suspeitas (ex: 4444, 8080) ou IPs externos não catalogados na infraestrutura.

3. Análise de Persistência (Serviços)
Malwares frequentemente utilizam serviços com inicialização automática para garantir permanência no sistema.
# Lista serviços em execução configurados para início automático
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, StartType | Sort-Object Name

Análise: Buscamos por serviços com nomes aleatórios ou sem descrições oficiais da Microsoft/Fabricante.

4. Auditoria de Logons (Event Logs)
Rastreamento de acessos ao sistema utilizando o Event ID 4624 (Logon bem-sucedido).
# Recupera os últimos 10 logons bem-sucedidos
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Select-Object TimeGenerated, ReplacementStrings

Análise: Monitoramos o "Logon Type" para identificar acessos via RDP (Tipo 10) ou rede (Tipo 3) em horários não comerciais.
