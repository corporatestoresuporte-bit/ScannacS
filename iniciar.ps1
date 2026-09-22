<#
.SYNOPSIS
  Iniciador do agente-vulnerabilidades: prepara o ambiente, verifica o Claude
  Code e abre a interface interativa no próprio terminal.

  Abordagem inspirada no iniciador do RAPTOR (MIT): higiene de ambiente →
  verificação de dependências (python, claude) → resumo → abre `claude`.
  Reimplementado em PowerShell (o de origem é POSIX). Ver docs/integracoes.md.

.PARAMETER NoLaunch
  Só prepara e mostra o resumo; não abre a interface (útil para verificação).
#>
[CmdletBinding()]
param([switch]$NoLaunch)

$ErrorActionPreference = 'Stop'
# Raiz = pasta deste script (lida bem com espaços e acentos no caminho).
$Root = $PSScriptRoot
Set-Location -LiteralPath $Root

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Write-Err ($m) { Write-Host "XX  $m" -ForegroundColor Red }

Write-Step "agente-vulnerabilidades — inicializando"
Write-Host "    Projeto: $Root"

# --- 1. Python -------------------------------------------------------------
$py = $null
foreach ($cand in @('py','python','python3')) {
  $c = Get-Command $cand -ErrorAction SilentlyContinue
  if ($c) { $py = $c.Source; break }
}
if (-not $py) {
  Write-Err "Python 3.11+ não encontrado no PATH."
  Write-Host "    Próxima ação: instale o Python e reabra o terminal."
  exit 1
}
Write-Host "    Python: $py"

# --- 2. Claude Code --------------------------------------------------------
$claude = Get-Command claude -ErrorAction SilentlyContinue
if (-not $claude) {
  Write-Err "Claude Code (claude) não encontrado no PATH."
  Write-Host "    Próxima ação: instale o Claude Code e rode 'claude --version'."
  Write-Host "    (O restante do ambiente foi preparado; reabra após instalar.)"
} else {
  Write-Host "    Claude Code: $($claude.Source)"
}

# --- 3. Ambiente local -----------------------------------------------------
# A base não tem dependências externas (stdlib). Basta apontar o PYTHONPATH
# para src/. As settings do projeto (.claude/settings.json) fazem o mesmo
# dentro da sessão do Claude Code, então `python -m agente` funciona lá também.
# Dependências de scanners/IA entram depois (requirements.txt + venv).
$env:PYTHONPATH = (Join-Path $Root 'src')
Write-Host "    PYTHONPATH: $($env:PYTHONPATH)"

function Invoke-Agente { param([string[]]$CmdArgs)
  & $py -m agente @CmdArgs
}

# --- 4. Resumo compacto ----------------------------------------------------
Write-Step "Estado do projeto"
try { Invoke-Agente @('doctor') } catch { Write-Warn "doctor falhou: $_" }

# --- 5. Abrir a interface --------------------------------------------------
if ($NoLaunch) {
  Write-Step "Preparado. (--NoLaunch: interface não aberta.)"
  Write-Host "    Para abrir: .\iniciar.ps1   ou   agente ui"
  exit 0
}
if (-not $claude) { exit 1 }

Write-Step "Abrindo o Claude Code no projeto (Ctrl+C encerra)"
try {
  # Interface nativa do Claude Code como centro da experiência.
  & $claude.Source -n 'AgenteAuditoria' '/auditoria'
} catch [System.Management.Automation.PipelineStoppedException] {
  Write-Host ""; Write-Warn "Interrompido pelo teclado."
} finally {
  Write-Step "Sessão encerrada."
}
