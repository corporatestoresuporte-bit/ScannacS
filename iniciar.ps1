<#
.SYNOPSIS
  Iniciador do agente-vulnerabilidades: prepara o ambiente, verifica o Claude
  Code e abre a interface interativa (UI dark) no próprio terminal.

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

# --- UI dark (fundo preto) -------------------------------------------------
try {
  $ui = $Host.UI.RawUI
  $ui.BackgroundColor = 'Black'
  $ui.ForegroundColor = 'Gray'
  Clear-Host
} catch {}

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Write-Err ($m) { Write-Host "XX  $m" -ForegroundColor Red }

Write-Host ""
Write-Host "  +-------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  |   AGENTE-VULNERABILIDADES  -  auditoria segura   |" -ForegroundColor Cyan
Write-Host "  +-------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "    Projeto: $Root" -ForegroundColor DarkGray

# --- 1. Python -------------------------------------------------------------
$py = $null
foreach ($cand in @('py','python','python3')) {
  $c = Get-Command $cand -ErrorAction SilentlyContinue
  if ($c) { $py = $c.Source; break }
}
if (-not $py) {
  Write-Err "Python 3.11+ nao encontrado no PATH."
  Write-Host "    Proxima acao: instale o Python e reabra o terminal."
  exit 1
}
Write-Host "    Python: $py" -ForegroundColor DarkGray

# --- 2. Claude Code --------------------------------------------------------
$claude = Get-Command claude -ErrorAction SilentlyContinue
if (-not $claude) {
  Write-Err "Claude Code (claude) nao encontrado no PATH."
  Write-Host "    Proxima acao: instale o Claude Code e rode 'claude --version'."
  Write-Host "    (O restante do ambiente foi preparado; reabra apos instalar.)"
} else {
  Write-Host "    Claude Code: $($claude.Source)" -ForegroundColor DarkGray
}

# --- 3. Ambiente local -----------------------------------------------------
# A base nao tem dependencias externas (stdlib). Basta apontar o PYTHONPATH
# para src/. As settings do projeto (.claude/settings.json) fazem o mesmo
# dentro da sessao do Claude Code, entao `python -m agente` funciona la tambem.
$env:PYTHONPATH = (Join-Path $Root 'src')
Write-Host "    PYTHONPATH: $($env:PYTHONPATH)" -ForegroundColor DarkGray

function Invoke-Agente { param([string[]]$CmdArgs)
  & $py -m agente @CmdArgs
}

# --- 4. Resumo compacto ----------------------------------------------------
Write-Step "Estado do projeto"
try { Invoke-Agente @('doctor') } catch { Write-Warn "doctor falhou: $_" }

# --- 5. Abrir a interface --------------------------------------------------
if ($NoLaunch) {
  Write-Step "Preparado. (--NoLaunch: interface nao aberta.)"
  Write-Host "    Para abrir: .\iniciar.ps1   ou   agente ui"
  Write-Host "    Na interface, digite:  /scan" -ForegroundColor Green
  exit 0
}
if (-not $claude) { exit 1 }

Write-Step "Abrindo o Claude Code no projeto (Ctrl+C encerra)"
Write-Host "    Dica: digite  /scan  para configurar/rodar a auditoria." -ForegroundColor Green
try {
  # Interface nativa do Claude Code como centro da experiencia.
  & $claude.Source -n 'AgenteAuditoria' '/scan'
} catch [System.Management.Automation.PipelineStoppedException] {
  Write-Host ""; Write-Warn "Interrompido pelo teclado."
} finally {
  Write-Step "Sessao encerrada."
}
