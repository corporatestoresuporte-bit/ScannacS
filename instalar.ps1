<#
.SYNOPSIS
  Instalador do agente-vulnerabilidades no Windows: prepara o ambiente, cria o
  atalho `scan` no PATH e mostra quais ferramentas de scan faltam instalar.
  Nao baixa ferramentas ofensivas sozinho - apenas mostra os comandos.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
Set-Location -LiteralPath $Root

function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "!!  $m" -ForegroundColor Yellow }

Step "agente-vulnerabilidades - instalacao"

# Python
$py = $null
foreach ($c in @('py','python','python3')) {
  $g = Get-Command $c -ErrorAction SilentlyContinue
  if ($g) { $py = $g.Source; break }
}
if (-not $py) { Warn "Python 3.11+ nao encontrado. Instale e rode de novo."; exit 1 }
Write-Host "    Python: $py"

# PYTHONPATH (base sem dependencias externas)
$src = Join-Path $Root 'src'
$env:PYTHONPATH = $src

# Caminho curto (8.3) para evitar bug de acento no nome do usuario
$short = $src
try { $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($src).ShortPath } catch {}

# Diretorio de Scripts do Python (costuma estar no PATH)
$scriptsDir = Split-Path $py -Parent
$cand = Join-Path $scriptsDir 'Scripts'
if (Test-Path $cand) { $scriptsDir = $cand }

# Cria o atalho `scan` (scan.cmd) no PATH
$wrapper = Join-Path $scriptsDir 'scan.cmd'
$content = "@echo off`r`nset `"PYTHONPATH=$short`"`r`npython -m agente scan %*"
try {
  Set-Content -Path $wrapper -Value $content -Encoding ascii
  Write-Host "    Atalho criado: $wrapper"
  Write-Host "    Agora voce pode digitar:  scan <alvo>"
} catch {
  Warn "Nao consegui criar $wrapper. Rode como: `$env:PYTHONPATH='src'; python -m agente scan <alvo>"
}

# Estado do projeto + ferramentas
Step "Estado"
try { & $py -m agente doctor } catch { Warn "doctor falhou: $_" }

Step "Ferramentas externas - comandos de instalacao (opcional)"
Write-Host "  nuclei : winget install ProjectDiscovery.nuclei"
Write-Host "  nmap   : winget install Insecure.Nmap"
Write-Host "  ffuf   : go install github.com/ffuf/ffuf/v2@latest"
Write-Host "  sqlmap : git clone https://github.com/sqlmapproject/sqlmap C:\tools\sqlmap"
Write-Host "  sslyze : pip install sslyze   (evite se seu usuario tem acento; use WSL)"
Write-Host ""
Step "Pronto. Use:  scan <alvo>   (ex.: scan exemplo.com)"
