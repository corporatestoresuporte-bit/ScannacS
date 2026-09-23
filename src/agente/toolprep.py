"""Preparo do ambiente PELA INTERFACE: detecta, instala e valida as ferramentas.

Sem o usuário procurar instruções por ferramenta. Fontes oficiais, ambiente
consistente com o executor (BIN_DIR + Scripts do Python atual entram no PATH).

Diagnóstico distingue:
  funcional              (verde: encontrada + versão executa; verde = utilizável)
  nao_instalada          (não existe)
  instalada_nao_localizada (existe em local conhecido, mas fora do PATH do executor)
  incompativel           (versão abaixo do mínimo / arquitetura não suportada)
  precisa_config         (instalada, mas depende de config: templates/db/docker)

Classificação por alvo: necessaria | complementar | nao_aplicavel.

Instalação automática (sem sudo/admin) para: pip (semgrep/sslyze/wafw00f),
binários oficiais (trivy/nuclei/ffuf) e git (sqlmap). nmap e ZAP pedem
intervenção (sistema/admin ou docker/java) — conduzidas com texto claro + retry.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

from . import config

# --------------------------------------------------------------------------- #
# ambiente
# --------------------------------------------------------------------------- #
def os_info() -> dict:
    system = "windows" if os.name == "nt" else "linux"
    distro = ""
    if system == "linux":
        try:
            data = Path("/etc/os-release").read_text(encoding="utf-8")
            m = re.search(r"^ID=(.+)$", data, re.M)
            distro = (m.group(1).strip().strip('"').lower() if m else "")
        except OSError:
            distro = ""
    arch = (platform.machine() or "").lower()
    arch = "amd64" if arch in ("x86_64", "amd64", "x64") else (
        "arm64" if arch in ("arm64", "aarch64") else arch)
    return {"os": system, "distro": distro, "arch": arch}


def _which(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    argv = list(cmd)
    exe = shutil.which(argv[0])
    if exe:
        argv[0] = exe
        # no Windows, wrappers .cmd/.bat só rodam via cmd /c
        if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
            argv = ["cmd", "/c"] + argv
    try:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))
    except FileNotFoundError:
        return 127, "não encontrado"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


# --------------------------------------------------------------------------- #
# registro das ferramentas integradas
# --------------------------------------------------------------------------- #
# kind: builtin|pip|binary|git|system|docker
# targets: onde é NECESSÁRIA; complementar/aplicável derivam da função role().
TOOLS = [
    # embutidos (sempre funcionais; sem instalar)
    {"key": "builtin-web", "label": "Motores embutidos (headers/TLS/fingerprint)",
     "kind": "builtin", "necess": {"site", "server"}, "compl": set()},
    {"key": "bundle-audit", "label": "Segredo no bundle (JS do cliente)",
     "kind": "builtin", "necess": {"site"}, "compl": set()},
    {"key": "api-graphql-ws", "label": "GraphQL/WebSocket (introspection/handshake)",
     "kind": "builtin", "necess": set(), "compl": {"site"}},
    {"key": "codereview", "label": "Análise de código (SAST-leve)",
     "kind": "builtin", "necess": {"code"}, "compl": set()},
    {"key": "deps-osv", "label": "Dependências (OSV/KEV/EPSS)",
     "kind": "builtin", "necess": {"code"}, "compl": set()},
    # código
    {"key": "semgrep", "label": "Semgrep (SAST real)", "kind": "pip",
     "pip": "semgrep", "version": ["semgrep", "--version"],
     "necess": set(), "compl": {"code"}},
    {"key": "trivy", "label": "Trivy (IaC/misconfig)", "kind": "binary",
     "repo": "aquasecurity/trivy",
     "asset": {"windows": r"(?i)trivy_.*windows-64bit\.zip",
               "linux": r"(?i)trivy_.*Linux-64bit\.tar\.gz"},
     "exe": "trivy", "version": ["trivy", "--version"],
     "necess": set(), "compl": {"code"}},
    # site / API
    {"key": "nuclei", "label": "Nuclei (scanner de vulnerabilidades)", "kind": "binary",
     "repo": "projectdiscovery/nuclei",
     "asset": {"windows": r"(?i)nuclei_.*windows_amd64\.zip",
               "linux": r"(?i)nuclei_.*linux_amd64\.zip"},
     "exe": "nuclei", "version": ["nuclei", "-version"], "config_hint": "templates",
     "necess": set(), "compl": {"site"}},
    {"key": "ffuf", "label": "ffuf (descoberta de conteúdo)", "kind": "binary",
     "repo": "ffuf/ffuf",
     "asset": {"windows": r"(?i)ffuf_.*windows_amd64\.zip",
               "linux": r"(?i)ffuf_.*linux_amd64\.tar\.gz"},
     "exe": "ffuf", "version": ["ffuf", "-V"],
     "necess": set(), "compl": {"site"}},
    {"key": "sqlmap", "label": "sqlmap (injeção SQL)", "kind": "git",
     "git": "https://github.com/sqlmapproject/sqlmap.git", "entry": "sqlmap.py",
     "version": ["sqlmap", "--version"], "necess": set(), "compl": {"site"}},
    {"key": "sslyze", "label": "SSLyze (TLS aprofundado)", "kind": "pip",
     "pip": "sslyze", "version": ["sslyze", "--help"],
     "necess": set(), "compl": {"site", "server"}},
    {"key": "wafw00f", "label": "wafw00f (detecção de WAF)", "kind": "pip",
     "pip": "wafw00f", "version": ["wafw00f", "-h"],
     "necess": set(), "compl": {"site"}},
    {"key": "zap", "label": "OWASP ZAP (DAST)", "kind": "docker",
     "version": ["docker", "--version"], "config_hint": "docker",
     "necess": set(), "compl": {"site"}},
    # servidor
    {"key": "nmap", "label": "nmap (portas/serviços)", "kind": "system",
     "version": ["nmap", "--version"], "necess": {"server"}, "compl": {"site"}},
]

_BY_KEY = {t["key"]: t for t in TOOLS}


def role(tool: dict, kinds: set) -> str:
    """necessaria | complementar | nao_aplicavel para o perfil (alvos escolhidos)."""
    if tool["necess"] & kinds:
        return "necessaria"
    if tool["compl"] & kinds:
        return "complementar"
    return "nao_aplicavel"


# --------------------------------------------------------------------------- #
# diagnóstico
# --------------------------------------------------------------------------- #
def _diagnose_one(tool: dict) -> dict:
    kind = tool["kind"]
    if kind == "builtin":
        return {"state": "funcional", "green": True, "version": "embutido",
                "detail": "sempre disponível (stdlib)"}

    exe = tool.get("exe") or tool["key"]
    found = _which(exe)
    vcmd = tool.get("version")

    if kind == "docker":
        d = _which("docker")
        if not d:
            return {"state": "nao_instalada", "green": False, "version": "",
                    "detail": "ZAP roda via Docker; Docker não encontrado"}
        rc, out = _run(["docker", "--version"], 12)
        if rc == 0:
            return {"state": "precisa_config", "green": False,
                    "version": out.strip()[:60],
                    "detail": "Docker ok; a imagem do ZAP é baixada na 1ª execução"}
        return {"state": "precisa_config", "green": False, "version": "",
                "detail": "Docker presente mas não respondeu"}

    if not found:
        # instalada mas fora do PATH do executor?
        alt = _find_offpath(tool)
        if alt:
            return {"state": "instalada_nao_localizada", "green": False,
                    "version": "", "detail": f"encontrada em {alt} (fora do PATH)"}
        return {"state": "nao_instalada", "green": False, "version": "",
                "detail": "não encontrada"}

    # encontrada: valida versão (execução mínima = verde). Timeout curto: se a
    # ferramenta não responde rápido a --version, tratamos como precisa_config
    # em vez de travar a interface.
    if vcmd:
        rc, out = _run(vcmd, 12)
        if rc == 124:  # timeout na versão
            return {"state": "precisa_config", "green": False, "version": "",
                    "detail": f"encontrada ({found}) mas --version não respondeu a tempo"}
        if rc == 0:
            ver = _extract_version(out)
            return {"state": "funcional", "green": True, "version": ver,
                    "detail": f"{found}"}
        return {"state": "incompativel", "green": False, "version": "",
                "detail": f"encontrada ({found}) mas não executou: {out.strip()[:80]}"}
    return {"state": "funcional", "green": True, "version": "", "detail": found}


def _find_offpath(tool: dict) -> str:
    """Procura a ferramenta em locais comuns fora do PATH (nao_localizada)."""
    exe = tool.get("exe") or tool["key"]
    names = [exe, exe + ".exe"]
    cands = [config.BIN_DIR]
    if os.name == "nt":
        for p in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                  os.environ.get("LOCALAPPDATA")):
            if p:
                cands.append(Path(p))
    else:
        cands += [Path("/usr/local/bin"), Path("/usr/bin"), Path("/snap/bin"),
                  Path.home() / ".local" / "bin"]
    for base in cands:
        for n in names:
            hit = base / n
            try:
                if hit.exists():
                    return str(hit)
            except OSError:
                pass
    return ""


_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _extract_version(text: str) -> str:
    m = _VER_RE.search(text or "")
    return m.group(1) if m else ""   # sem número de versão -> vazio (não "Usage:…")


def _item(t: dict, kinds: set, d: dict) -> dict:
    return {"key": t["key"], "label": t["label"], "kind": t["kind"],
            "role": role(t, kinds), **d,
            "installable": t["kind"] in ("pip", "binary", "git"),
            "intervention": t["kind"] in ("system", "docker")}


def diagnose(kinds: set, options: dict | None = None, cb=None) -> dict:
    """Diagnostica em PARALELO. Se `cb` for dado, chama cb(item) à medida que
    cada ferramenta resolve (feedback progressivo na interface)."""
    options = options or {}
    from concurrent.futures import ThreadPoolExecutor, as_completed
    items = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_diagnose_one, t): t for t in TOOLS}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                d = fut.result()
            except Exception as e:  # noqa: BLE001
                d = {"state": "incompativel", "green": False, "version": "",
                     "detail": f"erro no diagnóstico: {e}"}
            it = _item(t, kinds, d)
            items.append(it)
            if cb:
                try:
                    cb(it)
                except Exception:  # noqa: BLE001
                    pass
    # ordem estável (a de TOOLS) p/ exibição
    order = {t["key"]: i for i, t in enumerate(TOOLS)}
    items.sort(key=lambda x: order.get(x["key"], 99))
    # capacidades
    green = {i["key"] for i in items if i["green"]}
    ess_missing = [i for i in items if i["role"] == "necessaria" and not i["green"]]
    return {"os": os_info(), "tools": items,
            "resumo": {"funcionais": sorted(green),
                       "essenciais_faltando": [i["key"] for i in ess_missing]}}


# --------------------------------------------------------------------------- #
# instalação
# --------------------------------------------------------------------------- #
def _emit(cb, **ev):
    if cb:
        try:
            cb(ev)
        except Exception:  # noqa: BLE001
            pass


def _pip_install(pkg: str, cb) -> tuple[bool, str]:
    _emit(cb, msg=f"instalando {pkg} via pip…")
    rc, out = _run([sys.executable, "-m", "pip", "install", "--upgrade", pkg], 900)
    if rc == 0:
        return True, "instalado via pip"
    return False, f"pip falhou: {out.strip()[-200:]}"


def _github_asset_url(repo: str, pattern: str) -> tuple[str, str]:
    """URL do asset da última release que casa com o padrão. (url, nome)."""
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "scannacs-prep",
                                               "Accept": "application/vnd.github+json"})
    import json
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    rx = re.compile(pattern)
    for a in data.get("assets", []):
        if rx.search(a.get("name", "")):
            return a["browser_download_url"], a["name"]
    raise RuntimeError(f"nenhum asset casou '{pattern}' na última release de {repo}")


def _download(url: str, dest: Path, cb) -> None:
    _emit(cb, msg=f"baixando {url.split('/')[-1]}…")
    req = urllib.request.Request(url, headers={"User-Agent": "scannacs-prep"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _extract_exe(archive: Path, exe: str, outdir: Path) -> Path:
    """Extrai o executável do zip/tar para outdir. Devolve o caminho final."""
    target_names = {exe, exe + ".exe"}
    outdir.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip" or zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            member = _pick_member(z.namelist(), target_names)
            with z.open(member) as src:
                data = src.read()
    else:
        with tarfile.open(archive) as tf:
            member = _pick_member(tf.getnames(), target_names)
            data = tf.extractfile(member).read()
    final = outdir / (exe + (".exe" if os.name == "nt" else ""))
    final.write_bytes(data)
    if os.name != "nt":
        final.chmod(0o755)
    return final


def _pick_member(names: list[str], targets: set) -> str:
    for n in names:
        base = n.replace("\\", "/").split("/")[-1]
        if base in targets:
            return n
    # fallback: primeiro que começa com o nome do exe
    for n in names:
        base = n.replace("\\", "/").split("/")[-1].lower()
        if any(base == t.lower() or base.startswith(list(targets)[0].lower()) for t in targets):
            return n
    raise RuntimeError(f"executável {targets} não achado no arquivo")


def _binary_install(tool: dict, cb) -> tuple[bool, str]:
    info = os_info()
    if info["arch"] not in ("amd64",):
        return False, (f"arquitetura {info['arch']} não suportada pelo instalador "
                       "automático (baixe o binário oficial manualmente)")
    pattern = tool["asset"].get(info["os"])
    if not pattern:
        return False, f"sem asset para {info['os']}"
    try:
        url, name = _github_asset_url(tool["repo"], pattern)
    except Exception as e:  # noqa: BLE001
        return False, f"não achei a release oficial: {e}"
    config.BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = config.BIN_DIR / name
    try:
        _download(url, tmp, cb)
        _emit(cb, msg=f"extraindo {name}…")
        final = _extract_exe(tmp, tool["exe"], config.BIN_DIR)
    except Exception as e:  # noqa: BLE001
        return False, f"falha ao baixar/extrair: {e}"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return True, f"binário oficial em {final}"


def _short_path(p: Path) -> str:
    """Caminho 8.3 no Windows (evita bug de acento em .cmd lido pelo cmd.exe)."""
    s = str(p)
    if os.name != "nt":
        return s
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(600)
        n = ctypes.windll.kernel32.GetShortPathNameW(s, buf, 600)
        if n:
            return buf.value
    except Exception:  # noqa: BLE001
        pass
    return s


def _git_install(tool: dict, cb) -> tuple[bool, str]:
    if not _which("git"):
        return False, "git não está instalado (necessário para clonar o sqlmap)"
    dest = config.BIN_DIR / tool["key"]
    if not dest.exists():
        _emit(cb, msg=f"clonando {tool['key']} (oficial)…")
        rc, out = _run(["git", "clone", "--depth", "1", tool["git"], str(dest)], 600)
        if rc != 0:
            return False, f"git clone falhou: {out.strip()[-200:]}"
    else:
        _emit(cb, msg=f"{tool['key']} já clonado; atualizando…")
        _run(["git", "-C", str(dest), "pull", "--ff-only"], 300)
    # wrapper no BIN_DIR
    entry = dest / tool["entry"]
    if os.name == "nt":
        wrapper = config.BIN_DIR / (tool["key"] + ".cmd")
        # caminhos 8.3 p/ o cmd.exe não quebrar em pastas com acento (ex.: Lázaro)
        py = _short_path(Path(sys.executable))
        sp = _short_path(entry)
        wrapper.write_text(f'@echo off\r\n"{py}" "{sp}" %*\r\n', encoding="ascii")
    else:
        wrapper = config.BIN_DIR / tool["key"]
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{entry}" "$@"\n',
                           encoding="utf-8")
        wrapper.chmod(0o755)
    return True, f"clonado + wrapper em {wrapper}"


def prepare(kinds: set, options: dict | None, cb=None, only: list[str] | None = None) -> dict:
    """Instala as ferramentas necessárias/complementares do perfil que dão para
    automatizar. Preserva o que já funciona; instala só o que falta.

    `only`: se informado, restringe às chaves dadas (retry sem reinstalar tudo).
    """
    config.ensure_dirs()
    config.augment_path()
    results = {}
    _emit(cb, msg="verificando o ambiente atual…")
    diag = diagnose(kinds, options)
    for item in diag["tools"]:
        key = item["key"]
        tool = _BY_KEY[key]
        if only and key not in only:
            continue
        if item["role"] == "nao_aplicavel":
            continue
        if item["green"]:
            results[key] = {"ok": True, "skipped": True, "detail": "já funcional"}
            continue
        if tool["kind"] in ("system", "docker"):
            results[key] = {"ok": False, "intervention": True,
                            "detail": _intervention_text(tool)}
            _emit(cb, key=key, done=True, ok=False, intervention=True,
                  detail=results[key]["detail"])
            continue
        _emit(cb, key=key, start=True, label=tool["label"])
        try:
            if tool["kind"] == "pip":
                ok, detail = _pip_install(tool["pip"], cb)
            elif tool["kind"] == "binary":
                ok, detail = _binary_install(tool, cb)
            elif tool["kind"] == "git":
                ok, detail = _git_install(tool, cb)
            else:
                ok, detail = False, "tipo de instalação desconhecido"
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"erro inesperado: {e}"
        # revalida (verde = executa)
        config.augment_path()
        post = _diagnose_one(tool)
        ok = ok and post["green"]
        results[key] = {"ok": ok, "detail": detail, "version": post.get("version", ""),
                        "state": post["state"]}
        _emit(cb, key=key, done=True, ok=ok, detail=detail,
              version=post.get("version", ""))
    return {"results": results, "diag": diagnose(kinds, options)}


def _intervention_text(tool: dict) -> str:
    info = os_info()
    if tool["key"] == "nmap":
        if info["os"] == "windows":
            return ("nmap precisa de instalador com admin. Opção: `winget install "
                    "Insecure.Nmap` (ou baixe de https://nmap.org/download). Depois "
                    "clique em 'Tentar de novo'.")
        if info["distro"] in ("kali",):
            return "nmap já costuma vir no Kali; se faltar: `sudo apt install nmap`."
        return ("nmap precisa de sudo: `sudo apt install nmap` (Debian/Ubuntu) ou o "
                "gerenciador da sua distro. Depois clique em 'Tentar de novo'.")
    if tool["key"] == "zap":
        return ("ZAP roda via Docker. Instale/abra o Docker Desktop (Windows) ou o "
                "docker engine (Linux). A imagem do ZAP é baixada na 1ª execução. "
                "Depois clique em 'Tentar de novo'.")
    return "requer intervenção manual do sistema."
