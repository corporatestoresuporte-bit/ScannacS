"""Análise de código local (SAST-leve) — o risco real de SPA + Supabase.

Roda contra uma PASTA local (repo/bundle), SEM rede, sem ação ofensiva.
Procura o que os scanners de fora não pegam:
  - segredo exposto (chave privada, service_role, API keys, .env versionado);
  - uso de service_role/admin no lado do cliente (frontend);
  - RLS do Supabase ausente ou frouxo (using (true) / to anon);
  - sinks de XSS (dangerouslySetInnerHTML, innerHTML=, eval).

Cada achado nasce como SUSPEITA, com arquivo:linha (evidência), para o
validador confirmar. Nada aqui executa o código analisado.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .findings import Finding, Severity, Status

# pastas ignoradas na varredura
_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__",
              ".next", "coverage", "playwright-report"}
_TEXT_EXT = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".env",
             ".sql", ".html", ".vue", ".svelte", ".py", ".txt", ".yml",
             ".yaml", ".toml", ".sh", ".template", ".local"}
_MAX_BYTES = 2_000_000

# --- padrões de segredo -----------------------------------------------------
_SECRETS = [
    ("chave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe live", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("GitHub token", re.compile(r"\bghp_[0-9A-Za-z]{30,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("segredo atribuído",
     re.compile(r"(?i)(secret|password|passwd|senha|api[_-]?key|access[_-]?token)"
                r"\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
_SERVICE_ROLE = re.compile(r"(?i)service_role|SUPABASE_SERVICE_ROLE")
_XSS_SINKS = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("innerHTML =", re.compile(r"\.innerHTML\s*=")),
    ("eval(", re.compile(r"\beval\s*\(")),
]
# frontend = onde chave secreta NÃO pode aparecer
_FRONTEND_HINTS = ("/src/", "\\src\\", "/dist/", "\\dist\\", "/public/", "\\public\\")


def _is_frontend(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    return any(h.replace("\\", "/") in p for h in _FRONTEND_HINTS)


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in _TEXT_EXT and p.name != ".env":
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _read(p: Path) -> list[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _f(target, title, sev, file, line, impact, remediation):
    return Finding(target=target, title=title, status=Status.SUSPECTED,
                   severity=sev, impact=impact, remediation=remediation,
                   engine="review-code",
                   evidence_ids=[f"{file}:{line}"])


def env_committed(root: Path, target: str) -> list[Finding]:
    """.env / .env.local versionados no git = segredo commitado."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files"],
                             capture_output=True, text=True, timeout=20)
    except Exception:  # noqa: BLE001
        return []
    out_l = (out.stdout or "").splitlines()
    hits = [f for f in out_l if re.search(r"(^|/)\.env($|\.)", f)
            and not f.endswith((".example", ".template", ".sample"))]
    return [_f(target, f"Arquivo de segredo versionado no git: {f}",
               Severity.HIGH, f, 0,
               "Segredos no repositório vazam para quem clona/vê o código.",
               "Remover do git (git rm --cached), rotacionar as chaves, "
               "e por no .gitignore.") for f in hits]


def review(root: Path, target: str = "") -> list[Finding]:
    target = target or root.name
    findings: list[Finding] = []
    findings += env_committed(root, target)

    for p in _iter_files(root):
        rel = str(p)
        frontend = _is_frontend(rel)
        lines = _read(p)
        for i, line in enumerate(lines, 1):
            # service_role no frontend = crítico
            if frontend and _SERVICE_ROLE.search(line):
                findings.append(_f(
                    target, "Chave/serviço admin do Supabase no lado do cliente",
                    Severity.CRITICAL, rel, i,
                    "service_role ignora RLS: exposto no frontend = acesso total "
                    "ao banco por qualquer visitante.",
                    "Nunca usar service_role no frontend; só a anon key. "
                    "Mover para backend e rotacionar."))
            # segredos
            for nome, pat in _SECRETS:
                if pat.search(line):
                    sev = Severity.CRITICAL if frontend else Severity.HIGH
                    findings.append(_f(
                        target, f"Possível segredo no código: {nome}",
                        sev, rel, i,
                        "Segredo exposto pode ser usado por terceiros.",
                        "Tirar do código, usar variável de ambiente/secret "
                        "manager e rotacionar."))
                    break
            # XSS sinks (só frontend)
            if frontend:
                for nome, pat in _XSS_SINKS:
                    if pat.search(line):
                        findings.append(_f(
                            target, f"Sink de XSS: {nome}", Severity.MEDIUM, rel, i,
                            "Inserir conteúdo não-sanitizado permite XSS.",
                            "Sanitizar/escapar; evitar innerHTML/eval."))
                        break

    findings += _review_supabase_rls(root, target)
    return findings


def _review_supabase_rls(root: Path, target: str) -> list[Finding]:
    """Migrations do Supabase sem RLS ou com política frouxa."""
    out: list[Finding] = []
    sup = root / "supabase"
    search_dirs = [sup] if sup.exists() else [root]
    sql_files = []
    for d in search_dirs:
        sql_files += [p for p in d.rglob("*.sql")
                      if not any(part in _SKIP_DIRS for part in p.parts)]
    for p in sql_files:
        lines = _read(p)
        text = "\n".join(lines).lower()
        rel = str(p)
        creates = [i for i, ln in enumerate(lines, 1)
                   if re.search(r"create table", ln, re.I)]
        if creates and "enable row level security" not in text:
            out.append(_f(
                target, f"Tabela(s) criada(s) sem RLS habilitado ({p.name})",
                Severity.HIGH, rel, creates[0],
                "Sem RLS, a anon key lê/escreve dados de todos os usuários.",
                "ALTER TABLE ... ENABLE ROW LEVEL SECURITY e criar policies."))
        for i, ln in enumerate(lines, 1):
            if re.search(r"using\s*\(\s*true\s*\)", ln, re.I):
                out.append(_f(
                    target, f"Política RLS permissiva (using (true)) ({p.name})",
                    Severity.HIGH, rel, i,
                    "using (true) libera a linha para qualquer um.",
                    "Restringir por auth.uid() / tenant."))
    return out
