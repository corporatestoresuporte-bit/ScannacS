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

# --- abuso de lógica/API (a classe do "hack por interceptação") -------------
# (severidade, título, regex, impacto, correção)
_APP_LOGIC = [
    (Severity.HIGH, "mass assignment (corpo da requisição espalhado no banco)",
     re.compile(r"\.(insert|update|upsert)\s*\([^)]*\.\.\.\s*(req\.body|request\.body|body|payload|input|data)\b", re.I),
     "Espalhar o corpo da requisição direto no banco deixa o cliente gravar "
     "campos proibidos (role, 2fa, saldo).",
     "Aceitar só uma allowlist de campos; nunca ...body no insert/update."),
    (Severity.HIGH, "papel/permissão vindo do corpo da requisição",
     re.compile(r"(?i)\b(role|is_admin|isadmin|role_id|papel|perfil)\b\s*[:=]\s*"
                r"(req\.body|request\.body|body|payload|input)\b|"
                r"body\.(role|is_admin|isadmin|role_id)"),
     "Cliente define o próprio papel = escalada para admin.",
     "Definir papel/permissão no servidor, nunca a partir do input."),
    (Severity.MEDIUM, "preço/total confiando no cliente",
     re.compile(r"(?i)\b(price|total|amount|valor|preco|subtotal)\b\s*[:=]\s*"
                r"(req\.body|request\.body|body|payload)\b|"
                r"body\.(price|total|amount|valor|preco)"),
     "Valor vindo do front pode ser adulterado (comprar por R$0).",
     "Recalcular preço/total no servidor a partir do catálogo."),
    (Severity.HIGH, "dado sensível retornado (senha/token/2fa)",
     re.compile(r"(?i)(select|returning|return|res\.json|reply\.send|res\.send)"
                r"[^\n]*(password|senha|password_hash|access_token|refresh_token|"
                r"totp|two_factor|2fa|secret)"),
     "Retornar hash de senha/token/2fa expõe credenciais ao cliente.",
     "Nunca retornar esses campos; selecionar só o necessário."),
    (Severity.LOW, "consulta sem filtro (select *) — risco de IDOR/vazamento",
     re.compile(r"\.select\(\s*['\"]\*['\"]\s*\)|\bselect\s+\*\s+from\b", re.I),
     "select * pode vazar colunas sensíveis e facilita IDOR.",
     "Selecionar colunas específicas e filtrar por dono (auth.uid())."),
]

# detecção de rota e de checagem de auth (heurística)
_ROUTE_DEF = re.compile(
    r"\b(app|router|fastify|server)\.(get|post|put|patch|delete)\s*\(|"
    r"export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|"
    r"export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=", re.I)
_AUTH_HINT = re.compile(
    r"(?i)getuser|getsession|requireauth|require_auth|verify(?:token|jwt)|"
    r"isauthenticated|ensureauth|@useguards|authguard|auth\.uid|"
    r"authorization|bearer|supabase\.auth|req\.user|request\.user")
_RATELIMIT = re.compile(
    r"(?i)rate.?limit|ratelimit|express-rate-limit|@upstash/ratelimit|"
    r"\bthrottle\b|slow.?down|p-?limit")
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

    project_has_routes = False
    project_has_ratelimit = False

    for p in _iter_files(root):
        rel = str(p)
        frontend = _is_frontend(rel)
        lines = _read(p)
        text = "\n".join(lines)
        file_has_route = bool(_ROUTE_DEF.search(text))
        file_has_auth = bool(_AUTH_HINT.search(text))
        if file_has_route:
            project_has_routes = True
        if _RATELIMIT.search(text):
            project_has_ratelimit = True

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
            # abuso de lógica/API (a classe do "hack por interceptação")
            for sev, nome, pat, impacto, fix in _APP_LOGIC:
                if pat.search(line):
                    findings.append(_f(target, nome, sev, rel, i, impacto, fix))
                    break

        # rota definida sem NENHUMA checagem de auth no arquivo
        if file_has_route and not file_has_auth:
            m = _ROUTE_DEF.search(text)
            ln = text[:m.start()].count("\n") + 1 if m else 1
            findings.append(_f(
                target, "Endpoint sem autenticação aparente",
                Severity.MEDIUM, rel, ln,
                "Rota sem checagem de login/permissão pode expor dados ou ações "
                "a qualquer um (endpoint aberto).",
                "Exigir sessão/token e checar permissão antes de responder."))

    # rate-limit no projeto inteiro
    if project_has_routes and not project_has_ratelimit:
        findings.append(_f(
            target, "Sem rate-limit aparente no projeto",
            Severity.LOW, str(root), 0,
            "Sem limite de requisições, o alvo fica exposto a brute-force de "
            "login e abuso de API (foi assim que invadiram o caso do vídeo).",
            "Adicionar rate-limit (ex.: por IP/rota) nas rotas sensíveis, "
            "especialmente login."))

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
