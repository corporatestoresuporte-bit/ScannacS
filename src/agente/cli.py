"""Interface de linha de comando do agente.

Uso:  python -m agente <comando>   (ou `agente <comando>` após pip install -e .)

Grupos: version | doctor | ui | session | prompts | scope | audit | exec |
        evidence | finding | fixtures | hook | integracoes
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from . import __version__, config
from . import audit as audit_mod
from . import context as ctx
from . import scope as scope_mod
from .evidence import CollectionStatus, Evidence, preserve_artifact
from .findings import Finding, can_confirm
from .store import Session
from .verdict import EvidenceTier


try:  # saída UTF-8 mesmo em console Windows cp1252 (evita crash em glyphs)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def _p(*a: object) -> None:
    print(*a)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# version / doctor
# --------------------------------------------------------------------------- #
def cmd_version(_a) -> int:
    _p(f"agente-vulnerabilidades {__version__}")
    return 0


def cmd_doctor(_a) -> int:
    _p(f"Python              : {sys.version.split()[0]}")
    _p(f"Modo                : {'checkout (dev)' if config._IS_CHECKOUT else 'instalado'}")
    _p(f"Dados (graváveis)   : {config.DATA_HOME}")
    _p(f"Recursos (pacote)   : {config.PKG_DATA}")
    _p(f"Wordlist encontrada : {config.WORDLIST.exists()}")
    claude = shutil.which("claude")
    _p(f"Claude Code         : {claude or 'NÃO encontrado no PATH'}")
    if claude:
        try:
            v = subprocess.run([claude, "--version"], capture_output=True,
                               text=True, timeout=20)
            _p(f"  versão            : {v.stdout.strip() or v.stderr.strip()}")
        except Exception as e:  # noqa: BLE001
            _p(f"  versão            : (falha ao consultar: {e})")
    _p(f"config/scope.toml   : {'presente' if config.SCOPE_FILE.exists() else 'AUSENTE (scope init)'}")
    _p(f".env                : {'presente' if config.ENV_FILE.exists() else 'ausente (copie .env.example)'}")
    masters = ctx.list_masters()
    _p(f"prompts master      : {len(masters)}")
    sess = Session.active()
    _p(f"sessão ativa        : {sess.id if sess else 'nenhuma'}")
    claude_md = config.ROOT / "CLAUDE.md"
    settings = config.ROOT / ".claude" / "settings.json"
    _p(f"CLAUDE.md           : {'presente' if claude_md.exists() else 'ausente'}")
    _p(f".claude/settings.json: {'presente' if settings.exists() else 'ausente'}")
    from . import engines as eng
    tools = eng.detect_tools()
    on = [t for t, ok in tools.items() if ok]
    _p(f"motores embutidos   : cabecalhos, tls, http-fingerprint (sempre)")
    _p(f"ferramentas externas: {len(on)}/{len(tools)} instaladas "
       f"({', '.join(on) or 'nenhuma'})")
    gate = audit_mod.preflight()
    _p(f"auditoria           : {'LIBERADA' if gate.allowed else 'BLOQUEADA'}")
    return 0


# --------------------------------------------------------------------------- #
# ui — abre a interface do Claude Code no projeto
# --------------------------------------------------------------------------- #
def cmd_ui(a) -> int:
    claude = shutil.which("claude")
    if not claude:
        _p("Claude Code não encontrado no PATH.")
        _p("Próxima ação: instale/abra o Claude Code e rode `claude --version`.")
        return 1
    prompt = a.print or "/scan"
    if a.no_launch:
        _p(f"[dry-run] abriria: claude -n \"AgenteAuditoria\" \"{prompt}\"  "
           f"(cwd={config.ROOT})")
        return 0
    from pathlib import Path as _P
    wsdir = _P.cwd()
    if not (wsdir / ".claude").exists():   # 1ª utilização: prepara o workspace
        try:
            materialize_workspace(wsdir)
        except Exception:  # noqa: BLE001
            pass
    _p("Abrindo Claude Code no projeto… (Ctrl+C encerra)")
    try:
        return subprocess.call([claude, "-n", "AgenteAuditoria", prompt],
                               cwd=str(wsdir))
    except KeyboardInterrupt:
        _p("\nInterrompido.")
        return 130


# --------------------------------------------------------------------------- #
# session
# --------------------------------------------------------------------------- #
def cmd_session_new(_a) -> int:
    scope = scope_mod.load_scope()
    s = Session.create(
        environment=(scope.environment if scope else ""),
        scope_hash=scope_mod.scope_hash(scope),
        prompts_hash=ctx.manifest_hash(),
    )
    _p(f"Sessão criada e ativa: {s.id}")
    return 0


def cmd_session_list(_a) -> int:
    ids = Session.list_ids()
    if not ids:
        _p("Nenhuma sessão.")
        return 0
    active = Session.active()
    for sid in ids:
        _p(f"  {'* ' if active and active.id == sid else '  '}{sid}")
    return 0


def cmd_session_show(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    m = s.meta()
    _p(f"sessão   : {s.id}")
    _p(f"status   : {m.get('status')}")
    _p(f"ambiente : {m.get('environment') or '-'}")
    _p(f"tarefas  : {len(s.tasks())} | achados: {len(s.findings())} | "
       f"evidências: {len(s.evidence())} | suspeitas: {len(s.suspicions())}")
    # detecta mudança de prompts/escopo desde a criação
    cur_prompts = ctx.manifest_hash()
    if m.get("prompts_hash") and m["prompts_hash"] != cur_prompts:
        _p("AVISO: os prompts master mudaram desde o início da sessão "
           "(reaplicar contexto).")
    cur_scope = scope_mod.scope_hash(scope_mod.load_scope())
    if m.get("scope_hash") and m["scope_hash"] != cur_scope:
        _p("AVISO: o escopo mudou desde o início da sessão (revalidar).")
    return 0


def cmd_session_resume(a) -> int:
    s = Session(a.id)
    if not s.dir.exists():
        _p(f"Sessão não encontrada: {a.id}")
        return 1
    s.set_active()
    _p(f"Sessão ativa: {s.id}")
    return cmd_session_show(a)


# --------------------------------------------------------------------------- #
# prompts
# --------------------------------------------------------------------------- #
def cmd_prompts_list(_a) -> int:
    masters = ctx.list_masters()
    if not masters:
        _p("Nenhum prompt master. Importe com `prompts import`.")
        return 0
    for m in masters:
        agents = ", ".join(m.agents) or "todos"
        _p(f"  [{m.order:>3}] {m.path.name} — {m.title} "
           f"(v{m.meta.get('version','1')}) | agentes: {agents}")
    _p(f"manifesto: {ctx.manifest_hash(masters)}")
    return 0


def cmd_prompts_import(a) -> int:
    if a.source == "-":
        text = sys.stdin.read()
    else:
        text = config.ROOT.joinpath(a.source).read_text(encoding="utf-8") \
            if not a.source.startswith(("/", "\\")) and ":" not in a.source \
            else open(a.source, encoding="utf-8").read()
    path = ctx.import_master(text, a.slug, title=a.title, order=a.order,
                             purpose=a.purpose, agents=a.agents, version=a.version)
    _p(f"Importado: {path.name}")
    return 0


def cmd_prompts_context(a) -> int:
    _p(ctx.assemble_context(only_for_agent=a.agent))
    return 0


def cmd_prompts_import_inbox(_a) -> int:
    imported = ctx.import_inbox()
    if not imported:
        _p(f"Nada em prompts/inbox/ para importar. "
           f"Coloque um .md/.txt em {ctx.INBOX_DIR} e rode de novo.")
        return 0
    for p in imported:
        _p(f"Importado: {p.name}")
    return 0


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #
def cmd_scope_init(_a) -> int:
    if config.SCOPE_FILE.exists():
        _p(f"Já existe: {config.SCOPE_FILE}")
        return 0
    if not config.SCOPE_EXAMPLE.exists():
        _p("Modelo ausente.")
        return 1
    shutil.copyfile(config.SCOPE_EXAMPLE, config.SCOPE_FILE)
    _p(f"Criado: {config.SCOPE_FILE}")
    return 0


def cmd_scope_show(_a) -> int:
    s = scope_mod.load_scope()
    if not s:
        _p("Escopo não definido.")
        return 1
    _p(f"authorized: {s.authorized} | by: {s.authorized_by or '-'} | "
       f"at: {s.authorized_at or '-'}")
    _p(f"environment: {s.environment or '-'} | alvos: {len(s.targets)}")
    for t in s.targets:
        _p(f"  - [{t.type}] {t.name or '(sem nome)'} -> {t.value} | "
           f"testes: {', '.join(t.allowed_tests) or '-'}")
    return 0


def cmd_scope_validate(_a) -> int:
    gate = audit_mod.preflight()
    if gate.allowed:
        _p("Portão: LIBERADO.")
        return 0
    _p("Portão: BLOQUEADO. Motivos:")
    for r in gate.reasons:
        _p(f"  - {r}")
    return 1


def _load_or_new_scope() -> scope_mod.Scope:
    return scope_mod.load_scope() or scope_mod.Scope()


def cmd_scope_set_env(a) -> int:
    s = _load_or_new_scope()
    s.environment = a.environment
    scope_mod.save_scope(s)
    _p(f"environment = {a.environment}")
    return 0


def cmd_scope_add_target(a) -> int:
    s = _load_or_new_scope()
    t = scope_mod.Target(
        name=a.name, type=a.type, value=a.value,
        allowed_tests=[x.strip() for x in (a.tests or "").split(",") if x.strip()],
        limits=a.limits or "",
        exclusions=[x.strip() for x in (a.exclusions or "").split(",") if x.strip()],
        notes=a.notes or "",
    )
    problems = t.problems()
    if problems:
        _p("Alvo recusado:")
        for p in problems:
            _p(f"  - {p}")
        return 1
    s.targets.append(t)
    scope_mod.save_scope(s)
    _p(f"Alvo adicionado: [{t.type}] {t.value}")
    return 0


def cmd_scope_verify(a) -> int:
    """Prova de posse do alvo (token em arquivo ou DNS TXT). Uma vez só."""
    s = scope_mod.load_scope()
    if not s:
        _p("Escopo ausente.")
        return 1
    host = scope_mod._host_of(a.target)
    tgt = next((t for t in s.targets if scope_mod._host_of(t.value) == host), None)
    if tgt is None:
        _p(f"Alvo não está no escopo: {a.target}")
        return 1
    token = scope_mod.expected_token(a.target)
    if tgt.owner_verified:
        _p(f"Posse JÁ confirmada para {host} (em {tgt.owner_verified_at}).")
        return 0
    ok, method, detail = scope_mod.verify_ownership(a.target)
    if ok:
        tgt.owner_verified = True
        tgt.owner_verified_at = _now()
        scope_mod.save_scope(s)
        _p(f"POSSE CONFIRMADA para {host} (método: {method}, {detail}).")
        _p("Não pedirei prova de novo para este alvo.")
        return 0
    _p(f"Posse ainda NÃO comprovada para {host}. {detail}")
    _p("Publique o token (uma das opções) e rode 'scope verify' de novo:")
    _p(f"  Opção A (arquivo): https://{host}/rz-audit-verify.txt")
    _p(f"    conteúdo exato:  {token}")
    _p(f"  Opção B (DNS TXT em {host}): valor {token}")
    return 2


def cmd_scope_authorize(a) -> int:
    """DISPARAR AUDITORIA — autorização única (não duplica confirmação)."""
    s = scope_mod.load_scope()
    if not s:
        _p("Escopo ausente — nada a autorizar.")
        return 1
    gate = scope_mod.evaluate_gate(scope_mod.Scope(
        authorized=True, authorized_by=a.by, authorized_at=_now(),
        environment=s.environment, targets=s.targets))
    if not gate.allowed:
        _p("Não é possível autorizar — escopo inválido:")
        for r in gate.reasons:
            _p(f"  - {r}")
        return 1
    s.authorized = True
    s.authorized_by = a.by
    s.authorized_at = _now()
    scope_mod.save_scope(s)
    _p(f"AUTORIZADO por {a.by} em {s.authorized_at}.")
    _p("Esta é a confirmação do escopo (DISPARAR AUDITORIA). "
       "`audit run` não pedirá confirmação de novo.")
    return 0


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def cmd_audit_plan(_a) -> int:
    for line in audit_mod.plan():
        _p(line)
    return 0


def cmd_audit_run(a) -> int:
    scope = scope_mod.load_scope()
    confirmed = bool(a.confirm) or bool(scope and scope.authorized)
    rps, maxrun = (50.0, 100000) if getattr(a, "aggressive", False) else (5.0, 500)
    if getattr(a, "aggressive", False):
        _p("Modo AGRESSIVO: sem teto prático de rate (dentro do escopo).")
    try:
        result = audit_mod.run(scope=scope, confirmed=confirmed,
                               rps=rps, max_per_run=maxrun)
    except audit_mod.AuditBlocked as exc:
        _p("Auditoria BLOQUEADA:")
        for r in exc.reasons:
            _p(f"  - {r}")
        return 2
    for note in result.notes:
        _p(note)
    _p(f"Executada: {result.executed} | achados: {len(result.findings)}")
    return 0


def cmd_audit_status(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    buckets: dict[str, int] = {}
    for t in s.tasks():
        buckets[t.get("status", "?")] = buckets.get(t.get("status", "?"), 0) + 1
    _p(f"Tarefas por estado: {buckets or '(nenhuma)'}")
    fnd = s.findings()
    by_status: dict[str, int] = {}
    for f in fnd:
        by_status[f.get("status", "?")] = by_status.get(f.get("status", "?"), 0) + 1
    _p(f"Achados por estado: {by_status or '(nenhum)'}")
    return 0


# --------------------------------------------------------------------------- #
# exec — executor controlado com captura de evidência
# --------------------------------------------------------------------------- #
def cmd_exec(a) -> int:
    parts = list(a.command)
    if parts and parts[0] == "--":
        parts = parts[1:]
    command = " ".join(parts).strip()
    if not command:
        _p("Nada a executar (use: exec --target X -- <comando>).")
        return 1
    scope = scope_mod.load_scope()
    from .executor import decide, check_and_consume
    dec = decide(command, scope)
    if not dec.allow:
        _p(f"BLOQUEADO pelo executor: {dec.reason}")
        return 2

    sess = Session.active()
    if sess is None:
        _p("Sem sessão ativa — crie com `session new`.")
        return 1

    # rate-limit por alvo
    if dec.targets:
        limits = sess.limits()
        for h in dec.targets:
            ok, reason, limits = check_and_consume(limits, h, a.rps, a.max_per_run)
            if not ok:
                sess.save_limits(limits)
                _p(f"BLOQUEADO: {reason}")
                return 2
        sess.save_limits(limits)

    status = CollectionStatus.OK
    try:
        proc = subprocess.run(command, shell=True, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=a.timeout)
        raw = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
        rc = proc.returncode
        if rc != 0:
            status = CollectionStatus.ERROR
    except subprocess.TimeoutExpired:
        raw, rc, status = "(timeout)", None, CollectionStatus.TIMEOUT
    except Exception as e:  # noqa: BLE001
        raw, rc, status = f"(erro: {e})", None, CollectionStatus.ERROR

    ev = Evidence(
        target=a.target, tool=(a.tool or command.split()[0]),
        params=command, source=a.target,
        result_summary=(raw[:200].replace("\n", " ") if raw else ""),
        status=status, tier=EvidenceTier.TOOL_OBSERVED, exit_code=rc,
    )
    stored = sess.add_evidence(ev.to_dict())
    ev.id = stored["id"]
    path, digest = preserve_artifact(sess.artifacts, ev.id, raw or "")
    # atualiza a evidência com o artefato
    evs = sess.evidence()
    for e in evs:
        if e.get("id") == ev.id:
            e["artifact_path"], e["artifact_sha256"] = path, digest
    from .store import write_json
    write_json(sess.dir / "evidence.json", evs)

    _p(f"Evidência {ev.id} | status={status.value} | exit={rc}")
    _p(f"Artefato: {path}")
    return 0 if status == CollectionStatus.OK else 3


# --------------------------------------------------------------------------- #
# evidence / finding
# --------------------------------------------------------------------------- #
def cmd_evidence_list(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    for e in s.evidence():
        _p(f"  {e.get('id')} | {e.get('tool')} -> {e.get('target')} | "
           f"{e.get('status')} | {e.get('tier')} | {e.get('artifact_path','')}")
    return 0


def cmd_finding_list(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    for f in s.findings():
        rev = "revisado" if (f.get("validation") or {}).get("validated_by") else "nao-revisado"
        _p(f"  {f.get('id')} | {f.get('status')} | {rev} | {f.get('severity')} | "
           f"{f.get('title')}")
    return 0


def cmd_finding_set(a) -> int:
    """Persiste a decisão do validador num achado (rastreável)."""
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    alts = [a.alt] if a.alt else []
    ok, msg = s.update_finding(a.id, a.status, a.by, a.reason, alts, a.type)
    _p(msg)
    return 0 if ok else 2


def cmd_reconcile(_a) -> int:
    """Reconciliação por ID (bruto/únicos/duplicados/estado/revisados)."""
    from . import reconcile as rec
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    r = rec.reconcile(s.findings())
    _p(f"Reconciliação da sessão {s.id}:")
    _p(f"  brutos: {r['bruto']} | únicos: {r['unicos']} | "
       f"duplicados: {r['duplicados']}")
    _p(f"  por estado: {r['por_estado']}")
    _p(f"  revisados: {r['revisados']} | não-revisados: {r['nao_revisados']}")
    _p(f"  por origem: {r['por_origem']}")
    return 0


def cmd_session_close(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    m = s.close()
    cob = m.get("cobertura", {})
    _p(f"Sessão {s.id} encerrada. Achados por estado: "
       f"{cob.get('achados_por_estado', {})} | não-revisados: "
       f"{cob.get('nao_revisados', 0)}")
    return 0


def cmd_fixtures_run(_a) -> int:
    from .fixtures import run_fixtures
    r = run_fixtures()
    _p(f"Fixtures na sessão {r['session']} (identificadas como TESTE):")
    _p(f"  achado validado — confirmável? {r['validated_confirmable']}")
    if r["validated_missing"]:
        _p(f"    faltando: {r['validated_missing']}")
    _p(f"  alerta descartado — confirmável? {r['dismissed_confirmable']} "
       f"(esperado: False)")
    if r["dismissed_missing"]:
        _p(f"    faltando: {r['dismissed_missing']}")
    return 0


def cmd_tools(_a) -> int:
    from . import engines as eng
    tools = eng.detect_tools()
    _p("Motores embutidos (sempre disponíveis):")
    _p("  - cabecalhos-seguranca, tls, http-fingerprint")
    _p("Ferramentas externas (rodam se instaladas):")
    for t, ok in tools.items():
        _p(f"  [{'x' if ok else ' '}] {t}")
    _p("Ausente = verificação inconclusiva (limitação), não achado.")
    return 0


def cmd_review_code(a) -> int:
    """Análise de código local (segredo/service_role/RLS/XSS)."""
    from pathlib import Path
    from . import codereview
    root = Path(a.path)
    if not root.exists():
        _p(f"Pasta não encontrada: {a.path}")
        return 1
    findings = codereview.review(root, target=a.target or root.name)
    sess = Session.active() or Session.create(environment="code-review")
    if getattr(a, "export", True):
        from . import codeexport
        n = codeexport.export_snippets(sess, findings,
                                       version=sess.meta().get("commit", ""))
        _p(f"Trechos de código exportados (redigidos + hash): {n}")
    for f in findings:
        sess.add_finding(f.to_dict())
    _p(f"Análise de código: {root}  (sessão {sess.id})")
    if not findings:
        _p("Nenhum indício de segredo/RLS/XSS. NÃO prova ausência de falha.")
        return 0
    order = {"critica": 0, "alta": 1, "media": 2, "baixa": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order.get(x.severity.value, 9)):
        ev = f.evidence_ids[0] if f.evidence_ids else ""
        _p(f"  [{f.severity.value.upper()}] {f.title}  ({ev})")
    _p(f"\nTotal: {len(findings)} suspeita(s) de análise estática — "
       "validar antes de confirmar.")
    return 0


def cmd_sast(a) -> int:
    """SAST real via Semgrep (roda se instalado)."""
    from pathlib import Path
    from . import sast
    root = Path(a.path)
    if not root.exists():
        _p(f"Pasta não encontrada: {a.path}")
        return 1
    sess = Session.active() or Session.create(environment="sast")
    findings, limits = sast.run_semgrep(root, config=a.config)
    for f in findings:
        sess.add_finding(f.to_dict())
    _p(f"SAST (Semgrep) em {root}  (sessão {sess.id})")
    for f in findings:
        ev = f.evidence_ids[0] if f.evidence_ids else ""
        _p(f"  [{f.severity.value.upper()}] {f.title}  ({ev})")
    if not findings:
        _p("  Nenhum achado Semgrep (ou ferramenta ausente — ver limitações).")
    for lim in limits:
        _p(f"  (limitação) {lim}")
    return 0


def cmd_zap_import(a) -> int:
    """Importa um relatório JSON do ZAP como achados."""
    from pathlib import Path
    from . import dast
    p = Path(a.json)
    if not p.exists():
        _p(f"Arquivo não encontrado: {a.json}")
        return 1
    findings = dast.parse_zap(p.read_text(encoding="utf-8", errors="replace"),
                              target=a.target)
    sess = Session.active() or Session.create(environment="dast")
    for f in findings:
        sess.add_finding(f.to_dict())
    _p(f"ZAP: {len(findings)} alerta(s) importado(s) (sessão {sess.id})")
    for f in findings:
        _p(f"  [{f.severity.value.upper()}] {f.title}")
    return 0


def cmd_dast(a) -> int:
    """DAST via ZAP baseline (Docker), só contra alvo no escopo + posse."""
    from . import dast, replay
    scope = scope_mod.load_scope()
    ok, reason = replay.authorized_target(a.url, scope)
    if not ok:
        _p(f"BLOQUEADO: {reason}")
        return 2
    sess = Session.active() or Session.create(environment="dast")
    _p("Rodando ZAP baseline (Docker)… pode levar alguns minutos.")
    findings, limits = dast.run_zap_baseline(a.url, target=a.url,
                                             host_network=a.host_network)
    for f in findings:
        sess.add_finding(f.to_dict())
    _p(f"ZAP: {len(findings)} alerta(s) (sessão {sess.id})")
    for f in findings:
        _p(f"  [{f.severity.value.upper()}] {f.title}")
    for lim in limits:
        _p(f"  (limitação) {lim}")
    return 0


def cmd_iac(a) -> int:
    """IaC/misconfig via Trivy (roda se instalado)."""
    from pathlib import Path
    from . import iac
    root = Path(a.path)
    if not root.exists():
        _p(f"Pasta não encontrada: {a.path}")
        return 1
    sess = Session.active() or Session.create(environment="iac")
    findings, limits = iac.run_trivy_config(root)
    for f in findings:
        sess.add_finding(f.to_dict())
    _p(f"IaC (Trivy) em {root}  (sessão {sess.id})")
    for f in findings:
        ev = f.evidence_ids[0] if f.evidence_ids else ""
        _p(f"  [{f.severity.value.upper()}] {f.title}  ({ev})")
    if not findings:
        _p("  Nenhuma misconfig (ou ferramenta ausente — ver limitações).")
    for lim in limits:
        _p(f"  (limitação) {lim}")
    return 0


def cmd_deps(a) -> int:
    """Scanner de dependências vulneráveis (OSV)."""
    from pathlib import Path
    from . import deps as deps_mod
    root = Path(a.path)
    if not root.exists():
        _p(f"Pasta não encontrada: {a.path}")
        return 1
    sess = Session.active() or Session.create(environment="deps")
    findings, limits = deps_mod.run_deps(root, sess)
    _p(f"Dependências (OSV) em {root}  (sessão {sess.id})")
    for f in findings:
        cve = f" [{f.cve}]" if f.cve else ""
        _p(f"  [{f.severity.value.upper()}] {f.title}{cve}")
    if not findings:
        _p("  Nenhuma dependência vulnerável encontrada nos lockfiles lidos.")
    for lim in limits:
        _p(f"  (limitação) {lim}")
    _p("Nota: 'afetada' != exploração comprovada; base OSV pode estar incompleta.")
    return 0


def cmd_scan(a) -> int:
    argv: list[str] = []
    if a.target:
        argv.append(a.target)
    if a.yes:
        argv.append("-y")
    if a.calm:
        argv.append("--calm")
    if getattr(a, "code", None):
        argv += ["--code", a.code]
    if getattr(a, "no_claude", False):
        argv.append("--no-claude")
    return scan_main(argv)


def cmd_replay(a) -> int:
    """Teste ativo autorizado (IDOR/mass/no-auth/rate). 1 requisição (JSON) ou HAR."""
    from pathlib import Path
    from . import replay
    tests = [t.strip() for t in (a.tests or "").split(",") if t.strip()]
    scope = scope_mod.load_scope()
    sess = Session.active() or Session.create(environment="replay")

    # monta a lista de requisições (1 JSON ou várias de um HAR)
    reqs = []
    if a.har:
        harf = Path(a.har)
        if not harf.exists():
            _p(f"HAR não encontrado: {a.har}")
            return 1
        try:
            reqs = replay.load_har(harf)
        except Exception as e:  # noqa: BLE001
            _p(f"HAR inválido: {e}")
            return 1
        _p(f"HAR: {len(reqs)} requisição(ões) importada(s).")
    elif a.request:
        reqf = Path(a.request)
        if not reqf.exists():
            _p(f"Arquivo de requisição não encontrado: {a.request}")
            return 1
        try:
            reqs = [replay.load_request(reqf)]
        except Exception as e:  # noqa: BLE001
            _p(f"JSON de requisição inválido: {e}")
            return 1
    else:
        _p("Informe um <req.json> ou --har <arquivo.har>.")
        return 1

    total, pulados = [], 0
    for req in reqs:
        try:
            found = replay.run_replay(sess, scope, req, tests,
                                      fuzz_value=a.fuzz_value,
                                      allow_side_effects=a.side_effects)
        except PermissionError as e:
            pulados += 1
            if len(reqs) == 1:
                _p(f"BLOQUEADO: {e}")
                return 2
            continue  # HAR: pula fora-de-escopo/muda-estado, segue o resto
        total.extend(found)

    _p(f"Replay: {len(reqs) - pulados} rodada(s), {pulados} pulada(s) "
       f"(fora do escopo/posse ou mudam estado). Sessão {sess.id}")
    if not total:
        _p("Nenhuma suspeita nos testes rodados. NÃO prova ausência de falha.")
        return 0
    for f in total:
        ev = ", ".join(f.evidence_ids) if f.evidence_ids else ""
        _p(f"  [{f.severity.value.upper()}] {f.title}  ({ev})")
    return 0


def cmd_hook(_a) -> int:
    from .hook import main as hook_main
    return hook_main()


def cmd_banner(_a) -> int:
    """Banner dark do projeto (usado pelo hook SessionStart do workspace)."""
    try:
        s = scope_mod.load_scope()
        alvos = len(s.targets) if s else 0
        auth = "sim" if (s and s.authorized) else "nao"
        prompts = len(ctx.list_masters())
    except Exception:  # noqa: BLE001
        alvos, auth, prompts = 0, "nao", 0
    C, G, D, R = "\033[96m", "\033[92m", "\033[90m", "\033[0m"
    _p(f"{C}  +-------------------------------------------------+")
    _p("  |   SCANNACS  -  auditoria dos proprios ativos      |")
    _p(f"  +-------------------------------------------------+{R}")
    _p(f"{D}  prompts:{prompts}  alvos:{alvos}  autorizado:{auth}{R}")
    _p(f"{G}  Digite  /scan  para configurar/rodar a auditoria.{R}")
    return 0


def materialize_workspace(dst) -> tuple[int, int]:
    """Copia o workspace empacotado para `dst`. Idempotente (não sobrescreve).

    Devolve (criados, preservados). Não traz segredo/escopo/sessão."""
    from pathlib import Path
    import shutil
    dst = Path(dst).resolve()
    srcws = config.PKG_DATA / "workspace"
    if not srcws.exists():
        raise FileNotFoundError(f"workspace empacotado ausente em {srcws}")
    created, kept = 0, 0
    for s in srcws.rglob("*"):
        if not s.is_file():
            continue
        parts = list(s.relative_to(srcws).parts)
        if parts and parts[0] == "claude_ws":   # renomeia de volta p/ .claude
            parts[0] = ".claude"
        d = dst.joinpath(*parts)
        d.parent.mkdir(parents=True, exist_ok=True)
        if d.exists():
            kept += 1
            continue
        shutil.copy2(s, d)
        created += 1
    return created, kept


def cmd_init_workspace(a) -> int:
    """Materializa o workspace do Claude (CLAUDE.md, .claude, prompts) numa pasta."""
    try:
        created, kept = materialize_workspace(a.dir)
    except FileNotFoundError as e:
        _p(f"{e} (rode tools/sync-workspace.py antes de empacotar).")
        return 1
    config.ensure_dirs()
    _p(f"Workspace pronto em {a.dir}: {created} criado(s), {kept} preservado(s).")
    _p("Abra o Claude Code nessa pasta e use /scan (a fase 2 usa os agentes/skills).")
    return 0


# --------------------------------------------------------------------------- #
# report — relatório de ponta a ponta a partir da sessão
# --------------------------------------------------------------------------- #
def _classify_evidence(evs: list) -> tuple[list, list, list]:
    """(rodou_ok, inconclusivos, nao_instalados) a partir das evidências."""
    ok, incon, missing = [], [], []
    for e in evs:
        st = e.get("status")
        tool = e.get("tool", "?")
        summ = (e.get("result_summary") or "").lower()
        if st == "ok":
            ok.append(tool)
        elif "ausente" in summ or "não instalada" in summ or "nao instalada" in summ:
            missing.append(tool)
        else:
            incon.append((tool, st, e.get("result_summary", "")[:80]))
    return ok, incon, missing


def print_report(sess: Session) -> None:
    m = sess.meta()
    findings = sess.findings()
    evs = sess.evidence()
    # alvo REAL desta sessão vem das evidências/achados, não do escopo global
    tgt = "-"
    for src in (evs, findings):
        for it in src:
            if it.get("target"):
                tgt = it["target"]
                break
        if tgt != "-":
            break
    scope = scope_mod.load_scope()
    verified = bool(scope and any(
        scope_mod._host_of(t.value) == scope_mod._host_of(tgt) and t.owner_verified
        for t in scope.targets))
    confirmados = [f for f in findings if f.get("status") == "confirmado"]
    suspeitas = [f for f in findings if f.get("status") == "suspeita"]
    descartados = [f for f in findings if f.get("status") == "descartado"]
    inconclusivos = [f for f in findings if f.get("status") == "inconclusivo"]
    ok, incon, missing = _classify_evidence(sess.evidence())

    nao_revisados = [f for f in findings
                     if not (f.get("validation") or {}).get("validated_by")]
    _p("=" * 56)
    _p(f" RELATÓRIO — {tgt}")
    _p(f" sessão {sess.id} | posse {'verificada' if verified else 'NÃO verificada'}")
    _p(f" versão {m.get('version','?')} commit {m.get('commit') or '-'} "
       f"({m.get('install_mode','?')}) | status {m.get('status','?')}")
    _p("=" * 56)
    _p(f"\nCONFIRMADOS (com evidência): {len(confirmados)}")
    for f in confirmados:
        _p(f"  - [{f.get('severity')}] {f.get('title')}")
    _p(f"\nSUSPEITAS (precisam validação): {len(suspeitas)}")
    for f in suspeitas:
        ev = ", ".join(f.get("evidence_ids", []))
        _p(f"  - [{f.get('severity')}] {f.get('title')}"
           f"{(' (evi: ' + ev + ')') if ev else ''}")
    if inconclusivos:
        _p(f"\nINCONCLUSIVOS (revisados, sem confirmação possível agora): "
           f"{len(inconclusivos)}")
        for f in inconclusivos:
            why = (f.get("validation") or {}).get("method") or ""
            _p(f"  - [{f.get('severity')}] {f.get('title')}"
               f"{(' — ' + why) if why else ''}")
    if descartados:
        _p(f"\nDESCARTADOS (refutados): {len(descartados)}")
        for f in descartados:
            _p(f"  - {f.get('title')}")
    if incon:
        _p(f"\nMOTORES INCONCLUSIVOS (não terminaram/erro): {len(incon)}")
        for tool, st, why in incon:
            _p(f"  - {tool}: {st} — {why}")
    if missing:
        _p(f"\nNÃO RODARAM (ferramenta não instalada): {', '.join(sorted(set(missing)))}")
    _p(f"\nNÃO REVISADOS (sem decisão registrada): {len(nao_revisados)}")
    if nao_revisados:
        _p("  -> não são 'seguros'; faltam validação/decisão rastreável "
           "(use `agente finding set-status`).")
    from . import reconcile as _rec
    r = _rec.reconcile(findings)
    _p(f"\nRECONCILIAÇÃO: brutos {r['bruto']} | únicos {r['unicos']} | "
       f"duplicados {r['duplicados']} | revisados {r['revisados']} | "
       f"não-revisados {r['nao_revisados']}")
    _p(f"\nCOBERTURA: motores OK: {', '.join(sorted(set(ok))) or '-'}")
    _p("AVISO: relatório sem achado NÃO prova ausência de vulnerabilidade — "
       "só cobre o que foi testado. Amostragem não vira conclusão ampla: itens "
       "sem decisão ficam em NÃO REVISADOS.")


def cmd_report(_a) -> int:
    s = Session.active()
    if not s:
        _p("Nenhuma sessão ativa.")
        return 1
    print_report(s)
    return 0


def cmd_integracoes(_a) -> int:
    doc = config.ROOT / "docs" / "integracoes.md"
    _p(f"Registro de integrações: {doc}")
    if doc.exists():
        _p(doc.read_text(encoding="utf-8")[:1500])
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agente",
                                description="Agente de auditoria dos próprios ativos.")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("version").set_defaults(func=cmd_version)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)

    ui = sub.add_parser("ui", help="abre a interface do Claude Code no projeto")
    ui.add_argument("--print", default=None, help="prompt inicial (default /auditoria)")
    ui.add_argument("--no-launch", action="store_true", help="apenas mostra o comando")
    ui.set_defaults(func=cmd_ui)

    se = sub.add_parser("session"); se_s = se.add_subparsers(dest="c")
    se_s.add_parser("new").set_defaults(func=cmd_session_new)
    se_s.add_parser("list").set_defaults(func=cmd_session_list)
    se_s.add_parser("show").set_defaults(func=cmd_session_show)
    r = se_s.add_parser("resume"); r.add_argument("id"); r.set_defaults(func=cmd_session_resume)
    se_s.add_parser("close", help="encerra a sessão com retrato de cobertura").set_defaults(func=cmd_session_close)

    pr = sub.add_parser("prompts"); pr_s = pr.add_subparsers(dest="c")
    pr_s.add_parser("list").set_defaults(func=cmd_prompts_list)
    imp = pr_s.add_parser("import")
    imp.add_argument("source", help="arquivo ou '-' para stdin")
    imp.add_argument("slug", help="identificador curto (kebab)")
    imp.add_argument("--title", default="")
    imp.add_argument("--order", type=int, default=100)
    imp.add_argument("--purpose", default="")
    imp.add_argument("--agents", default="")
    imp.add_argument("--version", type=int, default=1)
    imp.set_defaults(func=cmd_prompts_import)
    cx = pr_s.add_parser("context"); cx.add_argument("--agent", default=None)
    cx.set_defaults(func=cmd_prompts_context)
    pr_s.add_parser("import-inbox", help="importa prompts/inbox/*.md|.txt").set_defaults(func=cmd_prompts_import_inbox)

    sc = sub.add_parser("scope"); sc_s = sc.add_subparsers(dest="c")
    sc_s.add_parser("init").set_defaults(func=cmd_scope_init)
    sc_s.add_parser("show").set_defaults(func=cmd_scope_show)
    sc_s.add_parser("validate").set_defaults(func=cmd_scope_validate)
    ev = sc_s.add_parser("set-env"); ev.add_argument("environment")
    ev.set_defaults(func=cmd_scope_set_env)
    at = sc_s.add_parser("add-target")
    at.add_argument("--name", default="")
    at.add_argument("--type", required=True)
    at.add_argument("--value", required=True)
    at.add_argument("--tests", default="")
    at.add_argument("--limits", default="")
    at.add_argument("--exclusions", default="")
    at.add_argument("--notes", default="")
    at.set_defaults(func=cmd_scope_add_target)
    au = sc_s.add_parser("authorize", help="DISPARAR AUDITORIA (autorização única)")
    au.add_argument("--by", required=True)
    au.set_defaults(func=cmd_scope_authorize)
    vf = sc_s.add_parser("verify", help="prova de posse do alvo (token arquivo/DNS)")
    vf.add_argument("--target", required=True)
    vf.set_defaults(func=cmd_scope_verify)

    ad = sub.add_parser("audit"); ad_s = ad.add_subparsers(dest="c")
    ad_s.add_parser("plan").set_defaults(func=cmd_audit_plan)
    ru = ad_s.add_parser("run")
    ru.add_argument("--confirm", action="store_true")
    ru.add_argument("--aggressive", action="store_true",
                    help="sem teto prático de rate (força total no escopo)")
    ru.set_defaults(func=cmd_audit_run)
    ad_s.add_parser("status").set_defaults(func=cmd_audit_status)

    ex = sub.add_parser("exec", help="executor controlado + captura de evidência")
    ex.add_argument("--target", required=True)
    ex.add_argument("--tool", default="")
    ex.add_argument("--timeout", type=int, default=60)
    ex.add_argument("--rps", type=float, default=5.0)
    ex.add_argument("--max-per-run", type=int, default=500, dest="max_per_run")
    ex.add_argument("command", nargs=argparse.REMAINDER,
                    help="após --, o comando a executar")
    ex.set_defaults(func=cmd_exec)

    evd = sub.add_parser("evidence"); evd_s = evd.add_subparsers(dest="c")
    evd_s.add_parser("list").set_defaults(func=cmd_evidence_list)

    fn = sub.add_parser("finding"); fn_s = fn.add_subparsers(dest="c")
    fn_s.add_parser("list").set_defaults(func=cmd_finding_list)
    fs = fn_s.add_parser("set-status", help="persiste decisão do validador")
    fs.add_argument("id")
    fs.add_argument("--status", required=True,
                    choices=["confirmado", "descartado", "inconclusivo",
                             "suspeita", "nao_verificado"])
    fs.add_argument("--by", required=True)
    fs.add_argument("--reason", default="")
    fs.add_argument("--alt", default="", help="explicação alternativa considerada")
    fs.add_argument("--type", default=None,
                    help="confirmation_type (falha_no_codigo|configuracao_vulneravel|comportamento_reproduzido)")
    fs.set_defaults(func=cmd_finding_set)

    fx = sub.add_parser("fixtures"); fx_s = fx.add_subparsers(dest="c")
    fx_s.add_parser("run").set_defaults(func=cmd_fixtures_run)

    sca = sub.add_parser("scan", help="auditoria ponta a ponta (posse + roda tudo)")
    sca.add_argument("target", nargs="?")
    sca.add_argument("-y", "--yes", action="store_true")
    sca.add_argument("--calm", action="store_true")
    sca.add_argument("--code", default=None, help="pasta do código p/ análise local")
    sca.add_argument("--no-claude", action="store_true",
                     help="não abrir o Claude Code na fase 2")
    sca.set_defaults(func=cmd_scan)
    rc = sub.add_parser("review-code", help="análise de código local (segredo/RLS/XSS)")
    rc.add_argument("path")
    rc.add_argument("--target", default="")
    rc.add_argument("--no-export", dest="export", action="store_false",
                    help="não exportar os trechos de código (padrão: exporta)")
    rc.set_defaults(func=cmd_review_code, export=True)
    dp = sub.add_parser("deps", help="dependências vulneráveis via OSV (lockfiles)")
    dp.add_argument("path")
    dp.set_defaults(func=cmd_deps)
    st = sub.add_parser("sast", help="SAST real via Semgrep (se instalado)")
    st.add_argument("path")
    st.add_argument("--config", default="auto")
    st.set_defaults(func=cmd_sast)
    ic = sub.add_parser("iac", help="IaC/misconfig via Trivy (se instalado)")
    ic.add_argument("path")
    ic.set_defaults(func=cmd_iac)
    zi = sub.add_parser("zap-import", help="importa relatório JSON do ZAP")
    zi.add_argument("json")
    zi.add_argument("--target", default="")
    zi.set_defaults(func=cmd_zap_import)
    da = sub.add_parser("dast", help="DAST via ZAP baseline (Docker; posse+escopo)")
    da.add_argument("url")
    da.add_argument("--host-network", action="store_true",
                    help="usa --network host (labs em localhost, Linux)")
    da.set_defaults(func=cmd_dast)
    rp = sub.add_parser("replay", help="teste ativo autorizado (IDOR/mass/no-auth/rate)")
    rp.add_argument("request", nargs="?", help="arquivo JSON da requisição capturada")
    rp.add_argument("--har", default=None, help="importa requisições de um arquivo HAR")
    rp.add_argument("--tests", default="no-auth,idor,mass,rate")
    rp.add_argument("--fuzz-value", dest="fuzz_value", default="__idor_probe__")
    rp.add_argument("--com-efeito-colateral", dest="side_effects",
                    action="store_true", help="permite métodos que mudam estado")
    rp.set_defaults(func=cmd_replay)
    sub.add_parser("tools", help="lista motores/ferramentas detectadas").set_defaults(func=cmd_tools)
    sub.add_parser("report", help="relatório da sessão ativa").set_defaults(func=cmd_report)
    sub.add_parser("reconcile", help="reconciliação por ID dos achados").set_defaults(func=cmd_reconcile)
    sub.add_parser("hook").set_defaults(func=cmd_hook)
    sub.add_parser("banner").set_defaults(func=cmd_banner)
    iw = sub.add_parser("init-workspace",
                        help="materializa CLAUDE.md/.claude/prompts numa pasta")
    iw.add_argument("dir", nargs="?", default=".")
    iw.set_defaults(func=cmd_init_workspace)
    sub.add_parser("integracoes").set_defaults(func=cmd_integracoes)

    return p


# --------------------------------------------------------------------------- #
# scan — entrada única, ponta a ponta, com PROVA DE POSSE OBRIGATÓRIA
# --------------------------------------------------------------------------- #
def scan_main(argv: list[str] | None = None) -> int:
    """`scan [alvo]` — auditoria dos SEUS ativos.

    Exige prova de posse (token em arquivo ou DNS TXT) para QUALQUER alvo antes
    de testar. É o que torna a ferramenta segura para distribuir: não é possível
    escanear um host que você não controla.
    """
    ap = argparse.ArgumentParser(
        prog="scan",
        description="Auditoria de segurança ponta a ponta dos SEUS ativos "
                    "(exige prova de posse do alvo).")
    ap.add_argument("target", nargs="?", help="site/servidor (ex.: exemplo.com)")
    ap.add_argument("-y", "--yes", action="store_true", help="não perguntar")
    ap.add_argument("--calm", action="store_true", help="intensidade normal")
    ap.add_argument("--code", default=None,
                    help="pasta do código-fonte p/ análise local (segredo/RLS/XSS)")
    ap.add_argument("--no-claude", action="store_true",
                    help="não abrir o Claude Code na fase 2 (só a fase 1)")
    a = ap.parse_args(argv)
    config.ensure_dirs()

    target = a.target
    if not target:
        try:
            target = input("Qual site ou servidor vamos analisar? ").strip()
        except EOFError:
            target = ""
    if not target:
        _p("Nenhum alvo informado.")
        return 1

    host = scope_mod._host_of(target)
    if target.startswith(("http://", "https://")):
        ttype = "url"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        ttype = "ip"
    else:
        ttype = "domain"

    scope = scope_mod.load_scope() or scope_mod.Scope()
    existing = next((t for t in scope.targets
                     if scope_mod._host_of(t.value) == host), None)
    if existing is None:
        t = scope_mod.Target(name=host, type=ttype, value=target,
                             allowed_tests=["all"])
        probs = t.problems()
        if probs:
            _p("Alvo recusado:")
            for p in probs:
                _p(f"  - {p}")
            return 1
        scope.targets.append(t)
        existing = t
        scope_mod.save_scope(scope)
    elif "all" not in [x.lower() for x in existing.allowed_tests]:
        existing.allowed_tests = ["all"]
        scope_mod.save_scope(scope)

    # PROVA DE POSSE OBRIGATÓRIA (todo alvo) — impede uso contra terceiros
    if not existing.owner_verified:
        ok, method, _ = scope_mod.verify_ownership(existing.value)
        if ok:
            existing.owner_verified = True
            existing.owner_verified_at = _now()
            scope_mod.save_scope(scope)
            _p(f"Posse confirmada ({method}).")
        else:
            token = scope_mod.expected_token(existing.value)
            _p(f"Antes de testar, prove que {host} é seu (uma vez só).")
            _p(f"Publique o token e rode 'scan {target}' de novo:")
            _p(f"  Arquivo: https://{host}/rz-audit-verify.txt  ->  {token}")
            _p(f"  ou registro DNS TXT em {host}  ->  {token}")
            return 2

    # modo conversa: oferece incluir a análise do código-fonte (risco de SPA)
    if not a.code and not a.yes and sys.stdin.isatty():
        try:
            cp = input("Caminho do codigo-fonte p/ analise local "
                       "(Enter p/ pular): ").strip().strip('"')
        except EOFError:
            cp = ""
        if cp:
            a.code = cp

    if not a.yes:
        _p(f"Vou auditar {existing.value} com todos os motores instalados"
           f"{' + analise do codigo' if a.code else ''}. Nada sai do seu alvo.")
        try:
            resp = input("Comecar? (s/N) ").strip().lower()
        except EOFError:
            resp = ""
        if resp not in ("s", "sim", "y", "yes", "iniciar"):
            _p("Cancelado.")
            return 0

    scope.authorized = True
    scope.authorized_by = "dono"
    scope.authorized_at = _now()
    scope_mod.save_scope(scope)

    # Escopo POR-EXECUÇÃO: só o alvo selecionado (não varre outros salvos).
    run_scope = scope_mod.Scope(
        authorized=True, authorized_by="dono", authorized_at=scope.authorized_at,
        environment=scope.environment, targets=[existing])

    sess = Session.create(environment=scope.environment or "producao",
                          scope_hash=scope_mod.scope_hash(run_scope),
                          prompts_hash=ctx.manifest_hash())
    _p("Rodando auditoria ponta a ponta... (pode levar alguns minutos)")
    rps, maxrun = (5.0, 500) if a.calm else (50.0, 100000)
    try:
        audit_mod.run(scope=run_scope, confirmed=True, session=sess,
                      rps=rps, max_per_run=maxrun)
    except audit_mod.AuditBlocked as exc:
        _p("Bloqueado: " + "; ".join(exc.reasons))
        return 2

    if a.code:
        from pathlib import Path
        from . import codereview
        cpath = Path(a.code)
        if cpath.exists():
            _p(f"Analisando código em {cpath} ...")
            for f in codereview.review(cpath, target=existing.value):
                sess.add_finding(f.to_dict())
        else:
            _p(f"(--code) pasta não encontrada: {a.code}")

    _p("")
    print_report(sess)

    # Fase 2: abre o Claude Code para VALIDAR e escrever o relatório final.
    # (O Claude não re-executa scan ofensivo — apenas analisa a evidência.)
    if not a.no_claude:
        claude = shutil.which("claude")
        if claude and sys.stdin.isatty():
            _p("\n== Fase 2: abrindo o Claude Code para validar e finalizar "
               "o relatório (Ctrl+C encerra) ==")
            from pathlib import Path as _P
            wsdir = _P.cwd()
            if not (wsdir / ".claude").exists():   # 1ª utilização: prepara sozinho
                try:
                    c, _k = materialize_workspace(wsdir)
                    _p(f"   workspace preparado ({c} arquivos) em {wsdir}")
                except Exception as e:  # noqa: BLE001
                    _p(f"   (aviso: não preparei o workspace: {e})")
            try:
                subprocess.call([claude, "-n", "Auditoria", "/finalizar"],
                                cwd=str(wsdir))
            except Exception as e:  # noqa: BLE001
                _p(f"(não consegui abrir o Claude Code: {e})")
        elif not claude:
            _p("\n(Claude Code não encontrado. Depois rode a fase 2 manual: "
               "abra `claude` no projeto e use /finalizar.)")
    return 0


def main(argv: list[str] | None = None) -> int:
    config.ensure_dirs()
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    return func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
