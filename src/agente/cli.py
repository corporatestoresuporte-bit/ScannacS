"""Interface de linha de comando do agente.

Uso:  python -m agente <comando>
      (ou, após `pip install -e .`, apenas `agente <comando>`)

Comandos:
  version            mostra a versão
  doctor             checa ambiente (Python, config, prompts, segredos)
  scope init         cria config/scope.toml a partir do exemplo
  scope show         mostra o escopo atual
  scope validate     roda o portão de autorização e explica o veredito
  prompts list       lista os prompts master registrados
  audit plan         descreve o que seria executado (não toca na rede)
  audit run          executa a auditoria (bloqueada sem escopo + --confirm)
"""

from __future__ import annotations

import argparse
import shutil
import sys

from . import __version__, config
from . import audit as audit_mod
from . import scope as scope_mod


def _print(*a: object) -> None:
    print(*a)


def cmd_version(_args: argparse.Namespace) -> int:
    _print(f"agente-vulnerabilidades {__version__}")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    ok = True
    _print(f"Python              : {sys.version.split()[0]}")
    _print(f"Raiz do projeto     : {config.ROOT}")

    scope_state = "presente" if config.SCOPE_FILE.exists() else "AUSENTE (use scope init)"
    _print(f"config/scope.toml   : {scope_state}")

    settings_state = "presente" if config.SETTINGS_FILE.exists() else "ausente (opcional)"
    _print(f"config/settings.toml: {settings_state}")

    masters = sorted(config.MASTERS_DIR.glob("*")) if config.MASTERS_DIR.exists() else []
    _print(f"prompts master      : {len(masters)} arquivo(s)")

    env_state = "presente" if config.ENV_FILE.exists() else "ausente (copie de .env.example)"
    _print(f".env                : {env_state}")

    _print(f"motores de scan     : {len(audit_mod.ENGINES)} registrado(s)")

    gate = audit_mod.preflight()
    verdict = "LIBERADA" if gate.allowed else "BLOQUEADA"
    _print(f"auditoria           : {verdict}")
    return 0 if ok else 1


def cmd_scope_init(_args: argparse.Namespace) -> int:
    if config.SCOPE_FILE.exists():
        _print(f"Já existe: {config.SCOPE_FILE} (não sobrescrito).")
        return 0
    if not config.SCOPE_EXAMPLE.exists():
        _print(f"Modelo não encontrado: {config.SCOPE_EXAMPLE}")
        return 1
    shutil.copyfile(config.SCOPE_EXAMPLE, config.SCOPE_FILE)
    _print(f"Criado: {config.SCOPE_FILE}")
    _print("Edite os alvos e defina authorized = true quando você autorizar.")
    return 0


def cmd_scope_show(_args: argparse.Namespace) -> int:
    scope = scope_mod.load_scope()
    if scope is None:
        _print("Escopo não definido (config/scope.toml ausente).")
        return 1
    _print(f"authorized   : {scope.authorized}")
    _print(f"authorized_by: {scope.authorized_by or '-'}")
    _print(f"authorized_at: {scope.authorized_at or '-'}")
    _print(f"environment  : {scope.environment or '-'}")
    _print(f"alvos        : {len(scope.targets)}")
    for t in scope.targets:
        _print(f"  - [{t.type}] {t.name or '(sem nome)'} -> {t.value or '(vazio)'}")
    return 0


def cmd_scope_validate(_args: argparse.Namespace) -> int:
    gate = audit_mod.preflight()
    if gate.allowed:
        _print("Portão: LIBERADO — escopo válido e autorizado.")
        _print("A execução ainda exige `audit run --confirm`.")
        return 0
    _print("Portão: BLOQUEADO. Motivos:")
    for r in gate.reasons:
        _print(f"  - {r}")
    return 1


def cmd_prompts_list(_args: argparse.Namespace) -> int:
    if not config.MASTERS_DIR.exists():
        _print("prompts/masters/ não existe.")
        return 1
    files = sorted(p for p in config.MASTERS_DIR.glob("*") if p.is_file() and p.name != ".gitkeep")
    if not files:
        _print("Nenhum prompt master registrado ainda.")
        return 0
    for p in files:
        _print(f"  - {p.name}")
    return 0


def cmd_audit_plan(_args: argparse.Namespace) -> int:
    for line in audit_mod.plan():
        _print(line)
    return 0


def cmd_audit_run(args: argparse.Namespace) -> int:
    try:
        result = audit_mod.run(confirmed=args.confirm)
    except audit_mod.AuditBlocked as exc:
        _print("Auditoria BLOQUEADA:")
        for r in exc.reasons:
            _print(f"  - {r}")
        return 2
    for note in result.notes:
        _print(note)
    _print(f"Executada: {result.executed} | achados: {len(result.findings)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agente",
        description="Agente de auditoria de segurança dos próprios ativos.",
    )
    sub = p.add_subparsers(dest="command")

    sub.add_parser("version", help="mostra a versão").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="checa o ambiente").set_defaults(func=cmd_doctor)

    sp = sub.add_parser("scope", help="gerência de escopo")
    scope_sub = sp.add_subparsers(dest="scope_cmd")
    scope_sub.add_parser("init", help="cria scope.toml do exemplo").set_defaults(func=cmd_scope_init)
    scope_sub.add_parser("show", help="mostra o escopo").set_defaults(func=cmd_scope_show)
    scope_sub.add_parser("validate", help="roda o portão").set_defaults(func=cmd_scope_validate)

    pp = sub.add_parser("prompts", help="prompts master")
    prompts_sub = pp.add_subparsers(dest="prompts_cmd")
    prompts_sub.add_parser("list", help="lista os prompts").set_defaults(func=cmd_prompts_list)

    ap = sub.add_parser("audit", help="auditoria")
    audit_sub = ap.add_subparsers(dest="audit_cmd")
    audit_sub.add_parser("plan", help="descreve o que seria executado").set_defaults(func=cmd_audit_plan)
    run_p = audit_sub.add_parser("run", help="executa (bloqueada sem escopo)")
    run_p.add_argument(
        "--confirm",
        action="store_true",
        help="confirma explicitamente o início da execução",
    )
    run_p.set_defaults(func=cmd_audit_run)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    return func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
