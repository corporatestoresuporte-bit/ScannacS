"""agente-vulnerabilidades — base do agente de auditoria de segurança.

Fundação modular. Os provedores de IA e os scanners reais são integrados
depois, quando os prompts master e o escopo forem definidos.
"""

try:  # instalado: usa a versão real do pacote (fonte única = pyproject)
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("scannacs")
except Exception:  # checkout sem metadados instalados: casa com pyproject
    __version__ = "0.2.0b2"

__all__ = ["__version__"]
