"""Directory stabile dell'agente: dove vivono identita' e token.

Perche' esiste
--------------
`token.json`, `device.key` e `device.crt` erano risolti come path RELATIVI,
quindi la cwd decideva quale identita' usava l'agente. Lo stesso device finiva
con tre token diversi (uno per ogni directory di lancio: radice del repo,
cartella degli agenti, cartella dell'exe) e il brain rispondeva 401 a ogni
chiamata autenticata: l'agente restava registrato ma CIECO, con un warning al
minuto e nessun recupero (il wipe automatico non esiste, by design).

Ora la base e' una sola e non dipende da dove sei quando avvii:

  * exe PyInstaller  -> cartella dell'eseguibile (accanto a config.json);
  * sorgente Python  -> cartella degli agenti (…/agents/python);
  * override esplicito -> NODETRACE_IDENTITY_DIR (o AEGIS_AGENT_HOME).
"""
import os
import sys


def agent_home() -> str:
    """Path assoluto della directory di stato dell'agente. Mai eccezioni."""
    env = os.getenv("NODETRACE_IDENTITY_DIR") or os.getenv("AEGIS_AGENT_HOME")
    if env and env.strip():
        return os.path.abspath(env.strip())
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    # …/agents/python/services/agent_home.py -> …/agents/python
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
