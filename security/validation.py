### app/security/validacao.py
import bleach

def limpar_input(entrada: str) -> str:
    return bleach.clean(entrada)
