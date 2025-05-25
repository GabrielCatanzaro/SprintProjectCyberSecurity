### app/utils/email_sender.py
import random

def enviar_codigo(email: str) -> int:
    codigo = random.randint(100000, 999999)
    print(f"Enviar para {email}: Código {codigo}")
    return codigo