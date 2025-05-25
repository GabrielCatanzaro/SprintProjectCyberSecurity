import json
import os
import re
import time
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import jwt  # pip install PyJWT

# --- Configurações ---
SECRET_KEY = secrets.token_bytes(32)  # chave AES-256 (32 bytes)
JWT_SECRET = "supersecretjwtkey"  # para tokens JWT
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 300  # 5 minutos
MFA_CODE_EXPIRY = 120  # segundos

# Setup logger de auditoria
logging.basicConfig(filename='audit.log', level=logging.INFO, format='%(asctime)s %(message)s')

# --- Funções para criptografia AES-256 ---

def encrypt_data(plaintext: str, key: bytes) -> str:
    iv = secrets.token_bytes(16)  # vetor de inicialização para CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    # Retorna base64 iv + ciphertext
    return base64.b64encode(iv + ct).decode()

def decrypt_data(ciphertext_b64: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()
    return plain.decode()

# --- Validação / Sanitização ---
def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_cpf(cpf: str) -> bool:
    # Simples validação de formato (XXX.XXX.XXX-XX ou só dígitos)
    return re.match(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$", cpf) is not None

# --- Autenticação multifator simplificada ---

class MFA:
    codes = {}  # user_id: (code, expiry_time)

    @staticmethod
    def send_code(user_id):
        code = f"{secrets.randbelow(1000000):06d}"  # 6 dígitos
        expiry = time.time() + MFA_CODE_EXPIRY
        MFA.codes[user_id] = (code, expiry)
        # Simula envio SMS/email
        print(f"[MFA] Código para {user_id}: {code}")

    @staticmethod
    def verify_code(user_id, code_input):
        if user_id not in MFA.codes:
            return False
        code, expiry = MFA.codes[user_id]
        if time.time() > expiry:
            del MFA.codes[user_id]
            return False
        if code == code_input:
            del MFA.codes[user_id]
            return True
        return False

# --- JWT Token ---

def create_jwt_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --- Dados dos usuários (simulação banco) ---

USERS_DB = {
    "user1": {
        "cpf": encrypt_data("123.456.789-00", SECRET_KEY),
        "email": encrypt_data("user1@email.com", SECRET_KEY),
        "password": encrypt_data("senha123", SECRET_KEY),  # deveria usar hash+salt, mas simplificado
        "history": encrypt_data("Aposta 1: perda, Aposta 2: ganho", SECRET_KEY),
        "role": "user"
    },
    "admin": {
        "cpf": encrypt_data("111.222.333-44", SECRET_KEY),
        "email": encrypt_data("admin@email.com", SECRET_KEY),
        "password": encrypt_data("adminpass", SECRET_KEY),
        "history": encrypt_data("", SECRET_KEY),
        "role": "admin"
    }
}

# --- Funções principais ---

def log_action(user_id, action):
    logging.info(f"User '{user_id}' realizou ação: {action}")

def authenticate(user_id, password):
    user = USERS_DB.get(user_id)
    if not user:
        return False
    try:
        stored_password = decrypt_data(user["password"], SECRET_KEY)
    except Exception:
        return False
    if stored_password != password:
        return False
    MFA.send_code(user_id)
    return True

def mfa_login(user_id, code):
    if MFA.verify_code(user_id, code):
        user = USERS_DB.get(user_id)
        if user:
            token = create_jwt_token(user_id, user['role'])
            log_action(user_id, "Login com MFA")
            return token
    return None

def get_user_data(token, user_id_to_fetch):
    payload = decode_jwt_token(token)
    if not payload:
        print("Token inválido ou expirado.")
        return
    if payload["user_id"] != user_id_to_fetch and payload["role"] != "admin":
        print("Sem permissão para acessar dados de outro usuário.")
        return
    user = USERS_DB.get(user_id_to_fetch)
    if not user:
        print("Usuário não encontrado.")
        return
    decrypted_data = {k: decrypt_data(v, SECRET_KEY) for k, v in user.items() if k != "role"}
    log_action(payload["user_id"], f"Acessou dados do usuário '{user_id_to_fetch}'")
    print(json.dumps(decrypted_data, indent=2, ensure_ascii=False))

def update_user_email(token, user_id, new_email):
    payload = decode_jwt_token(token)
    if not payload:
        print("Token inválido ou expirado.")
        return False
    if payload["user_id"] != user_id and payload["role"] != "admin":
        print("Sem permissão para modificar dados de outro usuário.")
        return False
    if not validate_email(new_email):
        print("E-mail inválido.")
        return False
    USERS_DB[user_id]["email"] = encrypt_data(new_email, SECRET_KEY)
    log_action(payload["user_id"], f"Atualizou email do usuário '{user_id}'")
    print("Email atualizado com sucesso.")
    return True

def delete_user(token, user_id_to_delete):
    payload = decode_jwt_token(token)
    if not payload:
        print("Token inválido ou expirado.")
        return False
    # Apenas admin pode deletar usuários
    if payload["role"] != "admin":
        print("Sem permissão para deletar usuários.")
        return False
    if user_id_to_delete not in USERS_DB:
        print("Usuário não encontrado.")
        return False
    del USERS_DB[user_id_to_delete]
    log_action(payload["user_id"], f"Deletou usuário '{user_id_to_delete}'")
    print(f"Usuário '{user_id_to_delete}' deletado.")
    return True

# --- Monitoramento simples ---
SUSPICIOUS_ACTIVITY = {}

def monitor_activity(user_id, action):
    SUSPICIOUS_ACTIVITY.setdefault(user_id, []).append((action, time.time()))
    # Simples: se mais de 5 ações em 10 seg, alerta
    actions = SUSPICIOUS_ACTIVITY[user_id]
    recent = [t for a, t in actions if time.time() - t < 10]
    if len(recent) > 5:
        print(f"Alerta: atividade suspeita detectada para usuário {user_id}!")

# --- Demonstração simples ---
if __name__ == "__main__":
    print("== Autenticação ==")
    user = "user1"
    pwd = "senha123"

    if authenticate(user, pwd):
        code = input("Digite o código MFA enviado: ")
        token = mfa_login(user, code)
        if token:
            print(f"Login OK! Token JWT: {token}")

            print("\n== Dados do usuário ==")
            get_user_data(token, user)

            print("\n== Atualizando email ==")
            new_email = input("Digite novo email: ")
            update_user_email(token, user, new_email)

            print("\n== Tentativa de exclusão por usuário comum ==")
            delete_user(token, "user1")  # deve falhar

            print("\n== Login admin para deletar usuário ==")
            if authenticate("admin", "adminpass"):
                code_admin = input("Digite o código MFA para admin: ")
                token_admin = mfa_login("admin", code_admin)
                if token_admin:
                    delete_user(token_admin, "user1")
        else:
            print("Falha na verificação MFA.")
    else:
        print("Autenticação falhou.")

