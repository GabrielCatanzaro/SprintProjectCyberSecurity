import sqlite3
from cryptography.fernet import Fernet
import os

class CryptoManager:
    """
    Responsável por gerar/carregar a chave Fernet e
    criptografar/descriptografar strings (e‑mail).
    """
    def __init__(self, key_path: str = "secret.key"):
        self.key_path = key_path
        self.key = self._load_or_create_key()
        self.fernet = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(self.key_path, "wb") as f:
            f.write(key)
        return key

    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self.fernet.decrypt(token.encode()).decode()


class Banco:
    """
    Classe que gerencia toda a lógica de acesso ao SQLite:
      - criação da tabela
      - inserção de usuários
      - obtenção de dados de usuário
      - listagem de usuários (descriptografando o e‑mail)
      - atualização de usuário (senha, e‑mail, is_admin)
      - exclusão de usuário
    """
    def __init__(self, db_path: str = "users.db"):
        self.conn = sqlite3.connect(db_path)
        self.crypto = CryptoManager()
        self._create_table()

    def _create_table(self):
        """
        Cria a tabela 'users' (caso não exista):
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email_encrypted TEXT NOT NULL,
            is_admin INTEGER NOT NULL,
            token_2fa TEXT NOT NULL
        """
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username         TEXT PRIMARY KEY,
                password_hash    TEXT NOT NULL,
                email_encrypted  TEXT NOT NULL,
                is_admin         INTEGER NOT NULL,
                token_2fa        TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def insert_user(
        self,
        username: str,
        password_hash: str,
        email_plain: str,
        is_admin: bool,
        token_2fa: str
    ) -> None:
        """
        Insere um novo usuário na tabela, criptografando o e‑mail
        e convertendo is_admin para inteiro (0 ou 1).
        """
        email_encrypted = self.crypto.encrypt(email_plain)
        self.conn.execute("""
            INSERT INTO users
            (username, password_hash, email_encrypted, is_admin, token_2fa)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            password_hash,
            email_encrypted,
            1 if is_admin else 0,
            token_2fa
        ))
        self.conn.commit()

    def get_user(self, username: str):
        """
        Retorna a tupla completa de dados do usuário:
          (username, password_hash, email_encrypted, is_admin, token_2fa)
        Ou None, se não existir.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return row

    def list_users(self) -> list:
        """
        Retorna uma lista de tuplas já com e‑mail descriptografado:
          [(username, email_decrypted, is_admin_bool), ...]
        """
        resultado = []
        for row in self.conn.execute("SELECT username, email_encrypted, is_admin FROM users"):
            username, email_encrypted, is_admin_int = row
            email_decrypted = self.crypto.decrypt(email_encrypted)
            resultado.append((username, email_decrypted, bool(is_admin_int)))
        return resultado

    def update_user(
        self,
        username: str,
        new_password_hash: str = None,
        new_email_plain: str = None,
        new_is_admin: bool = None
    ) -> bool:
        """
        Atualiza os campos fornecidos para o usuário 'username'.
        Se new_password_hash não for None, atualiza password_hash.
        Se new_email_plain não for None, criptografa e atualiza email_encrypted.
        Se new_is_admin não for None, atualiza is_admin (0/1).
        Retorna True se o usuário existia e a atualização foi feita, 
        ou False se o usuário não existe.
        """
        # Verifica se usuário existe
        row = self.get_user(username)
        if row is None:
            return False

        campos = []
        valores = []

        if new_password_hash is not None:
            campos.append("password_hash = ?")
            valores.append(new_password_hash)

        if new_email_plain is not None:
            email_encrypted = self.crypto.encrypt(new_email_plain)
            campos.append("email_encrypted = ?")
            valores.append(email_encrypted)

        if new_is_admin is not None:
            campos.append("is_admin = ?")
            valores.append(1 if new_is_admin else 0)

        # Se não for passada nenhuma atualização, não faz nada
        if not campos:
            return True  # nada a atualizar, mas usuário existe

        # Constrói a query dinamicamente
        sql = f"UPDATE users SET {', '.join(campos)} WHERE username = ?"
        valores.append(username)
        self.conn.execute(sql, tuple(valores))
        self.conn.commit()
        return True

    def delete_user(self, username: str) -> bool:
        """
        Exclui o usuário 'username'. Retorna True se algo foi deletado,
        ou False se o usuário não existia.
        """
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        self.conn.commit()
        return cursor.rowcount > 0
