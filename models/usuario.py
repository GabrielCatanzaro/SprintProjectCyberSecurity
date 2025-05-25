### app/models/usuario.py
from werkzeug.security import generate_password_hash, check_password_hash

class Usuario:
    def __init__(self, email: str, senha: str):
        self.email = email
        self.senha_hash = self._gerar_hash(senha)

    def _gerar_hash(self, senha: str) -> str:
        return generate_password_hash(senha)

    def verificar_senha(self, senha: str) -> bool:
        return check_password_hash(self.senha_hash, senha)