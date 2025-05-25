### app/services/autenticacao.py
from models.usuario import Usuario

class Autenticacao:
    def __init__(self):
        self.usuarios = {}

    def registrar(self, email: str, senha: str) -> Usuario:
        if email in self.usuarios:
            raise Exception("Usuário já existe")
        usuario = Usuario(email, senha)
        self.usuarios[email] = usuario
        return usuario

    def login(self, email: str, senha: str) -> bool:
        usuario = self.usuarios.get(email)
        return usuario.verificar_senha(senha) if usuario else False