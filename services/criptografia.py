### app/services/criptografia.py
from cryptography.fernet import Fernet

class Criptografia:
    def __init__(self, chave: bytes = None):
        self.chave = chave or Fernet.generate_key()
        self.cipher = Fernet(self.chave)

    def criptografar(self, dados: bytes) -> bytes:
        return self.cipher.encrypt(dados)

    def descriptografar(self, dados_criptografados: bytes) -> bytes:
        return self.cipher.decrypt(dados_criptografados)
