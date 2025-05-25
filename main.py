from models.usuario import Usuario
from services.criptografia import Criptografia
from services.auditoria import Auditoria
from security.jwt_manager import JWTManager

if __name__ == "__main__":
    usuario = Usuario("teste@exemplo.com", "senha123")

    criptografia = Criptografia()
    senha_criptografada = criptografia.criptografar(b"senha123")
    senha_original = criptografia.descriptografar(senha_criptografada)

    auditoria = Auditoria()
    auditoria.registrar(usuario.email, "Login bem-sucedido")

    jwt_manager = JWTManager("segredo_super_secreto")
    token = jwt_manager.gerar_token("123")

    print("Usuário válido:", usuario.verificar_senha("senha123"))
    print("Senha criptografada:", senha_criptografada)
    print("Senha original:", senha_original)
    print("Token JWT:", token)

