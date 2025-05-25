import re
import secrets
import hmac
from getpass import getpass
from passlib.hash import pbkdf2_sha256 as hasher
from banco import Banco

class UserManager:
    """
    Lógica de negócio:
     - validação de username, senha e e‑mail
     - registro (gera hash, token 2FA e chama Banco.insert_user)
     - login (verifica hash + token 2FA)
     - listagem, consulta de passkey, atualização e exclusão (apenas admin)
    """

    USER_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
    PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@#$%^&+=]{6,}$")
    EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

    ADMIN_CODE = "123"  # código fixo de administrador para teste

    def __init__(self):
        self.db = Banco()

    def _validate_credentials(self, username: str, password: str, email: str) -> bool:
        if not self.USER_REGEX.fullmatch(username):
            print("[ERRO] Nome de usuário inválido. Use 3–20 letras, dígitos ou underscore.")
            return False

        if not self.PASSWORD_REGEX.fullmatch(password):
            print("[ERRO] Senha fraca. Deve ter ≥6 caracteres, incluir letras e números.")
            return False

        if not self.EMAIL_REGEX.fullmatch(email):
            print("[ERRO] E‑mail inválido.")
            return False

        return True

    def register_user(self, username: str, password: str, email: str, is_admin: bool = False) -> bool:
        """
        Registra um usuário. Se is_admin=True, pede o código ADMIN_CODE
        para validar. Retorna True se o registro ocorreu, ou False caso falhe.
        """
        # 1) Verifica se já existe
        if self.db.get_user(username) is not None:
            print(f"[ERRO] Já existe usuário com nome '{username}'.")
            return False

        # 2) Validação de formato
        if not self._validate_credentials(username, password, email):
            return False

        # 3) Se quiser ser admin, valida o código
        if is_admin:
            code = getpass("Digite o código de administrador para validar: ").strip()
            if code != self.ADMIN_CODE:
                print("[ERRO] Código de administrador inválido. Cadastro abortado.")
                return False

        # 4) Gera hash de senha e token 2FA
        password_hash = hasher.hash(password)
        token_2fa = secrets.token_hex(16)

        # 5) Insere no banco
        self.db.insert_user(username, password_hash, email, is_admin, token_2fa)

        print(f"[REGISTRADO] Usuário '{username}' criado com sucesso.")
        print(f"           Token 2FA (anote para login): {token_2fa}")
        return True

    def login(self, username: str, password: str, token_2fa: str) -> dict or None:
        """
        Tenta autenticar:
         - verifica se existe
         - confere hash da senha
         - confere token 2FA
        Se tudo OK, retorna {'username': ..., 'is_admin': True/False}.
        Caso contrário, retorna None.
        """
        row = self.db.get_user(username)
        if row is None:
            print("[ERRO] Usuário não encontrado.")
            return None

        stored_hash = row[1]
        is_admin_int = row[3]
        stored_token = row[4]

        if not hasher.verify(password, stored_hash):
            print("[ERRO] Senha incorreta.")
            return None

        if not hmac.compare_digest(token_2fa, stored_token):
            print("[ERRO] Token 2FA inválido.")
            return None

        print(f"[LOGIN] Bem‑vindo, {username}!")
        return {'username': username, 'is_admin': bool(is_admin_int)}

    def list_users(self) -> None:
        """
        Imprime todos os usuários cadastrados (com e‑mail descriptografado).
        """
        lista = self.db.list_users()
        if not lista:
            print("[INFO] Nenhum usuário cadastrado ainda.")
            return

        print("\n[USUÁRIOS CADASTRADOS]:")
        for username, email, is_admin in lista:
            role = "(admin)" if is_admin else ""
            print(f" - {username} {role} | E-mail: {email}")
        print()  # linha em branco no final

    def get_passkey(self, username: str) -> str or None:
        """
        Retorna o token 2FA do usuário (ou None se não existir).
        """
        row = self.db.get_user(username)
        if row is None:
            return None
        return row[4]  # token_2fa

    def update_user_interactive(self, target: str) -> None:
        """
        Faz um fluxo interativo para o admin atualizar:
         - senha
         - e‑mail
         - is_admin (se for alterar de False -> True, valida ADMIN_CODE novamente)
        """
        row = self.db.get_user(target)
        if row is None:
            print(f"[ERRO] Usuário '{target}' não encontrado.")
            return

        print(f"\n[ATUALIZAÇÃO] Usuário: {target}")
        # --- Alterar senha? ---
        alterar_senha = input("Deseja alterar a senha? (s/n): ").strip().lower() == 's'
        new_password_hash = None
        if alterar_senha:
            nova_senha = getpass("Nova senha: ")
            # Poderíamos validar contra PASSWORD_REGEX novamente, mas aqui vamos assumir que o admin sabe a regra
            if not self.PASSWORD_REGEX.fullmatch(nova_senha):
                print("[ERRO] Senha fraca. Atualização de senha cancelada.")
            else:
                new_password_hash = hasher.hash(nova_senha)

        # --- Alterar e‑mail? ---
        alterar_email = input("Deseja alterar o e‑mail? (s/n): ").strip().lower() == 's'
        new_email = None
        if alterar_email:
            email_digitado = input("Digite o novo e‑mail: ").strip()
            if not self.EMAIL_REGEX.fullmatch(email_digitado):
                print("[ERRO] E‑mail inválido. Atualização de e‑mail cancelada.")
            else:
                new_email = email_digitado

        # --- Alterar permissão de admin? ---
        alterar_admin = input("Deseja alterar permissão de admin? (s/n): ").strip().lower() == 's'
        new_is_admin = None
        if alterar_admin:
            atual_is_admin = bool(row[3])
            if atual_is_admin:
                # Se já for admin, pode despromover sem código
                reduzir = input("Remover permissão de admin deste usuário? (s/n): ").strip().lower() == 's'
                if reduzir:
                    new_is_admin = False
            else:
                # Se não for admin, para promover, valida o código
                promover = input("Promover para admin? (s/n): ").strip().lower() == 's'
                if promover:
                    code = getpass("Digite o código de administrador para promover: ").strip()
                    if code != self.ADMIN_CODE:
                        print("[ERRO] Código de administrador inválido. Não promoveu.")
                    else:
                        new_is_admin = True

        # Se nada para atualizar
        if new_password_hash is None and new_email is None and new_is_admin is None:
            print("[INFO] Nenhuma alteração solicitada. Nada foi modificado.")
            return

        # Chama o método de atualização do Banco
        sucesso = self.db.update_user(
            username=target,
            new_password_hash=new_password_hash,
            new_email_plain=new_email,
            new_is_admin=new_is_admin
        )
        if sucesso:
            print(f"[SUCESSO] Usuário '{target}' atualizado com sucesso.")
        else:
            print(f"[ERRO] Falha na atualização de '{target}' (usuário não existe).")

    def delete_user(self, target: str) -> None:
        """
        Deleta o usuário alvo. Se não existir, exibe erro.
        """
        row = self.db.get_user(target)
        if row is None:
            print(f"[ERRO] Usuário '{target}' não encontrado.")
            return

        confirm = input(f"Tem certeza que deseja excluir '{target}'? (s/n): ").strip().lower()
        if confirm != 's':
            print("[INFO] Exclusão cancelada.")
            return

        sucesso = self.db.delete_user(target)
        if sucesso:
            print(f"[DELETADO] Usuário '{target}' removido do sistema.")
        else:
            print(f"[ERRO] Falha ao deletar '{target}'. (talvez não exista)")



def main():
    manager = UserManager()
    session_user = None  # armazena {'username': ..., 'is_admin': ...} após login

    while True:
        print("\n=== MENU ===")
        print("1. Login")
        print("2. Registrar novo usuário")
        print("3. Listar usuários cadastrados (admin)")
        print("4. Consultar passkey de usuário (admin)")
        print("5. Atualizar cadastro de usuário (admin)")
        print("6. Deletar usuário (admin)")
        print("7. Sair")

        choice = input("Escolha uma opção: ").strip()

        # ====== 1. LOGIN ======
        if choice == '1':
            u = input("Usuário: ").strip()
            p = getpass("Senha: ")
            t = input("Token 2FA: ").strip()

            user_dict = manager.login(u, p, t)
            if user_dict:
                session_user = user_dict
            # em caso de falha, session_user permanece o mesmo (ou None)

        # ====== 2. REGISTRAR USUÁRIO ======
        elif choice == '2':
            u = input("Novo nome de usuário: ").strip()
            e = input("E‑mail: ").strip()
            p = getpass("Senha: ")
            quer_admin = input("Deseja registrar como admin? (s/n): ").strip().lower() == 's'

            success = manager.register_user(u, p, e, quer_admin)
            if not success:
                print("[INFO] Registro não concluído. Voltando ao menu.")
            else:
                print("[INFO] Registro concluído. Você pode fazer login agora.")

        # ====== 3. LISTAR USUÁRIOS (SOMENTE ADMIN) ======
        elif choice == '3':
            if session_user is None or not session_user['is_admin']:
                print("[ERRO] Acesso negado. Somente administradores podem listar usuários.")
            else:
                manager.list_users()

        # ====== 4. CONSULTAR PASSKEY (SOMENTE ADMIN) ======
        elif choice == '4':
            if session_user is None or not session_user['is_admin']:
                print("[ERRO] Acesso negado. Somente administradores podem consultar passkeys.")
            else:
                alvo = input("Digite o nome de usuário para consultar passkey: ").strip()
                key = manager.get_passkey(alvo)
                if key:
                    print(f"[PASSKEY] Usuário '{alvo}' – Token 2FA: {key}")
                else:
                    print(f"[ERRO] Usuário '{alvo}' não encontrado.")

        # ====== 5. ATUALIZAR CADASTRO (SOMENTE ADMIN) ======
        elif choice == '5':
            if session_user is None or not session_user['is_admin']:
                print("[ERRO] Acesso negado. Somente administradores podem atualizar cadastros.")
            else:
                alvo = input("Digite o nome de usuário para atualizar: ").strip()
                manager.update_user_interactive(alvo)

        # ====== 6. DELETAR USUÁRIO (SOMENTE ADMIN) ======
        elif choice == '6':
            if session_user is None or not session_user['is_admin']:
                print("[ERRO] Acesso negado. Somente administradores podem deletar usuários.")
            else:
                alvo = input("Digite o nome de usuário para deletar: ").strip()
                manager.delete_user(alvo)

        # ====== 7. SAIR ======
        elif choice == '7':
            print("Encerrando o sistema. Até mais!")
            break

        # ====== OPÇÃO INVÁLIDA ======
        else:
            print("[ERRO] Opção inválida. Tente novamente.")


if __name__ == "__main__":
    main()
