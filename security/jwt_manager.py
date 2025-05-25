### app/security/jwt_manager.py
import security.jwt_manager as jwt_manager
import datetime

class jwt_manager:
    def __init__(self, segredo: str, expiracao_horas: int = 2):
        self.segredo = segredo
        self.expiracao_horas = expiracao_horas

    def gerar_token(self, usuario_id: str) -> str:
        payload = {
            'id': usuario_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=self.expiracao_horas)
        }
        return jwt_manager.encode(payload, self.segredo, algorithm='HS256')

    def verificar_token(self, token: str):
        try:
            return jwt_manager.decode(token, self.segredo, algorithms=['HS256'])
        except jwt_manager.ExpiredSignatureError:
            return None
