### app/services/auditoria.py
import logging

class Auditoria:
    def __init__(self, arquivo_log: str = "auditoria.log"):
        logging.basicConfig(filename=arquivo_log, level=logging.INFO)

    def registrar(self, usuario: str, acao: str):
        logging.info(f'Usuário: {usuario} - Ação: {acao}')