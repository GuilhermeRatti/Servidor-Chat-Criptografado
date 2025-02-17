import socket
import ssl
import threading
import json
import logging
import argparse
import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QTextBrowser,
    QLineEdit, QPushButton, QLabel, QMessageBox
)
from PyQt6.QtCore import Qt, QDateTime

logger = logging.getLogger(__name__)

# Essa classe será utilizada somente para adicionar uma interface gráfica GUI inicial
# onde um nome de usuário será solicitado.
# Nomes de usuário serão ativamente trocados durante as conversas no chat.
class LoginDialog(QDialog):
    def __init__(self,conn):
        super().__init__()
        self.conn = conn
        self.setWindowTitle("Chat Login")
        self.setFixedSize(300, 150)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        self.username_label = QLabel("Enter your username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                font-size: 12pt;
                border: 2px solid #ccc;
                border-radius: 5px;
            }
        """)
        
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.validate_login)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addLayout(button_layout)
    
    def validate_login(self):
        username = self.username_input.text().strip()
        
        if not username:
            QMessageBox.warning(self, "Invalid Username", 
                               "Please enter a valid username!")
            return
        
        self.accept()

class ChatWindow(QMainWindow):
    def __init__(self,username,conn):
        super().__init__()
        self.username = username
        self.setWindowTitle(f"PyQt6 Chat - {self.username}")
        self.setGeometry(100, 100, 400, 500)
        self.conn = conn
        
        # Cria o widget central e o layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Cria o display histórico de chat
        self.chat_history = QTextBrowser()
        self.chat_history.setStyleSheet("""
            QTextBrowser {
                background-color: #ffffff;
                font-family: Arial;
                font-size: 12pt;
                padding: 2px;
                border: none;
            }
        """)
        layout.addWidget(self.chat_history)
        
        # Cria a caixa de texto de input
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Escreva sua mensagem aqui...")
        self.message_input.returnPressed.connect(self.send_message)

        input_layout.addWidget(self.message_input)
        
        self.send_button = QPushButton("Enviar")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)
        
        layout.addLayout(input_layout)
        
        # Uma mensagem inicial do servidor para ter um "feedback" visual de conexão feita com sucesso
        self.add_message("receive","Sistema", f"Bem vindo ao servidor de chat criptografado, {self.username}!")

        logger.info("Chat criado com sucesso.")
    
    def send_message(self):
        # método da classe GUI que trata o envio de mensagens ao servidor
        message = self.message_input.text().strip()
        if message:
            # Adiciona a mensagem escrita no histórico de mensagens e limpa a caixa de texto de entrada
            self.add_message("send",self.username, message)
            self.message_input.clear()
            
            # Toda mensagem a ser enviada para o servidor de chat é encapsulada em um dicionário e processada pela biblioteca json
            # Dessa forma, cada mensagem estará associada à um nome de usuário.
            message_dictionary = {"sender": self.username, "message" : message}
            json_message = json.dumps(message_dictionary)
            try:
                self.conn.send(json_message.encode('utf-8'))
                logger.info(f"Usuario '{self.username}' enviou mensagem com sucesso: '{message}'")
            except Exception as error:
                logger.error(f"Usuario '{self.username}' teve erro ao enviar mensagem: {error}")
    
    def receive_message(self,received_conn): 
        # método da classe GUI que trata o recebimento de mensagens de qualquer outro cliente conectado ao servidor
        try:
            while True:
                data = received_conn.recv(1024)
                if not data:
                    break
                data_dictionary = json.loads(data.decode('utf-8'))
                sender = data_dictionary["sender"]
                message = data_dictionary["message"]
                self.add_message("receive",sender, message)
                logger.info(f"Usuario '{self.username}' recebeu uma mensagem com sucesso: '{message}'")

        except Exception as error:
            logger.error(f"Usuario '{self.username}' teve erro ao receber mensagens:{error}")
        finally:
            received_conn.close()

    def add_message(self, type, sender, message):
        timestamp = QDateTime.currentDateTime().toString("hh:mm")
        alignment = "right" if type == "send" else "left"
        color = "#666" if sender == "System" else "#444"
        
        if alignment == "right":
            bubble_style = (
                "background-color: #DCF8C6;"
                "border-radius: 10px;"
                "padding: 8px;"
                "margin: 5px 20px 5px 50px;"
            )
            container_style = "display: flex; justify-content: flex-end;"
        else:
            bubble_style = (
                "background-color: #E8E8E8;"
                "border-radius: 10px;"
                "padding: 8px;"
                "margin: 5px 50px 5px 20px;"
            )
            container_style = "display: flex; justify-content: flex-start;"

        formatted_message = (
            f"<br>"
            f"<div></div><div style='{container_style}'>"
            f"<div style='{bubble_style}'>"
            f"<section style='color: {color}; font-weight: bold;'>{sender}:  </section>"
            f"<section style='color: #333; margin-top: 5px;'>{message}</section>"
            f"<section style='color: #999; font-size: small; margin-top: 5px; text-align: right;'> {timestamp}</section>"
            f"</div></div> <br>"
        )

        self.chat_history.append(formatted_message)
        self.chat_history.verticalScrollBar().setValue(
            self.chat_history.verticalScrollBar().maximum()
        )


def main(args):
    host = args.ip
    port = args.p

    TIME_FORMAT = '%a %b %-d %Y %-I:%M:%S %p'
    logformat = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'                             
    
    open('cliente.log', 'w').close() #clearing content from logger

    logging.basicConfig(filename='cliente.log', filemode='a', format=logformat, level=logging.INFO, encoding='utf-8')
    logger.info('Inicializando...')

    try:
        # Cria um contexto SSL para o cliente
        context = ssl.create_default_context(cafile="server.crt")
        # Para testes, desabilitamos a verificação do certificado e hostname
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = context.wrap_socket(raw_socket, server_hostname=host)
        conn.connect((host, port))
        logger.info("Conectado ao servidor com SSL.")
    except Exception as error:
        logger.error(f"Erro ao se conectar com o servidor! Error: {error}")
        raise(error)
    
    app = QApplication(sys.argv)
    login_dialog = LoginDialog(conn)
    if login_dialog.exec() != QDialog.DialogCode.Accepted:
        sys.exit()

    username = login_dialog.username_input.text().strip()
    logger.info(f"Usuario {username} criado com sucesso.")

    window = ChatWindow(username,conn)

    # Thread para receber mensagens continuamente
    thread_recebedor = threading.Thread(target=window.receive_message, args=(conn,))
    thread_recebedor.daemon = True
    thread_recebedor.start()

    logger.info("Thread criada com sucesso.")

    window.show()
    sys.exit(app.exec())
    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
    prog='python3 cliente.py',
    description = 'Esse programa levanta um cliente usuario do servidor de chat.\
        É necessário executar o código do servidor antes de executar qualquer cliente.\n\
        O cliente que deseja se conectar com um servidor também deve usar o mesmo ip:porta (p),\
        É possível definir ips e portas específicos usando argumentos neste código.\n',
    )

    parser.add_argument('-ip',
                        help='IP do servidor a ser conectado. Favor colocar apenas IPs válidos. Valor padrão é o local host: 127.0.0.1',
                        default='127.0.0.1',
                        type=str)

    parser.add_argument('-p', 
                        help='Porta que será utilizada pelo servidor. Valor padrão para porta é 12345', 
                        default='12345',
                        type=int)
                        
    args = parser.parse_args()
    main(args)