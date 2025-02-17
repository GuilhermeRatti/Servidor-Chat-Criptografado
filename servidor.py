import socket
import ssl
import threading
import json
import logging
import argparse
# Lista global para armazenar as conexões ativas
clientes = []
# Lock para sincronizar o acesso à lista de clientes
clientes_lock = threading.Lock()

logger = logging.getLogger(__name__)

def broadcast(mensagem, origem):
    """
    Envia a mensagem para todos os clientes conectados, exceto o que enviou a mensagem.
    """
    with clientes_lock:
        for cliente, addr in clientes:
            # Opcional: não enviar para o cliente que originou a mensagem
            if cliente != origem:
                try:
                    cliente.sendall(mensagem)
                except Exception as error:
                    logger.error(f"Erro ao enviar para {addr}: {error}")

def handle_client(conn, addr):
    logger.info(f"[{addr}] Conexão estabelecida.")
    # Adiciona a conexão à lista de clientes
    with clientes_lock:
        clientes.append((conn, addr))
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            mensagem = data.decode('utf-8')
            loaded_message = json.loads(mensagem)
            texto = loaded_message["message"]
            user = loaded_message["sender"]
            logger.info(f"[{addr}] Mensagem recebida de '{user}': {texto}")
            # Envia a mensagem para todos os outros clientes
            broadcast(data, conn)
    except Exception as error:
        logger.error(f"[{addr}] Erro: {error}")
    finally:
        # Remove a conexão da lista de clientes ao desconectar
        with clientes_lock:
            clientes.remove((conn, addr))
        conn.close()
        logger.info(f"[{addr}] Conexão encerrada.")

def main(args):

    host = args.ip
    port = args.p

    TIME_FORMAT = '%a %b %-d %Y %-I:%M:%S %p'
    logformat = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'                           
    
    open('servidor.log', 'w').close() #clearing content from logger

    logging.basicConfig(filename='servidor.log', filemode='a', format=logformat, level=logging.INFO, encoding='utf-8')
    logger.info('Inicializando...')

    try:
        # Cria um contexto SSL para o servidor
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')

        # Cria o socket TCP
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.bind((host, port))
        bindsocket.listen(5)
        logger.info(f"Servidor rodando em {host}:{port}")
    except Exception as error:
        logger.error(f"Servidor encontrou um erro ao tentar levantar um socket: {error}")
        return
    
    while True:
        newsocket, fromaddr = bindsocket.accept()
        try:
            # Envolvendo o socket com SSL para criptografia
            connstream = context.wrap_socket(newsocket, server_side=True)
        except ssl.SSLError as e:
            logger.error("Erro na conexão SSL:", e)
            continue
        
        # Cria uma thread para tratar cada cliente de forma paralela
        thread = threading.Thread(target=handle_client, args=(connstream, fromaddr))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
    prog='python3 cliente.py',
    description = 'Esse programa levanta um servidor de chat.\
        É necessário executar este código de servidor antes de executar qualquer cliente.\n\
        O cliente que deseja se conectar com um servidor deve usar o mesmo ip:porta (p),\
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
