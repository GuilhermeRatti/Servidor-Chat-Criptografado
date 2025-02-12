import socket
import ssl
import threading

# Lista global para armazenar as conexões ativas
clientes = []
# Lock para sincronizar o acesso à lista de clientes
clientes_lock = threading.Lock()

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
                except Exception as e:
                    print(f"Erro ao enviar para {addr}: {e}")

def handle_client(conn, addr):
    print(f"[{addr}] Conexão estabelecida.")
    # Adiciona a conexão à lista de clientes
    with clientes_lock:
        clientes.append((conn, addr))
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            mensagem = data.decode('utf-8')
            print(f"[{addr}] Mensagem recebida: {mensagem}")
            # Envia a mensagem para todos os outros clientes
            broadcast(data, conn)
    except Exception as e:
        print(f"[{addr}] Erro: {e}")
    finally:
        # Remove a conexão da lista de clientes ao desconectar
        with clientes_lock:
            clientes.remove((conn, addr))
        conn.close()
        print(f"[{addr}] Conexão encerrada.")

def main():
    host = '10.9.8.122'
    port = 12345

    # Cria um contexto SSL para o servidor
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')

    # Cria o socket TCP
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"Servidor rodando em {host}:{port}")

    while True:
        newsocket, fromaddr = bindsocket.accept()
        try:
            # Envolvendo o socket com SSL para criptografia
            connstream = context.wrap_socket(newsocket, server_side=True)
        except ssl.SSLError as e:
            print("Erro na conexão SSL:", e)
            continue
        # Cria uma thread para tratar cada cliente de forma paralela
        thread = threading.Thread(target=handle_client, args=(connstream, fromaddr))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    main()
