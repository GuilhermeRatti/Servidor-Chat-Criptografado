import socket
import ssl
import threading

def receber_mensagens(conn):
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("\nMensagem recebida:", data.decode('utf-8'))
    except Exception as e:
        print("Erro ao receber mensagens:", e)
    finally:
        conn.close()

def main():
    host = '10.9.8.122'
    port = 12345

    # Cria um contexto SSL para o cliente
    context = ssl.create_default_context(cafile="server.crt")
    # Para testes, desabilitamos a verificação do certificado e hostname
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(raw_socket, server_hostname=host)
    conn.connect((host, port))
    print("Conectado ao servidor com SSL.")

    # Thread para receber mensagens continuamente
    thread_recebedor = threading.Thread(target=receber_mensagens, args=(conn,))
    thread_recebedor.daemon = True
    thread_recebedor.start()

    try:
        while True:
            mensagem = input("Digite sua mensagem (ou vazio para sair): ")
            if not mensagem:
                break
            conn.send(mensagem.encode('utf-8'))
    except Exception as e:
        print("Erro:", e)
    finally:
        conn.close()
        print("Conexão encerrada.")

if __name__ == '__main__':
    main()
