import socket
import threading
import sys

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if not message:
                break
            print(message)
        except:
            print("Desconectado do servidor.")
            break

def main():
    host = "10.9.8.69"
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Lendo a primeira mensagem (solicitação do nome)
    sys.stdout.write(client_socket.recv(1024).decode("utf-8"))
    sys.stdout.flush()
    
    name = input()
    client_socket.send(name.encode("utf-8"))

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    while True:
        try:
            message = input()
            client_socket.send(message.encode("utf-8"))
            if message == "/quit":
                break
        except:
            break

    client_socket.close()

if __name__ == "__main__":
    main()
