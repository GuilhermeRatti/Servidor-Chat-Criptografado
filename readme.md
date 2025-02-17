# Chat Server Application

Uma implementação simples de servidor de chat com um socket criptografado, aceitando múltiplos usuários clientes em uma única sala de chat. É permitido que vários usuários tenham o mesmo nome. A criptografia é feita de forma assimétrica, com o servidor tendo posse da chave privada e clientes tendo acesso à um certificado público. Essa aplicação utiliza Python e OpenSSL para demonstrar o processo de criptografia ponta a ponta (do cliente, para servidor e então para o resto dos clientes), de forma a proteger a mensagem em seu tráfego.

## Propriedades de destaque

- **Mensagens em tempo real:** Esse sistema dá suporte a múltiplos clientes conversando em uma única sala concomitantemente.
- **Criptografia Assimétrica:** Utiliza das tecnologias do OpenSSL para criptografar todas as mensagens de ponta a ponta, de forma que somente o servidor tenha acesso à chave de criptografia privada.
- **Servidor Multi-thread:** Cada conexão de um cliente tem sua própria thread para comunicação eficiente.
- **Setup Fácil:** Poucas linhas de comando simples para levantar tanto o servidor quanto clientes.

## Pré-requisitos

- Python 3.6 ou versões posteriores.
- Bibliotecas de python requisitadas:
  - [pyqt6](https://pypi.org/project/PyQt6/) para o design da interface gráfica (GUI).
  - [json](https://docs.python.org/3/library/json.html) para processar as mensagens de envio.
  - [socket](https://docs.python.org/3/library/socket.html) para manipular os sockets.
  - [threading](https://docs.python.org/3/library/threading.html) para manipular as threads de cada cliente.
  - [ssl](https://docs.python.org/3/library/ssl.html) para encapsular os sockets com criptografia.
  - [logging](https://docs.python.org/3/library/logging.html) para fazer o controle do fluxo da aplicação.
  - [argparse](https://docs.python.org/3/library/argparse.html) para permitir argumentos de entrada na linha de código.
- [OpenSSL](https://docs.openiam.com/docs-4.2.1.3/appendix/2-openssl) para a geração das chaves públicas e privadas.

### Instalando bibliotecas de python via pip:

```bash
pip install -r path/to/requirements.txt
```

### Instalando OpenSSL via terminal (ubuntu):

Instalando dependências:
```bash
sudo apt-get update && sudo apt-get upgrade
sudo apt install build-essential checkinstall zlib1g-dev -y
```

Instalando o OpenSSL:
```bash
sudo apt install openssl
```

## Uso
Para utilizar esta implementação, é imprescindível primeiro gerar uma chave com OpenSLL para criptografar suas mensagens:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -config server.cnf -extensions v3_req
```

O segundo passo é levantar o servidor de chat:

```bash
python3 servidor.py [ -ip IP_HOST ] [ -p PORTA ]
```

Argumentos do programa:
- IP_HOST: O endereço IP onde o servidor será hospedado. Se nenhum argumento for informado o localhost (127.0.0.1) será usado como padrão.
- PORTA: A porta que será utilizada pelo socket. Se nenhuma porta for especificada a porta 12345 será utilizada como padrão.

Por fim, deve-se executar a quantidade de clientes desejada para acessar o servidor de chat:

```bash
python3 cliente.py [ -ip IP_HOST ] [ -p PORTA ]
```

Os argumentos do cliente seguem o mesmo padrão especificado do servidor e devem ser idênticos ao do servidor levantado para que o cliente acesse corretamente o serviço. Caso o cliente tente acessar um IP e/ou uma porta não utilizados por um servidor, a aplicação resultará em erro.

## Visão Geral do Código



## Considerações de Segurança
    https://www.ibm.com/docs/en/hpvs/1.2.x?topic=SSHPMH_1.2.x/topics/create_ca_signed_certificates.htm


## Possiveis Melhorias
