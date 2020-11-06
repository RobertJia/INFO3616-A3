import socket
import ssl
import time

hostname = "localhost"
port = 4433

# Handle application-layer messages (2cr)
def handle(conn):
    while True:
        # YOUR TASK STARTS HERE
        res = conn.recv().decode().strip()
        if (res=='PING'):
            conn.send(bytes('PONG\n', 'utf-8'))
    


def main():
    # Create a socket and correct context (3cr)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('server_cert.pem', 'server_key.pem')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind((hostname, port))
    sock.listen(5)
    print("Listening.")
    while True:
        conn = None
        try:
            # Final step to use the context ... (1cr)
            ssock = context.wrap_socket(sock, server_side=True)
            conn, addr = ssock.accept()
            handle(conn)
        except Exception as e:
            print(e)
        finally:
            if conn:
                conn.close()

main()
