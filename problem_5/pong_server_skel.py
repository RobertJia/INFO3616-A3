import socket
import ssl
import time

hostname = "localhost"
port = 4433

# Handle application-layer messages (2cr)
def handle(conn):
    while True:
        # YOUR TASK STARTS HERE
        ...



def main():
    # Create a socket and correct context (3cr)
    # ...
    print("Listening.")
    while True:
        conn = None
        ssock, addr = sock.accept()
        try:
            # Final step to use the context ... (1cr)
            # ...
            handle(conn)
        except Exception as e:
            print(e)
        finally:
            if conn:
                conn.close()

main()
