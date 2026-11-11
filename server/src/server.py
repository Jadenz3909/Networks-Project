import socket, threading, os
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("SERVER_HOST")
PORT = os.getenv("SERVER_PORT")

def handle_client(conn, addr):
    try:
        print(f"Client connected on {addr}")
    finally:
        socket.close(conn)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _socket:
        _socket.bind((HOST, PORT))
        _socket.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = _socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        

if __name__ == "__main__":
    main()