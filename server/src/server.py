import socket, threading, os
from dotenv import load_dotenv

load_dotenv()

HOST = socket.gethostbyname(socket.gethostname())
PORT = int(os.getenv("SERVER_PORT", 5678))


def handle_client(conn: socket.socket, addr: socket._RetAddress):
    try:
        print(f"Client connected on {addr}")
    finally:
        conn.close()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _socket:
        _socket.bind((HOST, PORT))
        _socket.listen()
        _socket.settimeout(1)
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = _socket.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()