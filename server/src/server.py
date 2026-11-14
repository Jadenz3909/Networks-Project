import socket, threading, os, hashlib, hmac, json, logging, login_info
from login_info import SCRYPT_PARAMS
from dotenv import load_dotenv

load_dotenv()

HOST = socket.gethostbyname(socket.gethostname())
PORT = int(os.getenv("SERVER_PORT", 5678))


def authenticate_user(args: dict) -> bool:
    try:
        username = args.get("username")
        password = args.get("password")
        if not username or not password:
            return False
        if not (isinstance(username, str) and isinstance(password, str)):
            return False
        if username not in login_info.user_hash:
            hashlib.scrypt(password.encode(), salt=os.urandom(16), n=SCRYPT_PARAMS.N, r=SCRYPT_PARAMS.R, p=SCRYPT_PARAMS.P)
            return False
        return hmac.compare_digest(login_info.user_hash[username]["hash"], hashlib.scrypt(password.encode(), salt=login_info.user_hash[username]["salt"], n=SCRYPT_PARAMS.N, r=SCRYPT_PARAMS.R, p=SCRYPT_PARAMS.P))
    except Exception: return False


def handle_auth(conn: socket.socket, addr: tuple) -> bool:
    try:
        conn.settimeout(5)
        logging.info(f"Client connected on {addr}")
        try:
            buf = conn.recv(4096)
        except socket.timeout:
            conn.sendall(b"408")
            logging.warning(f"client timeout {addr = }")
            return False
        if not buf:
            logging.warning(f"client connection terminated {addr = }")
            return False
        try:
            client_data = json.loads(buf)
        except Exception:
            conn.sendall(b"401")
            logging.warning(f"invalid data received {addr = }")
            return False
        if not authenticate_user(client_data):
            conn.sendall(b"401")
            logging.warning(f"incorrect username or password {addr = }")
            return False
        conn.settimeout(None)
        conn.sendall(b"200")
        logging.info(f"Client authenticated successfully on user {client_data["username"]} {addr = }")
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False
    return True


def handle_client(conn: socket.socket, addr: tuple):
    try:
        if not handle_auth(conn, addr):
            return
        
    finally:
        conn.close()


def main() -> None:
    login_info.create_dummy_users()
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