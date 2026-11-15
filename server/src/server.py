import socket, threading, os, hashlib, hmac, json, logging, tempfile, login_info
from pathlib import Path
from login_info import SCRYPT_PARAMS
from dotenv import load_dotenv

load_dotenv()

BASE = Path(__file__).parent / "storage"
ROOT = (BASE / "root").resolve()
TMP = (BASE / "tmp").resolve()
HOST = socket.gethostbyname(socket.gethostname())
PORT = int(os.getenv("SERVER_PORT", 5678))


def safe_path(raw: str) -> Path:
    try:
        if not isinstance(raw, str):
            raise ValueError(f"invalid input {type(raw) = }")
        if "\x00" in raw or ":" in raw:
            raise ValueError(f"invalid character in input")
        for invalid_char in r':*?"<>|':
            if invalid_char in raw:
                raise ValueError(f"invalid character in input")
        path = (ROOT / raw.lstrip("/\\")).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("path exists above root")
        return path
    except OSError:
        raise ValueError("invalid name")


def init_filesystem():
    ROOT.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)


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


def receive_file(conn: socket.socket, addr: tuple, file_path: Path, file_size: int) -> bool:
    bytes_received = 0
    upload_success = False
    tmp_path: Path | None = None
    conn.settimeout(5)
    try:
        fd, tmp_name = tempfile.mkstemp(suffix=".tmp", prefix=".upload_", dir=TMP)
        tmp_path = Path(tmp_name)
        hash = hashlib.sha256()
        with os.fdopen(fd, "wb") as file:
            while bytes_received < file_size:
                buf = conn.recv(min(4096, file_size - bytes_received))
                if buf == b"":
                    logging.warning(f"client connection terminated")
                    return False
                file.write(buf)
                hash.update(buf)
                bytes_received += len(buf)
        buf = conn.recv(4096)
        if not hmac.compare_digest(buf.strip(), hash.hexdigest().encode()):
            logging.warning("digest compare failed for uploaded file")
            conn.sendall(b"422")
            return True
        os.replace(tmp_path, file_path)
        upload_success = True
        logging.info("data received successfully")
        conn.sendall(b"201")
        return True
    except socket.timeout:
        logging.warning(f"client timeout {addr = }")
        return False
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False
    finally:
        if not upload_success:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
        

def handle_recv(conn: socket.socket, addr: tuple, input_: dict) -> bool:
    try:
        if not (input_.get("file_name") and input_.get("file_size_bytes") and input_.get("dir")):
            logging.warning(f"upload cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not (isinstance(input_["file_name"], str) and isinstance(input_["file_size_bytes"], int) and isinstance(input_["dir"], str)):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        for invalid_char in r'\/:*?"<>|':
            if invalid_char in input_["file_name"]:
                logging.warning(f"invalid character in file name {invalid_char = }")
                conn.sendall(b"400")
                return True
        if input_["file_name"] in ["..", ".", ""] or "\x00" in input_["file_name"]:
            logging.warning(f"invalid file name = {input_["file_name"]}")
            conn.sendall(b"400")
            return True
        try:
            path = safe_path(input_["dir"])
        except ValueError:
            logging.warning("unsafe path detected")
            conn.sendall(b"400")
            return True    
        if not path.is_dir():
            logging.warning(f"dir does not exist")
            conn.sendall(b"404")
            return True
        if (path / input_["file_name"]).is_file():
            logging.info(f"file '{input_["file_name"]}' exists, sending overwrite confirmation")
            try:
                conn.settimeout(10)
                conn.sendall(b"300")
                buf = conn.recv(4096)
            except socket.timeout:
                logging.warning(f"connection timed out {addr = }")
                return False
            conn.settimeout(None)
            try:
                response = json.loads(buf)
            except json.JSONDecodeError:
                logging.warning("client response could not be parsed")
                return False
            if not isinstance(response, dict):
                logging.warning("invalid response")
                return False
            if not response.get("overwrite") is True:
                conn.sendall(b"204")
                logging.info(f"overwrite declined")
                return True
        conn.sendall(b"100")
        return receive_file(conn, addr, path / input_["file_name"], input_["file_size_bytes"])
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False

def handle_client(conn: socket.socket, addr: tuple):
    try:
        if not handle_auth(conn, addr) == True:
            return
        data = b""
        while True:
            buf = conn.recv(4096)
            data += buf
            if data.endswith(b"\n"):
                parsed = json.loads(data)
                if not parsed.get("cmd"):
                    break
                else: handle_recv(conn, addr, parsed) # temporary, always use handle_recv even if its a different cmd
                data = b""
    finally:
        conn.close()


def main() -> None:
    init_filesystem()
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