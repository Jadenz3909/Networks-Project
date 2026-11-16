import socket, threading, os, hashlib, hmac, json, logging, tempfile, time, login_info
from pathlib import Path
from login_info import SCRYPT_PARAMS
from dotenv import load_dotenv

load_dotenv()

BASE = Path(__file__).parent / "storage"
ROOT = (BASE / "root").resolve()
TMP = (BASE / "tmp").resolve()
HOST = socket.gethostbyname(socket.gethostname())
PORT = int(os.getenv("SERVER_PORT", 5678))


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray(n)
    view = memoryview(buf)
    bytes_read = 0
    while bytes_read < 3:
        received = conn.recv_into(view[bytes_read:])
        if received == 0:
            raise OSError
    return bytes(buf)


def safe_path(raw: str) -> Path:
    """Check if a given path exits the boundaries of the ROOT folder or contains invalid characters.
    
    
    Args:
        raw (str): The path to check
    
        
    Returns:
        Path: The resolved path (removed of any ../. modifiers)
    
        
    Raises:
        ValueError: If the resolved path falls outside ROOT or if the resolved path contains invalid characters.
    """
    
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


def init_filesystem() -> None:
    """Creates filesystem folders if they don't exist."""
    ROOT.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)


def authenticate_user(args: dict) -> bool:
    """Authenticate whether a user's login information is valid compared against server-side login data.
    
    
    Args:
        args (dict): A dictionary containing the user's login information {'username': 'foo', 'password': 'bar'}
        
        
    Returns:
        bool: Whether the user's login information is valid
    """
    
    try:
        username = args.get("username")
        password = args.get("password")
        if not username or not password:
            logging.warning("username or password field messed up")
            return False
        if not (isinstance(username, str) and isinstance(password, str)):
            logging.warning(f"{username = } {password = }")
            return False
        if username not in login_info.user_hash:
            logging.warning(f"{username = } {password = }")
            hashlib.scrypt(password.encode(), salt=os.urandom(16), n=SCRYPT_PARAMS.N, r=SCRYPT_PARAMS.R, p=SCRYPT_PARAMS.P)
            return False
        logging.warning(f"{username = } {password = }")
        return hmac.compare_digest(bytes.fromhex(login_info.user_hash[username]["hash"]), hashlib.scrypt(password.encode(), salt=bytes.fromhex(login_info.user_hash[username]["salt"]), n=SCRYPT_PARAMS.N, r=SCRYPT_PARAMS.R, p=SCRYPT_PARAMS.P))
    except Exception as e: 
        logging.warning(e)
        return False


def handle_auth(conn: socket.socket, addr: tuple) -> bool:
    """Handles client authorization on connection.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
    
    try:
        conn.settimeout(5)
        logging.info(f"client connected on {addr}")
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
        logging.info(f"client authenticated successfully on user {client_data["username"]} {addr = }")
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False
    return True


def receive_file(conn: socket.socket, addr: tuple, file_path: Path, file_size: int) -> bool:
    """Receive a file from a connection and store it in file_path.
        
        
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        file_path (Path): The path where the received file should be stored
        file_size (int): The size of the received file in bytes
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
    
    bytes_received = 0
    upload_success = False
    tmp_path: Path | None = None
    conn.settimeout(5)
    try:
        fd, tmp_name = tempfile.mkstemp(suffix=".tmp", prefix=".upload_", dir=TMP)
        tmp_path = Path(tmp_name)
        local_hash = hashlib.sha256()
        with os.fdopen(fd, "wb") as file:
            while bytes_received < file_size:
                try:
                    buf = recv_exact(conn, (min(40000, file_size - bytes_received)))
                except OSError:
                    logging.warning(f"client connection terminated")
                    return False
                file.write(buf)
                local_hash.update(buf)
                bytes_received += len(buf)
                conn.sendall(b"100")
        buf = conn.recv(40000)
        recv_hash = buf
        while buf.endswith(b"\n"):
            buf = conn.recv(40000)
            recv_hash += buf
        if not hmac.compare_digest(recv_hash.strip(), local_hash.hexdigest().encode()):
            logging.warning("digest compare failed for uploaded file")
            conn.sendall(b"422")
            return True
        os.replace(tmp_path, file_path)
        upload_success = True
        logging.info("file received successfully")
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
    """Handles requests related to receiving files from the client.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        input_ (dict): A json containing the args sent by the client
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
    
    try:
        if not (input_.get("file_name") and input_.get("file_size_bytes") is not None and input_.get("dir", None) is not None):
            logging.warning(f"upload cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not (isinstance(input_["file_name"], str) and isinstance(input_["file_size_bytes"], int) and isinstance(input_["dir"], str)):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        size = input_["file_size_bytes"]
        if isinstance(size, bool) or not 0 <= size:
            logging.warning(f"invalid file {size = }")
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
                logging.info(f"overwrite declined")
                conn.sendall(b"204")
                return True
        conn.sendall(b"100")
        return receive_file(conn, addr, path / input_["file_name"], input_["file_size_bytes"])
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False


data_sent_bytes = {}
sent_time_seconds = {}
def add_send_time(client_addr: tuple, start: float, end: float, byte_ct: int = 40000) -> None:
    """Adds the send times to the global data send variables.
    
    
    Args:
        client_addr (tuple): The client's address
        start (float): The start time of when the data began sending
        end (float): The time at which the bytes were confirmed received by the client
    """
    
    global data_sent_bytes, sent_time_seconds
    data_sent_bytes[client_addr] += byte_ct
    sent_time_seconds[client_addr] = end - start


def clear_send_times(client_addr: tuple) -> None:
    global data_sent_bytes, sent_time_seconds
    data_sent_bytes[client_addr] = 0
    sent_time_seconds[client_addr] = 0
    
    
def calc_send_throughput(client_addr: tuple) -> float:
    global data_sent_bytes, sent_time_seconds
    if data_sent_bytes.get(client_addr) is None:
        raise ValueError("client not sent anything")
    return data_sent_bytes[client_addr] / sent_time_seconds[client_addr]

def get_data_sent(client_addr: tuple) -> int:
    global data_sent_bytes
    return data_sent_bytes[client_addr]


def send_file(conn: socket.socket, addr: tuple, path: Path) -> bool:
    """Sends a given file over a connection.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        path (Path): The path of the file to be sent
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
    
    try:
        logging.info(f"sending file at {path = } to client {addr = }")
        with open(path, "rb") as file:
            conn.sendfile(file)
            file.seek(0)
            digest = hashlib.file_digest(file, "sha256").hexdigest().encode()
        conn.sendall(digest)
        clear_send_times(addr)
        start_time = time.monotonic()
        while (code := recv_exact(conn, 3)) == b"100":
            add_send_time(addr, start_time, time.monotonic())
            print(f"\rSend Progress: {round(get_data_sent(addr)/path.stat().st_size, 1):%} Throughput: {calc_send_throughput(addr)}", end="", flush=True)
        if code != b"200":
            logging.warning("file send failed")
        else: logging.info(f"sent file at {path = } to client {addr = }")
        return True
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False


def handle_send(conn: socket.socket, addr: tuple, input_: dict) -> bool:
    """Handles requests related to sending files to a client.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        input_ (dict): A json containing the args sent by the client
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
        
    try:
        if input_.get("file_path", None) is None:
            logging.warning(f"download cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not isinstance(input_["file_path"], str):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        try:
            path = safe_path(input_["file_path"])
        except ValueError:
            logging.warning(f"unsafe path detected")
            conn.sendall(b"400")
            return True
        if not path.is_file():
            logging.warning(f"file at {path = } does not exist")
            conn.sendall(b"404")
            return True
        file_size = path.stat().st_size
        conn.sendall(b"200" + file_size.to_bytes(8, "big") + b"\n")
        try:
            conn.settimeout(5)
            data = b""
            while True:
                buf = conn.recv(4096)
                if buf == b"":
                    logging.warning(f"client connection terminated {addr = }")
                    return False
                data += buf
                if data.endswith(b"\n"):
                    if data.strip() != b"200":
                        logging.warning("client denied download")
                        conn.sendall(b"204")
                        return True
                    break
        except socket.timeout:
            logging.warning("client timed out")
            return False
        finally:
            conn.settimeout(None)
        return send_file(conn, addr, path)
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False


def handle_delete(conn: socket.socket, addr: tuple, input_: dict) -> bool:
    """Handles requests related to deleting files from the server.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        input_ (dict): A json containing the args sent by the client
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
        
    try:
        if not input_.get("file_path"):
            logging.warning(f"delete cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not isinstance(input_["file_path"], str):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        try:
            path = safe_path(input_["file_path"])
        except ValueError:
            logging.warning(f"unsafe path detected")
            conn.sendall(b"400")
            return True
        if not path.is_file():
            logging.warning(f"file at {path = } does not exist")
            conn.sendall(b"404")
            return True
        try:
            os.remove(path)
        except FileNotFoundError:
            logging.warning(f"file at {path = } disappeared before deletion")
            conn.sendall(b"404")
            return True
        except OSError:
            logging.exception(f"could not delete file at {path = }")
            conn.sendall(b"500")
            return True
        logging.info(f"removed file at {path = }")
        conn.sendall(b"200")
        return True
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False


def handle_ls(conn: socket.socket, addr: tuple, input_: dict) -> bool:
    try:
        if input_.get("dir", None) is None:
            logging.warning(f"dir cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not isinstance(input_["dir"], str):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        try:
            path = safe_path(input_["dir"])
        except ValueError:
            logging.warning(f"unsafe path detected")
            conn.sendall(b"400")
            return True
        if not path.is_dir():
            logging.warning(f"directory {path = } does not exist")
            conn.sendall(b"404")
            return True
        try:
            children = {}
            for item in path.iterdir():
                if item.is_file():
                    children[item.name] = "f"
                elif item.is_dir():
                    children[item.name] = "d"
        except OSError:
            logging.exception(f"could not list {path = }")
            conn.sendall(b"500")
            return True
        rval = ("200" + json.dumps(children) + "\n").encode()
        conn.sendall(rval)
        logging.info(f"sent {path = } contents to {addr = }")
        return True
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False


def handle_subfolder(conn: socket.socket, addr: tuple, input_: dict) -> bool:
    """Handles requests related to creating and deleting subfolders.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
        input_ (dict): A json containing the args sent by the client
        
    
    Returns:
        bool: Whether the server should keep the connection alive
    """
        
    try:
        if input_.get("action", None) is None or input_.get("subfolder_name", None) is None or input_.get("dir", None) is None:
            logging.warning(f"subfolder cmd: invalid arguments {addr = }")
            conn.sendall(b"400")
            return True
        if not isinstance(input_["action"], str) or not isinstance(input_["subfolder_name"], str) or not isinstance(input_["dir"], str):
            logging.warning(f"one or more invalid input types")
            conn.sendall(b"400")
            return True
        if input_["action"] not in ["create", "delete"]:
            logging.warning(f"invalid action = {input_["action"]}")
            conn.sendall(b"400")
            return True
        for invalid_char in r'\/:*?"<>|':
            if invalid_char in input_["subfolder_name"]:
                logging.warning(f"invalid character in subfolder name {invalid_char = }")
                conn.sendall(b"400")
                return True
        if input_["subfolder_name"] in ["..", ".", ""] or "\x00" in input_["subfolder_name"]:
            logging.warning(f"invalid subfolder name = {input_["subfolder_name"]}")
            conn.sendall(b"400")
            return True
        try:
            path = safe_path(input_["dir"]) / input_["subfolder_name"]
        except ValueError:
            logging.warning(f"unsafe path detected")
            conn.sendall(b"400")
            return True
        if path == ROOT:
            logging.warning("cannot delete root")
            conn.sendall(b"400")
            return True
        dir_exists = path.is_dir()
        match input_["action"]:
            case "create":
                if dir_exists:
                    logging.warning(f"subfolder already exists at {path = }")
                    conn.sendall(b"400")
                    return True
                os.mkdir(path)
                logging.info(f"subfolder created at {path = }")
                conn.sendall(b"200")
                return True
            case "delete":
                if not dir_exists:
                    logging.warning(f"subfolder does not exist at {path = }")
                    conn.sendall(b"404")
                os.rmdir(path)
                logging.info(f"subfolder deleted at {path = }")
                conn.sendall(b"200")
                return True
            case _:
                logging.exception("an unexpected error occured")
                conn.sendall(b"500")
                return True
    except OSError:
        logging.warning(f"client connection terminated {addr = }")
        return False
            

def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Handles a client connection and automatically closes the connection when finished.
    
    
    Args:
        conn (socket.socket): The connection to the client
        addr (tuple): The client's address
    """
        
    try:
        if not handle_auth(conn, addr) == True:
            return
        data = b""
        while True:
            conn.settimeout(None)
            buf = conn.recv(4096)
            if buf == b"":
                break
            data += buf
            if data.endswith(b"\n"):
                try:
                    parsed = json.loads(data)
                except json.JSONDecodeError:
                    parsed = None
                data = b""
                if not isinstance(parsed, dict):
                    logging.warning(f"invalid input from client {addr = }")
                    conn.sendall(b"400")
                    continue
                if not parsed.get("cmd"):
                    logging.warning(f"invalid input from client {addr = }")
                    conn.sendall(b"400")
                    continue
                if not isinstance(parsed["cmd"], str):
                    logging.warning(f"invalid input from client {addr = }")
                    conn.sendall(b"400")
                    continue
                match parsed["cmd"]:
                    case "upload":
                        logging.info(f"received command upload from {addr = }")
                        if not handle_recv(conn, addr, parsed):
                            return
                        continue
                    case "download":
                        logging.info(f"received command download from {addr = }")
                        if not handle_send(conn, addr, parsed):
                            return
                        continue
                    case "delete":
                        logging.info(f"received command delete from {addr = }")
                        if not handle_delete(conn, addr, parsed):
                            return
                        continue
                    case "dir":
                        logging.info(f"received command dir from {addr = }")
                        if not handle_ls(conn, addr, parsed):
                            return
                        continue
                    case "subfolder":
                        logging.info(f"received command subfolder from {addr = }")
                        if not handle_subfolder(conn, addr, parsed):
                            return
                        continue
                    case _:
                        logging.warning(f"invalid cmd = '{parsed["cmd"]}' from client {addr = }")
                        conn.sendall(b"400")
                        continue
    finally:
        logging.info(f"closing connection with {addr = }")
        conn.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(threadName)s %(message)s")
    init_filesystem()
    login_info.load_users()
    try:
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
    except KeyboardInterrupt:
        logging.info("Closing server...")
        exit()
        

if __name__ == "__main__":
    main()