import getpass
import hashlib
import json
import os
import posixpath
import socket
import time
import base64

# encryption using RSA
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# opens the public key from the folder
with open("public_key.pem", "rb") as f:
    _loaded = serialization.load_pem_public_key(f.read())

# checks that it is an RSA key
if not isinstance(_loaded, rsa.RSAPublicKey):
    raise TypeError("public_key.pem is not an RSA public key")

public_key = _loaded

# the encryption happens here and this is where it is padded
# base64 converts it back it letters and digits for the json
def encrypt(password: str) -> str:
    ciphertext = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()


CHUNK_SIZE = 256 * 1024
# donload save location
DOWNLOAD_DIR = "downloads"
# size of file transfers
UPLOAD_CHUNK = 40000
# bytes to MB
MB = 1_048_576

ERRORS = {
    400: "request rejected",
    401: "wrong username or password",
    404: "not found in server",
    408: "the server timed out",
    422: "the file has errors",
    500: "server error",
}

# looks up error codes
def print_error(code):
    print(f"Error {code}: {ERRORS.get(code, 'unexpected reply')}")

# adds the new line as it sends everything out
def send_request(sock, fields):
    sock.sendall((json.dumps(fields) + "\n").encode())

# reads exactly n bytes
def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the server closed the connection")
        data += chunk
    return data

# reads the codes
def recv_code(sock):
    return int(recv_exact(sock, 3))

# reads the entire line for dir
def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        data += recv_exact(sock, 1)
    return data

# allows you to enter IP and port, then connect to it
def do_connect(args):
    # takes the 2 arguments after connect
    if len(args) != 2 or not args[1].isdigit():
        print("Usage: connect <ip> <port>")
        return None
    ip, port = args[0], int(args[1])
    
    #asks for user logins
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    try:
        #opens the TCP connection
        sock = socket.create_connection((ip, port), timeout=5)
        sock.sendall(json.dumps({"username": username, "password": encrypt(password)}).encode())
        code = recv_code(sock)
    except OSError as e:
        print(f"Could not connect: {e}")
        return None
    # if something other 200 is sent, login failed
    if code != 200:
        print_error(code)
        sock.close()
        return None
    # connected and no timeout
    sock.settimeout(None)   
    print(f"Connected to {ip}:{port} as {username}")
    return sock

#sends a directory request to the server and reports back files
def do_dir(sock, args):
    directory = args[0] if args else "/"
    # sends the request
    send_request(sock, {"cmd": "dir", "dir": directory})
    #check for 200
    code = recv_code(sock)
    if code != 200:
        print_error(code)
        return

    # read the entry
    entries = json.loads(recv_line(sock))    
    if not entries:
        print("  (empty)")
        # prints each item
    for name, kind in sorted(entries.items()):
        label = "[folder]" if kind == "d" else "[file]  "
        print(f"  {label}  {name}")

#asks the server to delete a file
def do_delete(sock, args):
    if len(args) != 1:
        print("Usage: delete <remote_file>")
        return
    send_request(sock, {"cmd": "delete", "file_path": args[0]})
    code = recv_code(sock)
    if code != 200:
        print_error(code)
        return
    print(f"Deleted {args[0]}")

# create and delete subfoleders 
def do_subfolder(sock, args):
    if len(args) != 2 or args[0] not in ("create", "delete"):
        print("Usage: subfolder <create|delete> <path>")
        return
    action, path = args
    

    parent, name = posixpath.split(path.strip("/"))
    send_request(sock, {"cmd": "subfolder", "action": action,
                        "subfolder_name": name, "dir": "/" + parent})
    code = recv_code(sock)
    if code != 200:
        print_error(code)
        return
    print(f"Folder {path} {action}d")

# upload file to server
def do_upload(sock, args):
    if len(args) not in (1, 2):
        print("Usage: upload <local_file> [remote_dir]")
        return
    local_path = args[0]
    remote_dir = args[1] if len(args) == 2 else "/"
    if not os.path.isfile(local_path):
        print(f"No such local file: {local_path}")
        return
    name = os.path.basename(local_path)
    size = os.path.getsize(local_path)

    # informs the server what is being sent
    send_request(sock, {"cmd": "upload", "file_name": name,
                        "file_size_bytes": size, "dir": remote_dir})
    code = recv_code(sock)

    # user decides when to overwrite when code 300 is sent
    if code == 300:
        answer = input(f"{name} already exists on the server. Overwrite? (y/n): ")
        overwrite = answer.strip().lower() == "y"
        sock.sendall(json.dumps({"overwrite": overwrite}).encode())
        code = recv_code(sock)
        if code == 204:
            print("Upload cancelled.")
            return

    # code 100 means server is ready to go
    if code != 100:
        print_error(code)
        return

    # send file in chunks, and create hash as we go
    sha = hashlib.sha256()
    start = time.perf_counter()
    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(UPLOAD_CHUNK)
            if not chunk:
                break
            sock.sendall(chunk)
            sha.update(chunk)

            if recv_code(sock) != 100:
                print("Upload failed")
                return

    # send SHA - 256 to server to make sure file is unchanged
    sock.sendall((sha.hexdigest() + "\n").encode())
    code = recv_code(sock)
    seconds = time.perf_counter() - start
    if code != 201:
        print_error(code)
        return
    print(f"Uploaded {name}: {size / MB:.1f} MB in {seconds:.2f} s "
          f"({size / MB / seconds:.1f} MB/s)")

# downloads file from server to client
def do_download(sock, args):
    if len(args) != 1:
        print("Usage: download <remote_file>")
        return
    remote_path = args[0]
    name = posixpath.basename(remote_path)

    # request the file
    send_request(sock, {"cmd": "download", "file_path": remote_path})
    code = recv_code(sock)
    if code != 200:
        print_error(code)
        return

    # the size
    size = int.from_bytes(recv_exact(sock, 8), "big")
    recv_exact(sock, 1)

    # confirmation from server
    sock.sendall(b"200\n")

    # save the chunks and writes them
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    local_path = os.path.join(DOWNLOAD_DIR, name)
    sha = hashlib.sha256()
    received = 0
    shown = -1
    start = time.perf_counter()
    with open(local_path, "wb") as f:
        while received < size:
            chunk = recv_exact(sock, min(UPLOAD_CHUNK, size - received))
            if not chunk:
                raise ConnectionError("the server closed the connection")
            f.write(chunk)
            sha.update(chunk)
            received += len(chunk)
            sock.sendall(b"100")

            percent = received * 100 // size
            if percent != shown:
                print(f"\rDownloading: {percent}%",end="", flush=True)
                shown = percent
    
    seconds = time.perf_counter() - start
    print()

    # compares the server encryption with ours
    server_hash = recv_exact(sock, 64).decode()
    if server_hash != sha.hexdigest():
        sock.sendall(b"422")      
        os.remove(local_path)
        print("Download failed: the file was damaged on the way and was not kept.")
        return
    sock.sendall(b"200")

    print(f"Downloaded {name} to {local_path}: {size / MB:.1f} MB in {seconds:.2f} s "
          f"({size / MB / seconds:.1f} MB/s)")

# our key for entered commands
COMMANDS = {
    "dir": do_dir,
    "upload": do_upload,
    "download": do_download,
    "delete": do_delete,
    "subfolder": do_subfolder,
}

#runs our primary functions once connection is established
def main():
    sock = None
    print("Type 'help' to pull up commands")
    while True:
        line = input("> ").strip()
        if not line:
            continue
        cmd, *args = line.split()
        cmd = cmd.lower()

        if cmd == "quit":
            break
        elif cmd == "help":
            show_commands()
        elif cmd == "connect":
            sock = do_connect(args)
        elif cmd not in COMMANDS:
            print(f"Unknown command: {cmd}")
        elif sock is None:
            print("Not connected. Use: connect <ip> <port>")
        else:
            try:
                COMMANDS[cmd](sock, args)
            except OSError as e:
                print(f"Lost connection to server: {e}")
                sock = None

    if sock:
        sock.close()


def show_commands():
    print()
    print("Commands Available:")
    print(" connect (ip) (ports)")
    print(" dir (path)")
    print(" upload (local dir) (server dir)")
    print(" download (path file name)")
    print(" subfolder (create || delete) (path)")
    print(" quit")

if __name__ == "__main__":
    main()
