import socket
import os
import time
from protocol import send_msg, recv_msg

# allows you to enter IP and port, then connect to it
def do_connect(args):
    if len(args) != 2:
        print("Usage: connect <ip> <port>")
        return None
    ip, port = args[0], int(args[1])
    try:
        sock = socket.create_connection((ip, port), timeout=5)
    except OSError as e:
        print(f"Could not connect: {e}")
        return None
    print(f"Connected to {ip}:{port}")
    return sock

#sends a directory request to the server and reports back files
def do_dir(sock, args):
    directory = args[0] if args else "/"
    send_msg(sock, ["dir", directory])
    reply = recv_msg(sock)

    if reply["code"] != 200: #means success,
        print(f"Error {reply['code']}: {reply.get('message', '')}")
        return

    for entry in reply["entries"]:
        if entry["type"] == "dir":
            print(f"  [folder]  {entry['name']}")
        else:
            size_mb = entry["size"] / 1_048_576
            print(f"  {size_mb:8.1f} MB  {entry['name']}")

#asks the server to delete a file
def do_delete(sock, args):
    if len(args) != 1:
        print("Usage: delete <remote_file>")
        return
    send_msg(sock, ["delete", args[0]])
    reply = recv_msg(sock)

    if reply["code"] != 200:
        print_error(reply)
        return
    print(f"Deleted {args[0]}")

# create and delete subfoleders 
def do_subfolder(sock, args):
    if len(args) != 2 or args[0] not in ("create", "delete"):
        print("Usage: subfolder <create|delete> <path>")
        return
    action, path = args
    send_msg(sock, ["subfolder", action, path])
    reply = recv_msg(sock)

    if reply["code"] != 200:
        print_error(reply)
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
    send_msg(sock, ["upload", name, size, remote_dir])
    reply = recv_msg(sock)

    # user decides when to overwrite when code 300 is sent
    if reply["code"] == 300:
        answer = input(f"{name} already exists on the server. Overwrite? (y/n): ")
        overwrite = answer.strip().lower() == "y"
        send_msg(sock, overwrite)
        reply = recv_msg(sock)
        if not overwrite:
            print("Upload cancelled.")
            return

    # code 100 means server is ready to go
    if reply["code"] != 100:
        print_error(reply)
        return

    # send file in chunks
    start = time.perf_counter()
    with open(local_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sock.sendall(chunk)

    # confirm file is recieved
    reply = recv_msg(sock)
    seconds = time.perf_counter() - start
    if reply["code"] != 201:
        print_error(reply)
        return
    print(f"Uploaded {name}: {size / MB:.1f} MB in {seconds:.2f} s "
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
    while True:
        line = input("> ").strip()
        if not line:
            continue
        cmd, *args = line.split()
        cmd = cmd.lower()

        if cmd == "quit":
            break
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


if __name__ == "__main__":
    main()