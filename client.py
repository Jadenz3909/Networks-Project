import socket
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