import hashlib, os, json
from pathlib import Path

USERS = (Path(__file__).parent / "users").resolve()


user_hash = {}
        
        
def load_users() -> None:
    if not USERS.is_dir():
        USERS.mkdir(parents=True, exist_ok=True)
    try:
        with open(USERS / ".users", "r") as file:
            user_hash = json.load(file)
    except FileNotFoundError:
        return
    
    
def save_users() -> None:
    if not USERS.is_dir():
        USERS.mkdir(parents=True, exist_ok=True)
    with open(USERS / ".users", "w") as file:
        json.dump(user_hash, file)


load_users()


class SCRYPT_PARAMS:
    N = 2**14
    R = 8
    P = 1


def create_user(username: str, password: str) -> None:
    global user_hash
    salt = os.urandom(16)
    user_hash[username] = {
        "hash": hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_PARAMS.N, r=SCRYPT_PARAMS.R, p=SCRYPT_PARAMS.P),
        "salt": salt,
    }


dummy_users = {
    "alice": "ABC123",
    "bob": "DEF456",
}


def create_dummy_users() -> None:
    for user in dummy_users:
        create_user(user, dummy_users[user])
        
        
def main() -> None:
    options = ["new", "rm", "ls", "edit", "exit"]
    user_input = ""
    while True:
        while (user_input := input(f"{options = }")).lower() not in options:
            print("invalid input")
        match user_input:
            case "new":
                username = input("username = ")
                if username in user_hash:
                    print("user already exists")
                    continue
                password = input("pass = ")
                create_user(username, password)
            case "rm":
                username = input("username = ")
                if username not in user_hash:
                    print("user does not exist")
                    continue
                del user_hash[username]
            case "ls":
                print(user_hash.keys())
                continue
            case "edit":
                username = input("username = ")
                if username not in user_hash:
                    print("user does not exist")
                    continue
                password = input("new password = ")
                del user_hash[username]
                create_user(username, password)
                continue
            case "exit":
                save_users()
                break
                
                
if __name__ == "__main__":
    main()