import hashlib
import os


user_hash = {}

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
    create_dummy_users()
    
    
if __name__ == "__main__":
    main()