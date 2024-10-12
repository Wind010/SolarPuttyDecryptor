import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import sys
from typing import List, Tuple


def decrypt(password: str, ciphertext: str) -> str:
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[32:]

        # Derive the key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=24,  # Triple DES key size
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Create the cipher and decrypt the data
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())
        return data

    except Exception as e:
        print(f'Error: {e}')

def decrypt_wrapper(passwords: List[str], cipher: [str]) -> Tuple[str, str]: # type: ignore
    for i, password in enumerate(passwords):
        password: str  = password.strip()
        decrypted: str = decrypt(password, cipher)
        if decrypted and 'Credentials' in decrypted:
            print(f"✔ Correct password found on line {i}:  {password}")
            return (decrypted, password)
        else:
            print(f"❌ Password={password} is incorrect!")

 
def debug_decrypted_payload(decrypted: str):
    '''
    Useful to debug any unexpected bytes.
    '''
    import base64
    encoded_bytes = decrypted.encode("utf8")
    base64_bytes = base64.b64encode(encoded_bytes)
    base64_string = base64_bytes.decode("utf8")
    print(encoded_bytes)
    print(base64_string)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt Solar-PuTTY session using a password or wordlist.')
    parser.add_argument('session', help='Path to the Solar-PuTTY session (.dat) file.')
    parser.add_argument('-wl', '--wordlist', help='Path to the wordlist file (optional).', nargs='?')
    parser.add_argument('-p', '--password', help='Password to use for decryption (optional).', nargs='?')

    args = parser.parse_args()

    if len(sys.argv) != 4:
        print(sys.argv)
        print("Usage: python SolarPuttyDecryptor.py <session_file> -wl <wordlist> or -p <password>")
        exit(1)

    with open(args.session, 'r', encoding='UTF8') as f:
        ciphertext: str = f.read()

    if args.password:
        decrypted, password = decrypt_wrapper([args.password], ciphertext)
    elif args.wordlist:
        with open(args.wordlist, 'r', encoding='UTF8') as passwords:
            decrypted, password = decrypt_wrapper(passwords, ciphertext)
    else:
        parser.print_help()
        print("Error: Either a password or a wordlist must be provided.")
        exit(2)
 
    try:
        # Some gibberish could exist in begining.
        cleaned_up_decrypted: str = decrypted[decrypted.index('['):]
        fixed_decrypted: str = '{"Sessions":' + cleaned_up_decrypted
        
        # Some gibberish bytes could exist at end.  Part of the fun...
        fixed_decrypted = fixed_decrypted.replace("\\","_").replace(b'\x01'.decode('UTF8'), '')
        decrypted_json: str = json.loads(fixed_decrypted)
        print('🚀🚀🚀🚀🚀')

        print(json.dumps(decrypted_json, indent=4))
    except json.JSONDecodeError as e:
        print("💀 Invalid JSON:", e)
        print(decrypted)
        exit(3)
