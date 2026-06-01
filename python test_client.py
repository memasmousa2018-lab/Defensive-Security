import socket
import sys
sys.path.append(r"C:\Users\nab1\Downloads\port_scanner (4)\port_scanner")

# نضيف تعريف دوال التشفير هنا (إذا ما قدرت تستورد من crypto_utils)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

SECRET_KEY = b'0123456789abcdef'

def encrypt_message(message: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def decrypt_message(encrypted: str) -> str:
    iv, ct = encrypted.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 8888))

try:
    while True:
        msg = input("Enter message (or 'exit' to quit): ")
        if msg.lower() == "exit":
            break
        encrypted = encrypt_message(msg)
        sock.send(encrypted.encode())
        response = sock.recv(1024).decode()
        decrypted = decrypt_message(response)
        print(f"Server reply: {decrypted}")
finally:
    sock.close()