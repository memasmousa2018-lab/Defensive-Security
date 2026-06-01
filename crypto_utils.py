from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

SECRET_KEY = b'0123456789abcdef'  # 16 (AES-128)

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