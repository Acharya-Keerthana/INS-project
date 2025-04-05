from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from config import ENCRYPTION_KEY

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(raw.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size).decode()

# Example Usage
aes_cipher = AESCipher(ENCRYPTION_KEY)
encrypted_data = aes_cipher.encrypt("Sensitive Data")
decrypted_data = aes_cipher.decrypt(encrypted_data)

print("Encrypted:", encrypted_data)
print("Decrypted:", decrypted_data)
