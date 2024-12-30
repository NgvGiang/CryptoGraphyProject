import base64
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

# Giả sử bạn có JWE như sau
# jwe = 'eyJhbGciOiJBMTI4S1ciLCJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIn0.6i2aTG6OcZlm3Fnk1yn8QyTtpufjMxGQ.D2Wwi3YyAJN2mbA9.EKBpo1NUUOk-cxIMKsKmiBlOZ07bbmJ5LabGnOEuTNBRcqBRJ17ZoAhqT8FiYxbSqQ.mOTZ7bWuRfhptJGuA9ItvQ'
jwe = 'eyJhbGciOiJBMTI4S1ciLCJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIn0.hGChXtlX3gfdYHoeLzEGfT7yTm6YofCq.qnGfV0Y0vQe_hEDL.zImzvXF2Ss-sS53ufR4Plyab8Z8ScEZc9-t2mLODz98b8HuX_dd8e7OuhVSGLrdn7vVXgg.kK0qStBKSFMunLV5I-iEgg'
# Tách các phần của JWE
header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64  = jwe.split('.')

# Giải mã các phần từ Base64URL
header = json.loads(base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8'))
encrypted_key = base64.urlsafe_b64decode(encrypted_key_b64 + '==')
iv = base64.urlsafe_b64decode(iv_b64 + '==')
ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + '==')
tag = base64.urlsafe_b64decode(tag_b64 + '==')

# Giả sử bạn có khóa riêng (private key) hoặc khóa đối xứng (symmetric key)
# Đây là ví dụ với khóa đối xứng
secret_key = '16bytessecretkey'.encode()

# Giải mã Encrypted Key (nếu cần)

cek = aes_key_unwrap(secret_key, encrypted_key, backend=default_backend())

# Giải mã Ciphertext bằng AES-GCM cần: ciphertext, iv,AAD = header_b64(encode ascii), tag, cek(toàn bộ, không cần chia đôi như A128CBC-HS256)
# cipher = Cipher(algorithms.AES(cek), modes.GCM(iv), backend=default_backend())
# decryptor = cipher.decryptor()
# plaintext = decryptor.update(ciphertext) + decryptor.finalize()
aad = header_b64.encode()
aesgcm = AESGCM(cek)
try:
    plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
    print("Plaintext:", plaintext)
    print("Xác thực thành công!")
except Exception as e:
    print("Lỗi giải mã hoặc xác thực:", e)





