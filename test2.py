#encryption
import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

raw_json_header = '''
{
  "alg": "A128KW",
  "typ": "JWT",
  "enc": "A128GCM"
}
'''
raw_json_payload = '''
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
  }
'''
header_jsonize = json.loads(raw_json_header)
payload_jsonize = json.loads(raw_json_payload)
header_str = json.dumps(header_jsonize, separators=(',', ':'))
payload_str = json.dumps(payload_jsonize, separators=(',', ':'))

def generate_iv_and_cek():
  """
  Generates a random IV (96 bits) and CEK (128 bits) for use with A128GCM and A128KW.

  Returns:
      tuple: A tuple containing the IV and CEK as bytes objects.
  """

  # Generate a 96-bit (12-byte) random IV
  iv_ = os.urandom(12)

  # Generate a 128-bit (16-byte) random CEK
  cek_ = AESGCM.generate_key(128)

  return iv_, cek_
iv, cek = generate_iv_and_cek()
aad = base64.urlsafe_b64encode(header_str.encode())
aesgcm2 = AESGCM(cek)
# try:
#     plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
#     print("Plaintext:", plaintext)
#     print("Xác thực thành công!")
# except Exception as e:
#     print("Lỗi giải mã hoặc xác thực:", e)

ciphertext = aesgcm2.encrypt(iv,payload_str.encode(),aad)
secret_key = b"16bytessecretkey"
encrypted_key = aes_key_wrap(secret_key, cek, backend=default_backend())
ciphertext_only = ciphertext[:-16]
tag = ciphertext[-16:]
jwe = base64.urlsafe_b64encode(header_str.encode()).decode() + "."+ base64.urlsafe_b64encode(encrypted_key).decode() + "." + base64.urlsafe_b64encode(iv).decode() +'.'+ base64.urlsafe_b64encode(ciphertext_only).decode() + base64.urlsafe_b64encode(tag).decode()
print(jwe)