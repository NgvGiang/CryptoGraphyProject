#encryption
import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

raw_json_header = '''
{
  "alg": "A128KW",
  "typ": "JWT",
  "enc": "A128GCM"
}
'''
raw_json_payload = '''
{
  "sub": "HuyKhoi",
  "name": "VanGiang",
  "iat": 1516239022
  }
'''
header_jsonize = json.loads(raw_json_header)
payload_jsonize = json.loads(raw_json_payload)
header_str = json.dumps(header_jsonize, separators=(',', ':'))
payload_str = json.dumps(payload_jsonize, separators=(',', ':'))

def generate_iv_and_cek():
  # Generate a 96-bit (12-byte) random IV
  iv_ = os.urandom(12)
  # Generate a 128-bit (16-byte) random CEK
  cek_ = AESGCM.generate_key(128)
  return iv_, cek_
iv, cek = generate_iv_and_cek()
aad = base64.urlsafe_b64encode(header_str.encode()).rstrip(b"=") # Remove padding from AAD
aesgcm = AESGCM(cek)
ciphertext = aesgcm.encrypt(iv,payload_str.encode(),aad)
# Split ciphertext and tag
ciphertext_only = ciphertext[:-16]
tag = ciphertext[-16:]
secret_key = b'16bytessecretkey' # Should be randomly generated and securely stored
encrypted_key = aes_key_wrap(secret_key, cek, default_backend())
jwe = base64.urlsafe_b64encode(header_str.encode()).rstrip(b"=").decode() + "." + \
      base64.urlsafe_b64encode(encrypted_key).rstrip(b"=").decode() + "." + \
      base64.urlsafe_b64encode(iv).rstrip(b"=").decode() + '.' + \
      base64.urlsafe_b64encode(ciphertext_only).rstrip(b"=").decode() + '.' + \
      base64.urlsafe_b64encode(tag).rstrip(b"=").decode()
print(f"JWE: {jwe}")
