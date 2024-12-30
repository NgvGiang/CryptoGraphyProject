import base64
import hmac
import hashlib
import json

from numpy.ma.testutils import assert_equal
'''
example jwt with secret base64 encoded:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ
{"alg": "HS256","typ": "JWT"}

{"sub":"1234567890","name":"John Doe","iat":1516239022}


'''

plain_secret_key = 'your-256-bit-secret'
def encode_base64(data: str) -> str:
    # Hàm mã hóa base64, sau đó chuyển bytes thành string
    return base64.b64encode(data.encode()).decode()

def encode_base64_url(data: str) -> str:
    # hàm b64 cần byte, .encode chuyển string thành byte, sau đó encode b64, sau đó decode byte trở lại dạng string
    return base64.urlsafe_b64encode(data.encode()).decode().replace('=','')

def hmac_sha256(key: str, msg: str) -> bytes: # force return type to bytes, phù hợp với hàm .digest trả về bytes
    """
    Tạo chữ ký HMAC-SHA256 cho thông điệp msg, sử dụng key.
    """
    # Chuyển key và msg về bytes vì hàm hmac.new cần key ở dạng bytes
    key_bytes = key.encode()
    msg_bytes = msg.encode()

    signature = hmac.new(key_bytes, msg_bytes, hashlib.sha256)


    # Trả về giá trị chữ ký dưới dạng bytes
    return signature.digest()


raw_json_header = '''
{
  "alg": "HS256",
  "typ": "JWT"
}
'''
raw_json_payload = '''
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
  }
'''
#chuẩn hóa
# good_header = raw_json_header.replace('\n', '').replace('\r', '').replace(' ', '')
# good_payload=  raw_json_payload.replace('\n', '').replace('\r', '').replace(' ', '')
# print(good_header)
# print(good_payload)

header_jsonize = json.loads(raw_json_header)
payload_jsonize = json.loads(raw_json_payload)
#xóa cả dấu space sau dấu hai chấm
header_str = json.dumps(header_jsonize, separators=(',', ':'))
payload_str = json.dumps(payload_jsonize, separators=(',', ':'))

print(header_str)
print(payload_str)
#now is very gud


encoded_header = encode_base64_url(header_str)
encoded_body = encode_base64_url(payload_str)
print(f"encoded_header: {encoded_header}")
print(f"encoded_body: {encoded_body}")
body_payload_combination_base64 = (encoded_header + '.' + encoded_body)
print(body_payload_combination_base64)
signature = hmac_sha256(plain_secret_key, body_payload_combination_base64)
signature_encoded_base64url = base64.urlsafe_b64encode(signature).decode().replace('=','')
assert_equal(signature_encoded_base64url,'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')





