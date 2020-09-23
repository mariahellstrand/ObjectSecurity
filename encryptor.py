
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import pickle
import re
import hashlib

blocksize = AES.block_size

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def create_aeskey(key):
    key = int_to_bytes(key)
    key = hashlib.md5(key).hexdigest()
    return key[0:16]

def create_aesiv(key):
    key = int_to_bytes(key)
    key = hashlib.md5(key).hexdigest()
    return key[16:32]

def create_hash(sharedkey):
    byteskey = int_to_bytes(sharedkey)
    hashkey = HMAC.new(byteskey)
    return hashkey

def create_iv():
    return Random.new().read(blocksize)

def do_padding(data):
    temp = pickle.dumps(data)
    return temp + b'\0' * (blocksize - len(temp) % blocksize)

def undo_padding(data):
    return re.sub(b'\0*$', b'', data)

def encrypt(data, sharedkey):
    temp = do_padding(data)
    key = create_aeskey(sharedkey)
    iv = create_aesiv(sharedkey)
    obj = AES.new(key, AES.MODE_CBC, iv)
    return obj.encrypt(temp)

def decrypt(data, sharedkey):
    key = create_aeskey(sharedkey)
    iv = create_aesiv(sharedkey)
    obj = AES.new(key, AES.MODE_CBC, iv)
    message = undo_padding(obj.decrypt(data))
    return message

x = input(" ")
w = do_padding(x)
#print(w)
#print(w)
#print(undo_padding(w))
c = encrypt(w, 46774)
print(c)
d = decrypt(c, 46774)
print(d)

