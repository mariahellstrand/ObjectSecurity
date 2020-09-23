from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import pickle
import re
import hashlib

import time
import datetime
import os

blocksize = AES.block_size
#test_dir = "./Nonce_Log/"
#test_file = "client-logs"

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
    hej = temp + b'\0' * (blocksize - len(temp) % blocksize)
    return hej

def undo_padding(data):
    return pickle.loads(re.sub(b'\0*$', b'', data))

def encrypt2(data, sharedkey):
    temp = do_padding(data)
    key = create_aeskey(sharedkey)
    iv = create_aesiv(sharedkey)
    obj = AES.new(key, AES.MODE_CBC, iv)
    return obj.encrypt(temp)

def decrypt(data, sharedkey):
    key = create_aeskey(sharedkey)
    iv = create_aesiv(sharedkey)
    obj = AES.new(key, AES.MODE_CBC, iv)
    temp = obj.decrypt(data)
    message = undo_padding(temp)
    return message


#----Generate and check nonce------

def getNonce() -> str:
    timeInSec = time.time()
    nonce = datetime.datetime.fromtimestamp(timeInSec).strftime('%Y-%m-%d %H:%M:%S')
    print("Generated the nonce: ", nonce)
    return nonce


def isNonceValid(nonce, dir, filename):
    #check if file exists, adds file if not
    if not checkIfFileExists(dir, filename):
        addNonce(nonce, dir, filename)
        print("Received unique nonce: ", nonce)
        return True
    elif nonce not in open(dir + filename).read():
        addNonce(nonce, dir, filename)
        print("Received unique nonce: ", nonce)
        return True
    else:
        print("Nonce not valid")
        return False

def checkIfFileExists(dir, filename):
    #lists all files in directory dir and checks if filename exists
    for file in os.listdir(dir):
        if file == filename:
            return True
    return False

def addNonce(nonce, dir, filename):
    with open(dir + filename + ".txt", "a") as nonce_file:
        nonce_file.write(nonce + "\n")


#n = getNonce()
#isNonceValid(n, test_dir, test_file)
