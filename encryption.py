import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

import os
from stat import S_IREAD, S_IRWXU

class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

path = os.getcwd()
dir_list = os.listdir(path)
print(dir_list)
os.chmod('state', S_IREAD)
g = open('state', 'r')
status = g.readlines()
if(status[0] == 'encrypted'):

    password = input("Enter password for decryption: ")
    a = AESCipher(password)
    # print(a.decrypt('4aiHxRFeKAKTz9zGs2KZF0SmGKaWS/9wb6kXzQkKyyQ='))
    # print(a.decrypt('5USKlrd8JobNwNmVKB3kTw+of+0jiG8IlKCiHt810Do='))

    for i in dir_list:

        if(i != "encryption.py" and i != "keys" and i != 'state'):
            os.chmod(i, S_IREAD)
            print(i)
            f = open(i, 'r')
            list = f.readlines()
            elist = ""
            m = []
            for j in list:
                elist = a.decrypt(j)
                m.append(elist)
            print(m)
            os.chmod(i, S_IRWXU)
            f = open(i, 'w')
            for k in m:
                f.write(k)

    os.chmod('state', S_IRWXU)
    g = open('state', 'w')
    g.write('decrypted')
    os.chmod('state', S_IREAD)

elif(status[0] == 'decrypted'):
    password = input("Enter any password for encryption, make sure to remember it: ")
    a = AESCipher(password)
    for i in dir_list:
        if(i != "encryption.py" and i != "keys" and i!= 'state'):
            f = open(i, 'r')
            list = f.readlines()
            elist = ""
            m = []
            for j in list:
                elist = a.encrypt(j)
                m.append(elist)
            print(m)
            f = open(i, 'w')
            for k in m:
                f.write(k)
                f.write('\n')
            os.chmod(i, S_IREAD)
    os.chmod('state', S_IRWXU)
    g = open('state', 'w')
    g.write('encrypted')
    os.chmod('state', S_IREAD)