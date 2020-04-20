import base64
import hashlib
import random

def crypt(data, key):
   x = 0
   box = range(256)
   for i in range(256):
       x = (x + box[i] + ord(key[i % len(key)])) % 256
       box[i], box[x] = box[x], box[i]
   x = y = 0
   out = []
   for char in data:
       x = (x + 1) % 256
       y = (y + box[x]) % 256
       box[x], box[y] = box[y], box[x]
       out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
   return ''.join(out)


def tdecode(data, key, decode=base64.b64decode, salt_length=16):
   if decode:
       data = decode(data)
   salt = data[:salt_length]
   return crypt(data[salt_length:], hashlib.sha1(key + salt).digest())


if __name__ =='__main__':
   data = 'UUyFTj8PCzF6geFn6xgBOYSvVTrbpNU4OF9db9wMcPD1yDbaJw =='
   key = 'welcometoicqedu'
   decoded_data = tdecode(data=data, key=key)
   print(decoded_data)