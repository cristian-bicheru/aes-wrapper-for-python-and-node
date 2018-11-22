from Crypto.Cipher import AES

def PKCS7(msg):
    b = 16 - (len(msg) % 16)
    return (msg + b * chr(b)).encode()

def unPKCS7(msg):
    return msg[:-ord(msg[len(msg)-1:])]

def encrypt(msg, key, iv):
    aes = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return aes.encrypt(PKCS7(msg))

def decrypt(ct, key, iv):
    aes = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return unPKCS7(aes.decrypt(ct))
