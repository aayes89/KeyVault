from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA1
import os
import struct
import base64
import hmac
import hashlib
from Cryptodome.Cipher import ARC4

def returnportion(data, start, length):
    return data[start:start+length]

def hmac_sha1(key, message):
    return hmac.new(key, message, hashlib.sha1).digest()

def rc4_decrypt(data, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def decryptkv(kv, key):
    if kv is None or key is None:
        return None

    message = returnportion(kv, 0, 0x10)
    RC4_key = hmac_sha1(key, message)
    if RC4_key is None:
        return None

    restofkv = returnportion(kv, 0x10, len(kv) - 0x10)
    decrypted_rest = rc4_decrypt(restofkv, returnportion(RC4_key, 0, 0x10))

    finalimage = message + decrypted_rest
    return finalimage

# Ejemplo de uso:
kv_data = open("KV_en.bin", "rb").read()                     # Nombre del archivo keyvault.bin
cpu_key = bytes.fromhex("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")  # CPU key (16 bytes)
decrypted_kv = decryptkv(kv_data, cpu_key)
with open("keyvault_dec.bin", "wb") as f:                    # nombre el KeyVault desencriptado
    f.write(decrypted_kv)
