from Crypto.Cipher import AES
import os
import math

def padding(plaintext: bytes, length= 16):
    # pkcs#7
    pad = length - len(plaintext) % length

    return plaintext + bytes([pad] * pad)


def CBC_encrypt(plaintext: bytes, iv: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(padding(plaintext, 16))
    # convert byte to hex
    return ciphertext.hex()


def CBC_decrypt(ciphertext: bytes, iv: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def _encrypt(plaintext:bytes, key:bytes):
    # this function implement the encryption step for AES modes
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def CTR_decrypt(ciphertext: bytes, iv: bytes, key: bytes):
    num_block = math.ceil(len(ciphertext)/16)
    plaintext = []
    for i in range(num_block):
        f = _encrypt(iv, key)
        # plus iv with 1
        iv = iv[:15] + bytes([iv[15] + 1])
        plaintext.append(list(map(lambda x, y: x ^ y, f, ciphertext[i*16:(i+1)*16])))
    res = []
    for i in range(len(plaintext)):
        for j in range(len(plaintext[i])):
            res.append(plaintext[i][j])
    return bytes(res)

if __name__ == "__main__":
    # question 1:
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    ciphertext = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    iv = bytes.fromhex(ciphertext[:32])
    plaintext = CBC_decrypt(bytes.fromhex(ciphertext[32:]), iv, key)
    print('question 1:\n', plaintext)
    
    # question 2:
    key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    ciphertext = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    iv = bytes.fromhex(ciphertext[:32])
    plaintext = CBC_decrypt(bytes.fromhex(ciphertext[32:]), iv, key)
    print('question 2:\n', plaintext)

    #question 3:
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    ciphertext = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    iv = bytes.fromhex(ciphertext[:32])
    plaintext = CTR_decrypt(bytes.fromhex(ciphertext[32:]), iv, key)
    print('question 3:\n', plaintext)

    #question 4:
    key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    ciphertext = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    iv = bytes.fromhex(ciphertext[:32])
    plaintext = CTR_decrypt(bytes.fromhex(ciphertext[32:]), iv, key)
    print("question 4:\n", plaintext)