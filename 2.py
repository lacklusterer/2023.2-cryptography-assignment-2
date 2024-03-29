from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def xor_bytes(byte1, byte2):
    if len(byte1) != len(byte2):
        raise ValueError("Byte objects do not have the same length")
    result = bytes([a ^ b for a, b in zip(byte1, byte2)])

    return result

def AES_Decrypt(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_block = decryptor.update(block) + decryptor.finalize()

    return decrypted_block

def cbc_decrypt(cipher, key, iv):
    plaintext_final = ""
    previous_block = iv
    block_size = len(iv)

    for i in range(block_size, len(cipher), block_size):
        block = cipher[i:i+block_size]
        decrypted_block = AES_Decrypt(block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        plaintext_ascii = plaintext_block.decode('ascii', errors='ignore')
        plaintext_final += plaintext_ascii
        previous_block = block

    return plaintext_final

key1 = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
cipher1 = bytes.fromhex("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
cipher2 = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")

print(cbc_decrypt(cipher1, key1, cipher1[:16]))
print(cbc_decrypt(cipher2, key1, cipher2[:16]))
