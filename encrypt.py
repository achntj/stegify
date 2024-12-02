from Crypto.Cipher import AES
import base64

def pad_message(message):
    # AES block size is 16 bytes
    return message + (16 - len(message) % 16) * ' '

def encrypt_message(key, message):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_message = pad_message(message)
    encrypted_bytes = cipher.encrypt(padded_message.encode('utf-8'))
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_message(key, encrypted_message):
    try:
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(encrypted_bytes).decode('utf-8').strip()
        return decrypted_message
    except (UnicodeDecodeError, ValueError):
        # UnicodeDecodeError: if decryption produces invalid UTF-8
        # ValueError: if incorrect padding or decryption issues
        return None
