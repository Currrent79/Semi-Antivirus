import pyAesCrypt
import os

def encrypt_file(file_path, password, buffer_size=64 * 1024):
    """
    Encrypt a file using AES-256 with the provided password.
    """
    encrypted_file = file_path + ".aes"
    try:
        pyAesCrypt.encryptFile(file_path, encrypted_file, password, buffer_size)
        if os.path.exists(file_path):  # Only remove if it exists to avoid errors
            os.remove(file_path)
        return encrypted_file
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_file(encrypted_file, password, buffer_size=64 * 1024):
    """
    Decrypt a file using the provided password.
    """
    decrypted_file = encrypted_file.replace(".aes", "")
    try:
        pyAesCrypt.decryptFile(encrypted_file, decrypted_file, password, buffer_size)
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        return decrypted_file
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")
        