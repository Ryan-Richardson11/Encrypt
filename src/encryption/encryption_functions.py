from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Encrypt:
    def __init__(self):
        pass

    def encrypt_AES(self, file_name):
        aes_key = get_random_bytes(16)
        nonce = get_random_bytes(8)

        encryption = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

        # Read the file and encrypt it
        with open(f'{file_name}', "rb") as input_file:
            data = input_file.read()
            encrypted = encryption.encrypt(data)

        # Save the encrypted file with nonce and AES key at the beginning
        encrypted_file = file_name + ".enc"
        with open(encrypted_file, "wb") as encrypted_file:
            encrypted_file.write(nonce)
            encrypted_file.write(aes_key)
            encrypted_file.write(encrypted)

        print(f"File encrypted and saved as {encrypted_file}")

    def decrypt_AES(self, encrypted_file_name):
        # Open the encrypted file and read the nonce, AES key, and encrypted data
        with open(encrypted_file_name, "rb") as encrypted_file:
            nonce = encrypted_file.read(8)
            aes_key = encrypted_file.read(16)
            encrypted_data = encrypted_file.read()

        # Create AES cipher in CTR mode with the same nonce and key
        encryption = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

        # Decrypt the data
        decrypted_data = encryption.decrypt(encrypted_data)

        # Replace ".enc" in the file name to create the decrypted file name
        decrypted_file_name = encrypted_file_name.replace(".enc", "_decrypted")

        # Save the decrypted data to the new file
        with open(decrypted_file_name, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted and saved as {decrypted_file_name}")

    def cryptographic_erase():
        pass
