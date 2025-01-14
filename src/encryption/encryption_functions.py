from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from tkinter import filedialog
import os


class Encrypt:
    def __init__(self):
        pass

# =========================================
#                   AES
# =========================================
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

# =========================================
#                   DES
# =========================================
    def encrypt_DES(self, file_name):
        des_key = get_random_bytes(8)
        nonce = get_random_bytes(4)

        encryption = DES.new(des_key, DES.MODE_CTR, nonce=nonce)

        # Read the file and encrypt it
        with open(f'{file_name}', "rb") as input_file:
            data = input_file.read()
            encrypted = encryption.encrypt(data)

        # Save the encrypted file with nonce and DES key at the beginning
        encrypted_file = file_name + ".enc"
        with open(encrypted_file, "wb") as encrypted_file:
            encrypted_file.write(nonce)
            encrypted_file.write(des_key)
            encrypted_file.write(encrypted)

        print(f"File encrypted and saved as {encrypted_file}")

    def decrypt_DES(self, encrypted_file_name):
        # Open the encrypted file and read the nonce, DES key, and encrypted data
        with open(encrypted_file_name, "rb") as encrypted_file:
            nonce = encrypted_file.read(4)
            des_key = encrypted_file.read(8)
            encrypted_data = encrypted_file.read()

        # Create DES cipher in CTR mode with the same nonce and key
        encryption = DES.new(des_key, DES.MODE_CTR, nonce=nonce)

        # Decrypt the data
        decrypted_data = encryption.decrypt(encrypted_data)

        # Replace ".enc" in the file name to create the decrypted file name
        decrypted_file_name = encrypted_file_name.replace(".enc", "_decrypted")

        # Save the decrypted data to the new file
        with open(decrypted_file_name, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted and saved as {decrypted_file_name}")

# =========================================
#                   3DES
# =========================================
    def encrypt_3DES(self, file_name):
        des3_key = get_random_bytes(24)
        nonce = get_random_bytes(4)

        encryption = DES3.new(des3_key, DES3.MODE_CTR, nonce=nonce)

        # Read the file and encrypt it
        with open(f'{file_name}', "rb") as input_file:
            data = input_file.read()
            encrypted = encryption.encrypt(data)

        # Save the encrypted file with nonce and 3DES key at the beginning
        encrypted_file = file_name + ".enc"
        with open(encrypted_file, "wb") as encrypted_file:
            encrypted_file.write(nonce)
            encrypted_file.write(des3_key)
            encrypted_file.write(encrypted)

        print(f"File encrypted and saved as {encrypted_file}")

    def decrypt_3DES(self, encrypted_file_name):
        # Open the encrypted file and read the nonce, 3DES key, and encrypted data
        with open(encrypted_file_name, "rb") as encrypted_file:
            nonce = encrypted_file.read(4)
            des3_key = encrypted_file.read(24)
            encrypted_data = encrypted_file.read()

        # Create 3DES cipher in CTR mode with the same nonce and key
        encryption = DES3.new(des3_key, DES3.MODE_CTR, nonce=nonce)

        # Decrypt the data
        decrypted_data = encryption.decrypt(encrypted_data)

        # Replace ".enc" in the file name to create the decrypted file name
        decrypted_file_name = encrypted_file_name.replace(".enc", "_decrypted")

        # Save the decrypted data to the new file
        with open(decrypted_file_name, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted and saved as {decrypted_file_name}")

# =========================================
#                   RSA
# =========================================
    def generate_RSA_Key(self):
        key = RSA.generate(2048)
        private = key.export_key()
        public = key.publickey().export_key()

        key_dir = filedialog.askdirectory(
            title="Choose a Directory to Save the Keys")
        if not key_dir:
            print("Operation canceled")
            return
        private_key_path = os.path.join(key_dir, "private.pem")
        public_key_path = os.path.join(key_dir, "public.pem")

        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(private)

        with open(public_key_path, "wb") as public_key_file:
            public_key_file.write(public)

        print(f"Keys saved to {key_dir}")

    def encrypt_RSA(self, file_name, public_key_file="public.pem"):
        key_file = filedialog.askopenfile(
            title="Select the Public Key")
        if not key_file:
            print("Operation canceled")
            return
        public_key_path = key_file.name

        # Read the public key from file
        try:
            with open(public_key_path, "rb") as pub_key_file:
                public_key = RSA.import_key(pub_key_file.read())

            # Create an RSA cipher using OAEP padding (secure padding scheme)
            cipher_rsa = PKCS1_OAEP.new(public_key)
        except (ValueError, TypeError) as e:
            print(f"Invalid Key: {e}")
            return

        # Read the file and encrypt it
        with open(file_name, "rb") as input_file:
            data = input_file.read()
            encrypted = cipher_rsa.encrypt(data)

        # Save the encrypted file
        encrypted_file = file_name + ".enc"
        with open(encrypted_file, "wb") as encrypted_file:
            encrypted_file.write(encrypted)

        print(f"File encrypted and saved as {encrypted_file.name}")

    def decrypt_RSA(self, encrypted_file_name, private_key_file="private.pem"):
        # Read the private key from file
        with open(private_key_file, "rb") as priv_key_file:
            private_key = RSA.import_key(priv_key_file.read())

        # Create an RSA cipher using OAEP padding (same padding as for encryption)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Read the encrypted file and decrypt it
        with open(encrypted_file_name, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()
            decrypted_data = cipher_rsa.decrypt(encrypted_data)

        # Replace ".enc" in the file name to create the decrypted file name
        decrypted_file_name = encrypted_file_name.replace(".enc", "_decrypted")

        # Save the decrypted data to the new file
        with open(decrypted_file_name, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted and saved as {decrypted_file_name}")
