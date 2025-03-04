import hashlib
from tkinter import *


class Hash:

    def __init__(self):
        # Implement hashing history data structures
        pass

    # Utilizes the SHA-1 hashing algorithm
    def hash_password_SHA1(self, password):
        hashed = hashlib.sha1(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed
    # FINISH FILE HASH FUNCTIONS

    def hash_file_SHA1(self, file_path):
        with open(file_path, 'rb', buffering=0) as f:
            hashed = hashlib.file_digest(f, 'sha1').hexdigest()
        return hashed

    # Utilizes the SHA-2 (224) hashing algorithm
    def hash_password_SHA2_224(self, password):
        hashed = hashlib.sha224(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-2 (256) hashing algorithm
    def hash_password_SHA2_256(self, password):
        hashed = hashlib.sha256(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-2 (512) hashing algorithm
    def hash_password_SHA2_512(self, password):
        hashed = hashlib.sha512(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (224) hashing algorithm
    def hash_password_SHA3_224(self, password):
        hashed = hashlib.sha3_224(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (256) hashing algorithm
    def hash_password_SHA3_256(self, password):
        hashed = hashlib.sha3_256(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (384) hashing algorithm
    def hash_password_SHA3_384(self, password):
        hashed = hashlib.sha3_384(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (512) hashing algorithm
    def hash_password_SHA3_512(self, password):
        hashed = hashlib.sha3_512(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (shake-128) hashing algorithm
    def hash_password_SHA3_shake128(self, password):
        hashed = hashlib.shake_128(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the SHA-3 (shake-256) hashing algorithm
    def hash_password_SHA3_shake256(self, password):
        hashed = hashlib.shake_256(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed

    # Utilizes the md5 hashing algorithm
    def hash_password_md5(self, password):
        hashed = hashlib.md5(
            f"{password}".encode(), usedforsecurity=True).hexdigest()
        return hashed
