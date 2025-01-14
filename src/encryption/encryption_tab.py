from src.encryption.encryption_functions import Encrypt
from tkinter import *
from tkinter import filedialog

# ===========================================================================================================================================================
# End Build Encrypt Frame
# ===========================================================================================================================================================


def display_encryption_tab(frame):
    current = Encrypt()

    # Frames to display different hashing options
    encryption_options_frame_sym = LabelFrame(
        frame, text="Symmetric Algorithms (encrypt)")
    encryption_options_frame_sym.grid(
        row=0, column=0, padx=10, pady=10, sticky="nsew")

    encryption_options_frame_asym = LabelFrame(
        frame, text="Asymmetric Algorithms (encrypt)")
    encryption_options_frame_asym.grid(
        row=0, column=1, padx=10, pady=10, sticky="nsew")

    decryption_options_frame_sym = LabelFrame(
        frame, text="Symmetric Algorithms (decrypt)")
    decryption_options_frame_sym.grid(
        row=0, column=2, padx=10, pady=10, sticky="nsew")

    decryption_options_frame_asym = LabelFrame(
        frame, text="Asymmetric Algorithms (decrypt)")
    decryption_options_frame_asym.grid(
        row=0, column=3, padx=10, pady=10, sticky="nsew")

    # Configure rows and columns to be equally spaced
    frame.columnconfigure(0, weight=1)
    frame.columnconfigure(1, weight=1)
    frame.columnconfigure(2, weight=1)
    frame.columnconfigure(3, weight=1)
    frame.rowconfigure(0, weight=1)

    # Hashing option radio buttons
    selected_algorithm = StringVar(value="none")

    def create_radio_button(frame, text, value, row, column):
        return Radiobutton(frame, text=text, variable=selected_algorithm, value=value)

    # Symmetric Encryption
    aes_radio = create_radio_button(
        encryption_options_frame_sym, "AES", "aes-e", 0, 0)
    aes_radio.grid(row=0, column=0, padx=10, pady=10)

    des_radio = create_radio_button(
        encryption_options_frame_sym, "DES", "des-e", 1, 0)
    des_radio.grid(row=1, column=0, padx=10, pady=10)

    des3_radio = create_radio_button(
        encryption_options_frame_sym, "3DES", "3des-e", 2, 0)
    des3_radio.grid(row=2, column=0, padx=10, pady=10)

    # Asymmetric Encryption
    rsa_radio = create_radio_button(
        encryption_options_frame_asym, "RSA", "rsa-e", 0, 0)
    rsa_radio.grid(row=0, column=0, padx=10, pady=10)

    # Symmetric Decryption
    aes_radio = create_radio_button(
        decryption_options_frame_sym, "AES", "aes-d", 0, 0)
    aes_radio.grid(row=0, column=0, padx=10, pady=10)

    des_radio = create_radio_button(
        decryption_options_frame_sym, "DES", "des-d", 1, 0)
    des_radio.grid(row=1, column=0, padx=10, pady=10)

    des3_radio = create_radio_button(
        decryption_options_frame_sym, "3DES", "3des-d", 2, 0)
    des3_radio.grid(row=2, column=0, padx=10, pady=10)

    # Asymmetric Encryption
    rsa_radio = create_radio_button(
        decryption_options_frame_asym, "RSA", "rsa-d", 0, 0)
    rsa_radio.grid(row=0, column=0, padx=10, pady=10)

# ===========================================================================================================================================================
# End Build Encrypt Frame
# ===========================================================================================================================================================


# ===========================================================================================================================================================
# Start Encrypt File
# ===========================================================================================================================================================

    # File Entry
    file_label = Label(frame, text="Enter File Path:")
    file_label.grid(row=2, column=0, padx=20, pady=10)
    file_entry = Entry(frame, width=40)
    file_entry.grid(row=2, column=0, columnspan=4, padx=10, pady=10)

    def browse_local():
        file_path = filedialog.askopenfilename()
        if file_path:
            file_entry.delete(0, END)
            file_entry.insert(0, file_path)
    browse_button = Button(
        frame, text="Browse Local", command=browse_local)
    browse_button.grid(row=2, column=2, columnspan=6,
                       padx=10, pady=10)

    # File Result Label
    file_result_label = Label(frame, text="Encypted File: ")
    file_result_label.grid(row=4, column=0, columnspan=4, padx=10, pady=10)

    def encrypt_file():
        file_path = file_entry.get()
        algorithm = selected_algorithm.get()
        if algorithm == "none":
            file_result_label.config(text="Please select a hashing algorithm")
            return

        if algorithm == "aes-e":
            current.encrypt_AES(file_path)
        elif algorithm == "aes-d":
            current.decrypt_AES(file_path)
        elif algorithm == "des-e":
            current.encrypt_DES(file_path)
        elif algorithm == "des-d":
            current.decrypt_DES(file_path)
        elif algorithm == "3des-e":
            current.encrypt_3DES(file_path)
        elif algorithm == "3des-d":
            current.decrypt_3DES(file_path)
        # elif algorithm == "sha3_384":
        #     hashed = current.hash_password_SHA3_384(password)
        # elif algorithm == "sha3_512":
        #     hashed = current.hash_password_SHA3_512(password)
        # elif algorithm == "sha3_shake128":
        #     hashed = current.hash_password_SHA3_shake128(password)
        # elif algorithm == "sha3_shake256":
        #     hashed = current.hash_password_SHA3_shake256(password)
        # elif algorithm == "md5":
        #     hashed = current.hash_password_md5(password)

        file_result_label.config(
            text=f"File saved to same directory")

    # File Hash Button
    file_hash_button = Button(frame, text="Execute", command=encrypt_file)
    file_hash_button.grid(row=6, column=0, columnspan=4, padx=10, pady=10)

# ===========================================================================================================================================================
# Start Encrypt File
# ===========================================================================================================================================================


# ===========================================================================================================================================================
# Start Refresh App
# ===========================================================================================================================================================

# ===========================================================================================================================================================
# End Refresh App
# ===========================================================================================================================================================
