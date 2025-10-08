#!/usr/bin/env python3
################################################################################
#
# Secure File Encryptor
#
# Description:
#   A robust command-line tool for securely encrypting and decrypting files and
#   directories using modern, authenticated encryption (AES-256-GCM). It replaces
#   outdated practices with a secure, streamlined workflow.
#
# Key Improvements Over Original Script:
#   - Modern Cryptography: Uses AES-256-GCM for authenticated encryption,
#     providing both confidentiality and integrity. This prevents tampering.
#   - Secure Key Derivation: Implements PBKDF2 with a random salt and high
#     iteration count to protect against brute-force and dictionary attacks.
#   - Simplified Workflow: Eliminates the complex and fragile system of
#     splitting files into parts and managing them with a database. It creates a
#     single, secure output file for each input file.
#   - Efficient Memory Usage: Processes files in chunks (streaming), allowing it
#     to encrypt/decrypt very large files with minimal memory consumption.
#   - Robust Error Handling: Provides clear error messages for incorrect
#     passwords (authentication failure), file-not-found, and other issues.
#   - User-Friendly CLI: Uses an interactive, colored menu for ease of use.
#   - Cross-Platform Compatibility: Built with standard Python libraries to ensure
#     it runs smoothly on Windows, macOS, and Linux.
#
# Author: Gemini
# Date: October 8, 2025
#
################################################################################

import os
import sys
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# --- Third-party library for colored output ---
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
except ImportError:
    print("Warning: 'colorama' library not found. Colors will not be displayed.")
    print("Please install it using: pip install colorama")
    # Create dummy Fore and Style classes if colorama is not available
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()


# --- Configuration Constants ---
SALT_SIZE = 16
KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 16 # GCM nonce size
TAG_SIZE = 16 # GCM authentication tag size
PBKDF2_ITERATIONS = 100000  # A good standard for 2025
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming
FILE_EXTENSION = ".saef" # Secure Authenticated Encrypted File

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_key(password: str, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt_file(input_path: str, output_path: str, password: str) -> bool:
    """
    Encrypts a single file using AES-256-GCM.
    The output file format is: [SALT][NONCE][ENCRYPTED_DATA][AUTHTAG]
    """
    if not os.path.exists(input_path):
        print(f"{Fore.RED}Error: Input file not found at '{input_path}'")
        return False

    salt = get_random_bytes(SALT_SIZE)
    key = get_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        with open(input_path, 'rb') as fi, open(output_path, 'wb') as fo:
            fo.write(salt)
            fo.write(nonce)
            while True:
                chunk = fi.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                encrypted_chunk = cipher.encrypt(chunk)
                fo.write(encrypted_chunk)
            tag = cipher.digest()
            fo.write(tag)
        print(f"{Fore.GREEN}✅ Successfully encrypted '{input_path}' to '{output_path}'")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ An error occurred during encryption: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False

def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
    """
    Decrypts a single file encrypted with AES-256-GCM.
    Reads the file in the format: [SALT][NONCE][ENCRYPTED_DATA][AUTHTAG]
    """
    if not os.path.exists(input_path):
        print(f"{Fore.RED}Error: Input file not found at '{input_path}'")
        return False

    file_size = os.path.getsize(input_path)
    if file_size < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        print(f"{Fore.RED}❌ Decryption failed: File is corrupted or not a valid encrypted file.")
        return False

    try:
        with open(input_path, 'rb') as fi:
            salt = fi.read(SALT_SIZE)
            nonce = fi.read(NONCE_SIZE)
            fi.seek(-TAG_SIZE, os.SEEK_END)
            tag = fi.read(TAG_SIZE)
            key = get_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            fi.seek(SALT_SIZE + NONCE_SIZE)
            
            ciphertext_size = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE
            bytes_processed = 0
            with open(output_path, 'wb') as fo:
                while bytes_processed < ciphertext_size:
                    bytes_to_read = min(CHUNK_SIZE, ciphertext_size - bytes_processed)
                    chunk = fi.read(bytes_to_read)
                    if not chunk: break
                    decrypted_chunk = cipher.decrypt(chunk)
                    fo.write(decrypted_chunk)
                    bytes_processed += len(chunk)
            try:
                cipher.verify(tag)
                print(f"{Fore.GREEN}✅ Successfully decrypted '{input_path}' to '{output_path}'")
                return True
            except ValueError:
                print(f"{Fore.RED}❌ Decryption failed: Incorrect password or corrupted file.")
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False
    except Exception as e:
        print(f"{Fore.RED}❌ An error occurred during decryption: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False

def process_directory(path: str, password: str, action: callable):
    """Recursively encrypts or decrypts all files in a directory."""
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        print(f"{Fore.RED}Error: '{path}' is not a valid directory.")
        return

    print(f"{Style.BRIGHT}Processing directory: '{path}'...")
    for root, _, files in os.walk(path):
        for filename in files:
            input_path = os.path.join(root, filename)
            if action == encrypt_file and filename.endswith(FILE_EXTENSION):
                print(f"{Fore.YELLOW}-> Skipping already encrypted file: {filename}")
                continue
            if action == decrypt_file and not filename.endswith(FILE_EXTENSION):
                print(f"{Fore.YELLOW}-> Skipping non-encrypted file: {filename}")
                continue
            
            output_path = input_path + FILE_EXTENSION if action == encrypt_file else input_path[:-len(FILE_EXTENSION)]
            if action(input_path, output_path, password):
                os.remove(input_path)

def main():
    """Main function to display the menu and handle user input."""
    while True:
        clear_screen()
        print(f"{Style.BRIGHT}{Fore.CYAN}==============================")
        print(f"{Style.BRIGHT}{Fore.CYAN}    SECURE FILE ENCRYPTOR")
        print(f"{Style.BRIGHT}{Fore.CYAN}==============================")
        print(f"{Fore.GREEN}1. Encrypt a File or Directory")
        print(f"{Fore.YELLOW}2. Decrypt a File or Directory")
        print(f"{Fore.RED}3. Exit")
        print("------------------------------")
        
        choice = input(f"{Style.BRIGHT}Enter your choice (1-3): ")

        if choice == '1' or choice == '2':
            path = input("Enter the full path to the file or directory: ").strip()
            if not os.path.exists(path):
                print(f"{Fore.RED}Error: The specified path does not exist: '{path}'")
                input("\nPress Enter to continue...")
                continue
            
            try:
                password = getpass.getpass("Enter password: ")
                if not password:
                    print(f"{Fore.RED}Error: Password cannot be empty.")
                    input("\nPress Enter to continue...")
                    continue

                if choice == '1': # Encrypt
                    password_confirm = getpass.getpass("Confirm password: ")
                    if password != password_confirm:
                        print(f"{Fore.RED}Passwords do not match.")
                        input("\nPress Enter to continue...")
                        continue
                    action = encrypt_file
                else: # Decrypt
                    action = decrypt_file

                if os.path.isfile(path):
                    output_path = path + FILE_EXTENSION if choice == '1' else path[:-len(FILE_EXTENSION)]
                    if action(path, output_path, password):
                        os.remove(path)
                elif os.path.isdir(path):
                    process_directory(path, password, action)

            except Exception as e:
                print(f"{Fore.RED}An unexpected error occurred: {e}")

        elif choice == '3':
            print(f"{Fore.CYAN}Exiting program. Goodbye!")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()

