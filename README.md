# 🔐 Secure File Encryptor

A robust command-line tool for securely encrypting and decrypting files and directories using modern, authenticated encryption (AES-256-GCM). It features a secure key derivation mechanism (PBKDF2) and a user-friendly, interactive menu.

## 🌟 Key Features

- **Modern Authenticated Encryption**: Utilizes AES-256-GCM to provide both confidentiality and integrity, ensuring your files are not only unreadable but also protected from tampering.

- **Secure Password Handling**: Implements PBKDF2 with a random salt and a high iteration count (100,000) to derive a strong encryption key from your password, protecting against brute-force and dictionary attacks.

- **Memory Efficient**: Processes files in manageable chunks (64 KB), allowing it to encrypt and decrypt very large files with minimal memory consumption.

- **Interactive & User-Friendly**: Features a simple, colored, menu-driven interface that makes it easy to use without needing to remember complex commands.

- **Self-Contained Encrypted Files**: Creates a single, secure output file (.saef) for each input file, simplifying file management.

- **Directory Processing**: Can recursively encrypt or decrypt all files within a specified directory.

- **Cross-Platform**: Built with standard Python libraries to ensure it runs smoothly on Windows, macOS, and Linux.

## 🛠️ Requirements

- Python 3.6 or higher
- pycryptodome
- colorama

## 🚀 Installation

1. Clone the repository or download the script:

   ```bash
   git clone https://github.com/Raafay892/secure_file_encryptor.git
   cd secure_file_encryptor

2. Install the required libraries using pip:

   ```bash
   pip install pycryptodome colorama

##▶️ How to Use

Run the script from your terminal to launch the interactive menu.

   ```bash
   python3 secure_encryptor.py

You will be presented with the following options:

```
==============================
    SECURE FILE ENCRYPTOR
==============================
1. Encrypt a File or Directory
2. Decrypt a File or Directory
3. Exit
------------------------------
Enter your choice (1-3):
```

* Select an option (1, 2, or 3).
* Enter the full path to the file or directory you want to process.
* Enter your password when prompted. For encryption, you will be asked to confirm it.
* The script will handle the rest and provide status messages for the operations. The original file will be automatically and securely removed after a successful operation.

## ⚙️ How It Works

### Encryption Process

1. A secure random salt is generated.
2. Your password and the salt are run through PBKDF2 to derive a strong 256-bit encryption key.
3. A unique nonce (number used once) is generated for the AES-GCM cipher.
4. The file is read in chunks, and each chunk is encrypted.
5. The final encrypted file is created with the following structure: `[SALT][NONCE][ENCRYPTED DATA][AUTHENTICATION TAG]`.

### Decryption Process

1. The salt, nonce, and authentication tag are read from the encrypted file.
2. The same PBKDF2 process is used with your password and the extracted salt to re-derive the exact same encryption key.
3. The encrypted data is decrypted chunk by chunk.
4. Finally, the authentication tag is verified. If the verification succeeds, the file is authentic and unaltered. If it fails, it means the file has been corrupted, tampered with, or the password was incorrect.

## ⚠️ Important Security Notice

**DO NOT FORGET YOUR PASSWORD.**

Due to the secure nature of the encryption, there is no way to recover a forgotten password. The encrypted files will be permanently inaccessible without the correct password.

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.



