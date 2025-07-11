# Encrypt & Decrypt Files

A simple Python tool for encrypting and decrypting files using AES-256 encryption.

![GitHub](https://img.shields.io/github/license/michaelpowers8/Encrypt_Decrypt_Files)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)

## Features

- 🔒 AES-256 encryption for file security
- 📁 Supports encryption/decryption of any file type
- 🔑 Password-based key derivation (PBKDF2)
- 🛡️ Salted hashing for enhanced security
- 🚀 Simple command-line interface

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/michaelpowers8/Encrypt_Decrypt_Files.git
   cd Encrypt_Decrypt_Files
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Encrypt a file:
```bash
python encrypt_decrypt.py -e -i input_file.txt -o encrypted_file.enc
```

### Decrypt a file:
```bash
python encrypt_decrypt.py -d -i encrypted_file.enc -o decrypted_file.txt
```

### Options:
- `-e` or `--encrypt`: Encrypt mode
- `-d` or `--decrypt`: Decrypt mode
- `-i` or `--input`: Input file path
- `-o` or `--output`: Output file path
- `-p` or `--password`: Provide password as argument (optional, will prompt if not provided)

## Security Notes

- The same password is required for decryption as was used for encryption
- Do not lose your password - there is no recovery mechanism
- For maximum security, use a strong, complex password

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Author

Michael Powers - [GitHub](https://github.com/michaelpowers8)