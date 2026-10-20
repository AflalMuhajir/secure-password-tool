# Secure Password Tool

A lightweight, pure C command-line tool for generating strong passwords, analyzing password strength, and encrypting/decrypting data using **AES-256-CBC**.

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Features

- Cryptographically secure password generator
- Configurable character sets (lowercase, uppercase, digits, symbols)
- Option to exclude ambiguous characters (`0 O 1 l I`)
- Password strength analyzer (entropy estimation + common pattern detection)
- AES-256-CBC encryption & decryption with random IV
- Cross-platform (Windows, Linux, macOS)
- No external dependencies (uses only system libraries)
- Clean and educational codebase — great for learning secure coding

## Screenshots

## Building

### Requirements
- GCC or Clang
- Make (optional)

### Linux / macOS
```bash
make
./pass_tool

gcc -o pass_tool.exe src/main.c src/aes.c -O2 -Wall -lm -lbcrypt

secure-password-tool/
├── src/
│   ├── main.c          # Main program
│   ├── aes.c           # Tiny AES implementation
│   └── aes.h
├── .gitignore
├── LICENSE
├── Makefile
├── README.md
└── SECURITY.md


