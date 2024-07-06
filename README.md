# Smartcard-Based Security System

This project implements a comprehensive security system using smartcards for embedded systems. It consists of three main components: a Micro Payment System, an Access Control System, and a Secure File System.

## Features

- **Micro Payment System**: Manage funds and transactions using smartcards
- **Access Control System**: Control physical access using smartcards with challenge-response authentication
- **Secure File System**: Encrypt and decrypt files with two-factor authentication (smartcard + PIN)

## Requirements

- Python 3.7+
- pyscard
- cryptography

## Installation

1. Clone this repository:
2. Install required packages:
   logging (standard library)
   json (standard library)
   time (standard library)
   struct (standard library)
   os (standard library)
   contextlib (standard library)
   smartcard (from pyscard library)
     System
     util
     Exceptions (CardConnectionException, NoCardException)  
   cryptography  
     hazmat.primitives.hashes
     hazmat.primitives.asymmetric.rsa
     hazmat.primitives.asymmetric.padding
     hazmat.primitives.serialization
     hazmat.primitives.ciphers
     hazmat.backends

## Usage

### Micro Payment System

Run the Micro Payment System:
Follow the on-screen prompts to add funds, make payments, or check balance.

### Access Control System

Run the Access Control System:
Use this system to manage user access and simulate access attempts to different areas.

### Secure File System

Run the Secure File System:
Register new users, encrypt files, and decrypt files using smartcards and PINs.

## Configuration

Each system uses a JSON configuration file:

- `config.json` for Micro Payment System
- `security_config.json` for Access Control System
- `secure_file_config.json` for Secure File System

Modify these files to customize system behavior.

## Security Features

- RSA-based challenge-response authentication
- AES encryption for file security
- Two-factor authentication (smartcard + PIN)
- Secure key management
- Transaction and access logging

## Acknowledgments

- Thanks to the pyscard and cryptography library developers
- Inspired by real-world embedded security systems
