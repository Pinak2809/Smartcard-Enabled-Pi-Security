import os
import json
import logging
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureFileSystem:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.load_config()
        self.reader = None
        self.connection = None
        self.users = self.load_users()

    def load_config(self):
        config_file = 'secure_file_config.json'
        default_config = {
            "uid_block": 0,
            "key_a": [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            "secure_folder": "secure_files"
        }

        if not os.path.exists(config_file):
            self.logger.warning(f"Configuration file {config_file} not found. Creating with default values.")
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)

        try:
            with open(config_file, 'r') as file:
                config = json.load(file)
            self.uid_block = config.get('uid_block', default_config['uid_block'])
            self.key_a = config.get('key_a', default_config['key_a'])
            self.secure_folder = config.get('secure_folder', default_config['secure_folder'])
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.logger.info("Using default configuration.")
            self.uid_block = default_config['uid_block']
            self.key_a = default_config['key_a']
            self.secure_folder = default_config['secure_folder']

        if not os.path.exists(self.secure_folder):
            os.makedirs(self.secure_folder)

    def load_users(self):
        try:
            with open('users.json', 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            self.logger.warning("Users file not found. Creating empty users database.")
            return {}
        except json.JSONDecodeError:
            self.logger.error("Error decoding users file. Starting with empty users database.")
            return {}

    def save_users(self):
        with open('users.json', 'w') as file:
            json.dump(self.users, file, indent=4)

    def connect_reader(self):
        try:
            available_readers = readers()
            if not available_readers:
                self.logger.error("No readers found.")
                return False
            
            self.logger.info("Available readers:")
            for i, reader in enumerate(available_readers):
                self.logger.info(f"{i}: {reader}")
            
            self.reader = available_readers[0]  # Use the first reader
            self.logger.info(f"Using reader: {self.reader}")
            self.connection = self.reader.createConnection()
            self.logger.info("Reader initialized. Waiting for card...")
            return True
        except Exception as e:
            self.logger.error(f"Error initializing reader: {e}")
            return False

    def wait_for_card(self):
        print("Please insert your card...")
        while True:
            try:
                self.connection.connect()
                uid = self.read_card()
                if uid:
                    self.logger.info(f"Card detected. UID: {uid}")
                    return uid
            except (CardConnectionException, NoCardException):
                time.sleep(0.5)
            except Exception as e:
                self.logger.error(f"Unexpected error while waiting for card: {e}")
                time.sleep(0.5)

    def read_card(self):
        try:
            get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            data, sw1, sw2 = self.connection.transmit(get_uid)
            
            if sw1 == 0x90 and sw2 == 0x00:
                return toHexString(data)
            else:
                self.logger.warning(f"Failed to read card UID. SW1: {sw1:02X}, SW2: {sw2:02X}")
                return None
        except Exception as e:
            self.logger.error(f"Error reading card: {e}")
            return None

    def authenticate_user(self, uid):
        if uid not in self.users:
            print("Card not recognized. Please register first.")
            return False

        pin_attempt = input("Enter your PIN: ")
        if pin_attempt == self.users[uid]['pin']:
            print("Authentication successful.")
            return True
        else:
            print("Incorrect PIN.")
            return False

    def register_user(self):
        uid = self.wait_for_card()
        if uid in self.users:
            print("This card is already registered.")
            return

        name = input("Enter your name: ")
        pin = input("Create a PIN: ")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        self.users[uid] = {
            'name': name,
            'pin': pin,
            'private_key': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        }
        self.save_users()
        print(f"User {name} registered successfully.")

    def encrypt_file(self, uid, filename):
        if not self.authenticate_user(uid):
            return

        file_path = os.path.join(self.secure_folder, filename)
        if not os.path.exists(file_path):
            print(f"File {filename} not found in secure folder.")
            return

        with open(file_path, 'rb') as file:
            data = file.read()

        public_key = serialization.load_pem_public_key(
            self.users[uid]['public_key'].encode('utf-8'),
            backend=default_backend()
        )

        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(file_path + '.encrypted', 'wb') as file:
            file.write(encrypted_data)

        os.remove(file_path)
        print(f"File {filename} encrypted successfully.")

    def decrypt_file(self, uid, filename):
        if not self.authenticate_user(uid):
            return

        file_path = os.path.join(self.secure_folder, filename + '.encrypted')
        if not os.path.exists(file_path):
            print(f"Encrypted file {filename}.encrypted not found in secure folder.")
            return

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        private_key = serialization.load_pem_private_key(
            self.users[uid]['private_key'].encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(os.path.join(self.secure_folder, filename), 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)
        print(f"File {filename} decrypted successfully.")

def main():
    secure_fs = SecureFileSystem()
    
    if secure_fs.connect_reader():
        try:
            while True:
                print("\nOptions:")
                print("1. Register new user")
                print("2. Encrypt file")
                print("3. Decrypt file")
                print("4. Quit")
                
                choice = input("Select an option (1/2/3/4): ").strip()
                
                if choice == '1':
                    secure_fs.register_user()
                elif choice == '2':
                    uid = secure_fs.wait_for_card()
                    filename = input("Enter the filename to encrypt: ")
                    secure_fs.encrypt_file(uid, filename)
                elif choice == '3':
                    uid = secure_fs.wait_for_card()
                    filename = input("Enter the filename to decrypt: ")
                    secure_fs.decrypt_file(uid, filename)
                elif choice == '4':
                    break
                else:
                    print("Invalid option. Please try again.")
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
        finally:
            if secure_fs.connection:
                secure_fs.connection.disconnect()

if __name__ == "__main__":
    main()