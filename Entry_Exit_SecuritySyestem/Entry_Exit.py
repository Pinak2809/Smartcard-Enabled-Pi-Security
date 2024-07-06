import logging
import json
import time
import struct
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecuritySystem:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.load_config()
        self.reader = None
        self.connection = None
        self.users = self.load_users()
        self.private_key = self.load_or_generate_key()

    def load_config(self):
        config_file = 'security_config.json'
        default_config = {
            "uid_block": 0,
            "key_a": [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            "log_file": "access_log.txt"
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
            self.log_file = config.get('log_file', default_config['log_file'])
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.logger.info("Using default configuration.")
            self.uid_block = default_config['uid_block']
            self.key_a = default_config['key_a']
            self.log_file = default_config['log_file']

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

    def load_or_generate_key(self):
        key_file = 'private_key.pem'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        return private_key

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
        print("Waiting for card...")  # Print this message for user feedback
        while True:
            try:
                self.connection.connect()
                uid = self.read_card()
                if uid:
                    self.logger.info(f"Card detected. UID: {uid}")
                    return uid
            except (CardConnectionException, NoCardException):
                # Card not present, wait silently
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

    def challenge_response_auth(self, uid):
        if uid not in self.users:
            return False

        # Generate a random challenge
        challenge = os.urandom(32)

        # Sign the challenge with the private key
        signature = self.private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # In a real-world scenario, you would send the challenge to the card
        # and receive a response. Here, we're simulating that process.

        # Verify the signature (in a real scenario, this would be done on the card)
        try:
            self.private_key.public_key().verify(
                signature,
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def check_access(self, uid, area):
        if uid not in self.users:
            return False
        return area in self.users[uid]['access_areas']

    def log_access(self, uid, area, access_granted):
        with open(self.log_file, "a") as log_file:
            log_file.write(f"{time.time()},{uid},{self.users.get(uid, {}).get('name', 'Unknown')},{area},{access_granted}\n")

    def add_user(self, uid, name, access_areas):
        self.users[uid] = {
            'name': name,
            'access_areas': access_areas
        }
        self.save_users()
        self.logger.info(f"User {name} added with UID {uid} and access to {', '.join(access_areas)}")

    def remove_user(self, uid):
        if uid in self.users:
            name = self.users[uid]['name']
            del self.users[uid]
            self.save_users()
            self.logger.info(f"User {name} with UID {uid} removed")
        else:
            self.logger.warning(f"No user found with UID {uid}")

    def save_users(self):
        with open('users.json', 'w') as file:
            json.dump(self.users, file, indent=4)

    def close(self):
        if self.connection:
            try:
                self.connection.disconnect()
                self.logger.info("Connection closed.")
            except CardConnectionException:
                self.logger.info("No card to disconnect.")
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")

def main():
    security_system = SecuritySystem()
    
    if security_system.connect_reader():
        try:
            while True:
                print("\nOptions:")
                print("1. Wait for card")
                print("2. Add user")
                print("3. Quit")
                
                choice = input("Select an option (1/2/3): ").strip()
                
                if choice == '1':
                    uid = security_system.wait_for_card()
                    if security_system.challenge_response_auth(uid):
                        print(f"Card authenticated. User: {security_system.users.get(uid, {}).get('name', 'Unknown')}")
                        area = input("Enter the area you're trying to access: ").strip()
                        if security_system.check_access(uid, area):
                            print(f"Access granted to {area}")
                            security_system.log_access(uid, area, True)
                        else:
                            print(f"Access denied to {area}")
                            security_system.log_access(uid, area, False)
                    else:
                        print("Authentication failed.")
                    
                    input("Please remove the card and press Enter...")
                    while security_system.read_card():
                        time.sleep(0.1)
                    print("Card removed.")
                
                elif choice == '2':
                    uid = input("Enter the UID of the card (e.g., E3 CB 43 E8): ").strip().upper()
                    if not all(c in '0123456789ABCDEF ' for c in uid):
                        print("Invalid UID format. Please use hexadecimal characters and spaces only.")
                        continue
                    name = input("Enter the user's name: ").strip()
                    if not name:
                        print("Name cannot be empty.")
                        continue
                    areas = input("Enter access areas (comma-separated): ").strip().split(',')
                    areas = [area.strip() for area in areas if area.strip()]
                    if not areas:
                        print("At least one access area must be specified.")
                        continue
                    security_system.add_user(uid, name, areas)
                    print(f"User {name} added successfully.")
                
                elif choice == '3':
                    break
                
                else:
                    print("Invalid option. Please try again.")
                
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
        finally:
            security_system.close()

if __name__ == "__main__":
    main()