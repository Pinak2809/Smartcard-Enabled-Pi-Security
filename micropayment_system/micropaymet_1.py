import logging
import json
import time
import struct
import os
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException, NoCardException
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MicroPaymentSystem:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.load_config()
        self.reader = None
        self.connection = None

    def load_config(self):
        config_file = 'config.json'
        default_config = {
            "balance_block": 4,
            "key_a": [255, 255, 255, 255, 255, 255],
            "log_file": "transaction_log.txt"
        }

        if not os.path.exists(config_file):
            self.logger.warning(f"Configuration file {config_file} not found. Creating with default values.")
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)

        try:
            with open(config_file, 'r') as file:
                config = json.load(file)
            self.balance_block = config.get('balance_block', default_config['balance_block'])
            self.key_a = config.get('key_a', default_config['key_a'])
            self.log_file = config.get('log_file', default_config['log_file'])
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.logger.info("Using default configuration.")
            self.balance_block = default_config['balance_block']
            self.key_a = default_config['key_a']
            self.log_file = default_config['log_file']

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
            # Don't connect here, we'll do it in wait_for_card
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

    def authenticate(self, block):
        try:
            auth = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, 0x60, 0x00]
            response, sw1, sw2 = self.connection.transmit(auth)
            if sw1 == 0x90 and sw2 == 0x00:
                return True
            else:
                self.logger.warning(f"Authentication failed. SW1: {sw1:02X}, SW2: {sw2:02X}")
                return False
        except Exception as e:
            self.logger.error(f"Error during authentication: {e}")
            return False

    @contextmanager
    def authenticated_operation(self, block):
        if self.authenticate(block):
            try:
                yield
            finally:
                pass  # No specific cleanup needed after authentication
        else:
            raise Exception("Authentication failed")

    def read_balance(self):
        try:
            with self.authenticated_operation(self.balance_block):
                read_command = [0xFF, 0xB0, 0x00, self.balance_block, 0x10]
                data, sw1, sw2 = self.connection.transmit(read_command)
                if sw1 == 0x90 and sw2 == 0x00:
                    return struct.unpack('>I', bytes(data[:4]))[0]
                else:
                    self.logger.warning(f"Error reading balance. SW1: {sw1:02X}, SW2: {sw2:02X}")
                    return None
        except Exception as e:
            self.logger.error(f"Error reading balance: {e}")
            return None

    def write_balance(self, balance):
        try:
            with self.authenticated_operation(self.balance_block):
                balance_bytes = struct.pack('>I', balance) + bytes([0] * 12)  # Pad to 16 bytes
                write_command = [0xFF, 0xD6, 0x00, self.balance_block, 0x10] + list(balance_bytes)
                _, sw1, sw2 = self.connection.transmit(write_command)
                if sw1 == 0x90 and sw2 == 0x00:
                    return True
                else:
                    self.logger.warning(f"Error writing balance. SW1: {sw1:02X}, SW2: {sw2:02X}")
                    return False
        except Exception as e:
            self.logger.error(f"Error writing balance: {e}")
            return False

    def add_funds(self, amount):
        current_balance = self.read_balance()
        if current_balance is not None:
            new_balance = current_balance + amount
            if self.write_balance(new_balance):
                self.logger.info(f"Successfully added {amount}. New balance: {new_balance}")
                self.log_transaction("ADD", amount, new_balance)
                return new_balance
            else:
                self.logger.error("Failed to add funds.")
                return None
        else:
            self.logger.error("Failed to read current balance.")
            return None

    def make_payment(self, amount):
        current_balance = self.read_balance()
        if current_balance is not None:
            if current_balance >= amount:
                new_balance = current_balance - amount
                if self.write_balance(new_balance):
                    self.logger.info(f"Payment of {amount} successful. New balance: {new_balance}")
                    self.log_transaction("PAYMENT", amount, new_balance)
                    return new_balance
                else:
                    self.logger.error("Failed to process payment.")
                    return None
            else:
                self.logger.warning("Insufficient funds.")
                return None
        else:
            self.logger.error("Failed to read current balance.")
            return None

    def log_transaction(self, transaction_type, amount, new_balance):
        try:
            with open(self.log_file, "a") as log_file:
                log_file.write(f"{time.time()},{transaction_type},{amount},{new_balance}\n")
        except Exception as e:
            self.logger.error(f"Error logging transaction: {e}")

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
    mps = MicroPaymentSystem()
    
    if mps.connect_reader():
        try:
            while True:
                uid = mps.wait_for_card()
                balance = mps.read_balance()
                print(f"Current balance: {balance}")
                
                print("\nOptions:")
                print("1. Add Funds")
                print("2. Make a Payment")
                print("3. Quit")
                
                action = input("Select an option (1/2/3): ").strip()
                if action == '1':
                    amount = int(input("Enter amount to add: "))
                    new_balance = mps.add_funds(amount)
                    if new_balance is not None:
                        print(f"New balance: {new_balance}")
                elif action == '2':
                    amount = int(input("Enter payment amount: "))
                    new_balance = mps.make_payment(amount)
                    if new_balance is not None:
                        print(f"New balance: {new_balance}")
                elif action == '3':
                    break
                else:
                    print("Invalid option. Please try again.")
                
                print("Remove card and press Enter to continue...")
                input()
                print("Waiting for next card...")
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
        finally:
            mps.close()

if __name__ == "__main__":
    main()