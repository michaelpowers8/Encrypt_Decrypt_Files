import os
import re
import json
import stat
import time
import string
import secrets
import hashlib
import traceback
from xml_logging import XML_Logger
from pyAesCrypt import encryptStream, decryptStream

LOGGER_BASEPATH = os.path.dirname(os.path.abspath(__file__))
MASTER_PASSWORD_FILE = "C:/Code/Python/Encrypt_Decrypt_Files/Password_Data/Master_Password.secure"

class Single_File_Encryptor:
    def __init__(self,master_password:str,password_storage_file:str,logger:XML_Logger,password_length=12,buffer_size=64*1024):
        self.master_password:str = master_password
        self.password_storage_file:str = password_storage_file 
        self.password_length:int = password_length
        self.logger:XML_Logger = logger
        self.buffer_size = buffer_size
        self.master_password_hash:str = self.hash_password(self.master_password)
        self.master_password_verified:bool = self._verify_master_password()

    def _create_master_password_directory(self) -> None:
        if "/" in MASTER_PASSWORD_FILE:
            if not(os.path.isdir('/'.join(MASTER_PASSWORD_FILE.split("/")[:-1]))):
                os.makedirs('/'.join(MASTER_PASSWORD_FILE.split("/")[:-1]))
                return None
            else:
                return None
        elif "\\" in MASTER_PASSWORD_FILE:
            if not(os.path.isdir('\\'.join(MASTER_PASSWORD_FILE.split("\\")[:-1]))):
                os.makedirs('\\'.join(MASTER_PASSWORD_FILE.split("\\")[:-1]))
                return None
            else:
                return None
        return None

    def _verify_master_password(self) -> bool:
        self._create_master_password_directory()
        if not os.path.exists(MASTER_PASSWORD_FILE):
            with open(MASTER_PASSWORD_FILE, 'w', encoding='utf-8') as file:
                file.write(self.master_password_hash)
            os.system(f'icacls "{MASTER_PASSWORD_FILE}" /grant:r "%USERNAME%":R')
            os.chmod(MASTER_PASSWORD_FILE, stat.S_IREAD)
            os.system(f'attrib +h "{MASTER_PASSWORD_FILE}"')
            return True
        
        # Read stored hash and verify
        with open(MASTER_PASSWORD_FILE, 'r', encoding='utf-8') as file:
            stored_data = file.read()
        
        # Parse stored components (iterations:salt:hash)
        try:
            stored_iterations, stored_salt_hex, stored_hash_hex = stored_data.split(':')
            stored_salt = bytes.fromhex(stored_salt_hex)
        except ValueError:
            self.logger.log_to_xml(
                    message="Corrupted master password file. Could not parse salt/hash.",
                    basepath=self.logger.base_dir,
                    status="ERROR"
                )
            return False

        # Recompute hash using the STORED salt
        new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                self.master_password.encode(),
                stored_salt,
                int(stored_iterations)
            )
        
        return new_hash.hex() == stored_hash_hex  # Compare hashes

    def _contains_uppercase(self, password:str) -> bool:
        for character in password: 
            if character in string.ascii_uppercase:
                return True
        return False

    def _contains_lowercase(self, password:str) -> bool:
        for character in password: 
            if character in string.ascii_lowercase:
                return True
        return False

    def _contains_number(self, password:str) -> bool:
        for character in password: 
            if character in string.digits:
                return True
        return False

    def _contains_special_character(self, password:str) -> bool:
        for character in password: 
            if character in string.punctuation:
                return True
        return False

    def _verify_password(self, password:str) -> bool:
        return (self._contains_lowercase(password)) and (self._contains_uppercase(password)) and (self._contains_number(password)) and (self._contains_special_character(password))

    def generate_strong_password(self, length:int) -> str:
        """Generate cryptographically secure random password"""
        if(
            (not(isinstance(length,int))) 
          ):
            self.logger.log_to_xml(message=f"Failed to generate password. Invalid parameters passed. Length is of type {type(length)}. Must be an int",basepath=self.logger.base_dir,status="ERROR")
            return self.generate_strong_password(length=15)
        try:
            if(length < 10):
                raise ValueError("Password length must be at least 10 characters long")
            chars:str = string.ascii_letters + string.digits + string.punctuation
            chars:str = re.sub(r"[\\%\"\'\~\`]",'',chars)
            password:str = ''.join(secrets.choice(chars) for _ in range(length))
            while(not(self._verify_password(password=password))):
                password:str = ''.join(secrets.choice(chars) for _ in range(length))
            return password
        except Exception as e:
            self.logger.log_to_xml(message=f"Failed to generate password. Password length: {length}. Official error: {traceback.format_exc()}",basepath=self.logger.base_dir,status="ERROR")
            return self.generate_strong_password(length=15)

    def hash_password(self, password: str) -> str:
        salt = os.urandom(64)  # Add randomness
        iterations:int = 100_000   # Slow down attacks
        hash_value:bytes =  hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return f"{iterations}:{salt.hex()}:{hash_value.hex()}" 

    def _encrypt_data_file(self) -> None:
        if os.path.exists(self.password_storage_file):
            password_storage_file_encrypted:str = f"{self.password_storage_file}.aes"
            with open(self.password_storage_file, 'rb') as f_in, open(password_storage_file_encrypted, 'wb') as f_out:
                encryptStream(f_in, f_out, self.master_password, self.buffer_size)
            os.remove(self.password_storage_file)
            os.system(f'attrib +h "{password_storage_file_encrypted}"')

    def _decrypt_data_file(self) -> None:
        password_storage_file_encrypted:str = f"{self.password_storage_file}.aes"
        if os.path.exists(password_storage_file_encrypted):
            with open(password_storage_file_encrypted, 'rb') as f_in, open(self.password_storage_file, 'wb') as f_out:
                decryptStream(f_in, f_out, self.master_password, self.buffer_size)
            os.remove(password_storage_file_encrypted)
            os.system(f'attrib +h "{self.password_storage_file}"')

    def save_encryption_data(self, encrypted_path:str, password:str) -> bool|str:
        if(
            (not(isinstance(encrypted_path,str)))or 
            (not(len(encrypted_path.split('.'))>1))or 
            (not(encrypted_path.split('.')[-1].lower() == 'aes'))
          ):
            error_message:str = f"Encryption failed for {encrypted_path}. Invalid parameters passed. Encrypted path must be a string and end in .aes. Parameters passed: encrypted_path: {encrypted_path}"
            self.logger.log_to_xml(message=error_message,basepath=self.logger.base_dir,status="ERROR")
            return error_message
        try:
            self._decrypt_data_file()
        except Exception as e:
            self.logger.log_to_xml(message=f"Failed to decrypt password storage file. Official error: {traceback.format_exc()}",basepath=self.logger.base_dir,status="ERROR")
            return f"Failed to decrypt password storage file. Official error: {traceback.format_exc()}"
        try:
            if os.path.exists(self.password_storage_file) and os.path.getsize(self.password_storage_file) > 0:
                try:
                    with open(self.password_storage_file, "rb") as file:
                        data = json.loads(file.read().decode('utf-8'))
                except json.JSONDecodeError:
                    self.logger.log_to_xml(
                        message=f"Invalid JSON in {self.password_storage_file}, creating new file",
                        basepath=self.logger.base_dir,
                        status="WARNING"
                    )
                    data = {}
            else:
                data:dict[str,str] = {}
            data[encrypted_path] = password
            try:
                os.remove(self.password_storage_file)
            except:
                pass
            with open(self.password_storage_file, "wb") as file:
                file.write(json.dumps(data, indent=4).encode('utf-8'))  # Encode to bytes
            self._encrypt_data_file()
            return True
        except Exception as e:
            self.logger.log_to_xml(message=f"Failed to save encryption data for {encrypted_path} using password hash {self.hash_password(password)}. Official error: {traceback.format_exc()}",basepath=self.logger.base_dir,status="ERROR")
            return traceback.format_exc()

    def encrypt_file(self, file_path:str) -> bool:
        """Encrypt a file with AES-256"""
        valid_extensions:list[str] = ['txt','xml','pptx','py','json','eml','java','pdf','xls','xlsx','xlsm','cs','js','cpp','config','md','dll','exe']
        if(not(self.master_password_verified)):
            error_message:str = f"Encryption failed for {file_path}. Master password must match records. Password passed: {self.master_password}"
            self.logger.log_to_xml(message=error_message,basepath=self.logger.base_dir,status="ERROR")
            print(error_message)
            return False
        if(
            (not(isinstance(file_path,str)))or 
            (not(len(file_path.split('.'))>1))or 
            (not(file_path.split('.')[-1].lower() in valid_extensions))or
            (not(isinstance(self.password_storage_file,str)))or
            (not(self.master_password_verified))
          ):
            error_message:str = f"Encryption failed for {file_path}. Invalid parameters passed. Master password must match records, file path to encrypt must be of type {valid_extensions}. File path passed: {file_path}"
            self.logger.log_to_xml(message=error_message,basepath=self.logger.base_dir,status="ERROR")
            return False
        try:
            encrypted_path = f"{file_path}.aes"
            password:str = self.generate_strong_password(length=self.password_length)
            with open(file_path, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
                encryptStream(f_in, f_out, password, self.buffer_size)
            save_status:bool|str = self.save_encryption_data(encrypted_path,password)
            if isinstance(save_status,str):
                raise RuntimeError(save_status)
            os.remove(file_path) # Only remove original file if original file is encrypted AND password is properly saved
            return True
        except Exception as e:
            self.logger.log_to_xml(message=f"Encryption failed for {file_path}. Official error: {traceback.format_exc()}",basepath=self.logger.base_dir,status="ERROR")
            return False
