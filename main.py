import os
import json
import string
from typing import Any
from xml_logging import XML_Logger
from encryptor import Single_File_Encryptor,MASTER_PASSWORD_FILE

LOGGER_BASEPATH = os.path.dirname(os.path.abspath(__file__))

def _contains_uppercase(password:str) -> bool:
    for character in password: 
        if character in string.ascii_uppercase:
            return True
    return False

def _contains_lowercase(password:str) -> bool:
    for character in password: 
        if character in string.ascii_lowercase:
            return True
    return False

def _contains_number(password:str) -> bool:
    for character in password: 
        if character in string.digits:
            return True
    return False

def _contains_special_character(password:str) -> bool:
    for character in password: 
        if character in string.punctuation:
            return True
    return False

def _verify_password(password:str,min_password_length:int) -> bool:
    return (len(password) >= min_password_length) and(_contains_lowercase(password)) and (_contains_uppercase(password)) and (_contains_number(password)) and (_contains_special_character(password))

def get_master_password(min_password_length:int) -> str:
    password:str = input("Enter master password.\n")
    if os.path.exists(MASTER_PASSWORD_FILE):
        return password
    while not(_verify_password(password,min_password_length)):
        print(f"\nPassword must contain at least {min_password_length:,.0f} characters and have at least 1 lowercase, 1 uppercase, 1 number, and 1 special character.")
        password:str = input("Enter master password.\n")
    os.system('cls')
    return password

def _verify_configuration(configuration:dict[str,Any]) -> bool:
    required_keys:list[str] = ["File_To_Encrypt","Minimum_Master_Password_Length","Password_Storage_File","Buffer_Size"]
    missing_keys:list[str] = []

    for key in required_keys:
        if key not in configuration.keys():
            missing_keys.append(key)

    if len(missing_keys) > 0:
        print(f"Configuration could not be verified. Missing keys {','.join(missing_keys)}. Terminating program")
        return False
    return True

def get_configuration(config_filename:str) -> dict[str,Any]|None:
    try:
        if os.path.exists(config_filename):
            with open(config_filename,"r") as file:
                configuration:dict[str,Any] = json.load(file)
            if(_verify_configuration(configuration)):
                return configuration
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f"Failed to get configuration from {config_filename}. Terminating program")
        return None

def valid_file_to_encrypt(file:str):
    if not(os.path.exists(file)):
        return False
    if not(os.path.isfile(file)):
        return False
    return True
       
def main():
    logger:XML_Logger = XML_Logger(log_file="Encrypt_Files_Logger",archive_folder="archive",log_retention_days=7,base_dir=LOGGER_BASEPATH)
    configuration:dict[str,int|str] = get_configuration("Configuration.json")
    if configuration is None:
        return None
    password:str = get_master_password(configuration["Minimum_Master_Password_Length"])
    encryptor:Single_File_Encryptor = Single_File_Encryptor(
                master_password=password,
                password_storage_file=configuration["Password_Storage_File"],
                logger=logger,
                password_length=1000,
                buffer_size=configuration["Buffer_Size"]
            )
    if(valid_file_to_encrypt(configuration["File_To_Encrypt"])):
        encryptor.encrypt_file(configuration["File_To_Encrypt"])
    logger.save_variable_info(globals_dict=globals(),locals_dict=locals(),variable_save_path="Encrypt_Files_Variables.json") 

if __name__ == "__main__":
    main()
    