from cryptography.fernet import Fernet
import os
import json
from stat import S_IREAD
import sys
from pandas import DataFrame
import hashlib

def get_variable_info():
    # Get the current global and local variables
    globals_dict = globals()
    locals_dict = locals()
    
    # Combine them, prioritizing locals (to avoid duplicates)
    all_vars = {**globals_dict, **locals_dict}
    
    # Filter out modules, functions, and built-ins
    variable_info:list[dict[str,str|int|float|list|set|dict|bytes]] = []
    for name, value in all_vars.items():
        # Skip special variables, modules, and callables
        if name.startswith('__') and name.endswith('__'):
            continue
        if callable(value):
            continue
        if isinstance(value, type(sys)):  # Skip modules
            continue
            
        # Get variable details
        var_type:str = type(value).__name__
        try:
            var_hash:str = hashlib.sha256(str(value).encode('utf-8')).hexdigest()
        except Exception:
            var_hash:str = "Unhashable"
        
        var_size:int = sys.getsizeof(value)
        
        variable_info.append({
            "Variable Name": name,
            "Type": var_type,
            "Hash": var_hash,
            "Size (bytes)": var_size
        })
    
    # Convert to a DataFrame for nice tabular output
    df:DataFrame = DataFrame(variable_info)
    return df

def create_master_key() -> bytes:
    return Fernet.generate_key()

def get_master_key() -> bytes:
    try:
        with open("Master_Key.key","rb") as key_file:
            master_key:bytes = key_file.read()
        if(len(master_key)<1):
            raise Exception()
    except:
        master_key:bytes = create_master_key()
        with open("Master_Key.key","wb") as key_file:
            key_file.write(master_key)
        os.chmod("Master_Key.key", S_IREAD)
    return master_key

def is_file(path:str) -> bool:
    return os.path.isfile(path)

def read_file(full_path:str,current_file:str) -> str:
    with open(os.path.join(full_path,current_file),'rb') as file:
        contents:str = file.read()
    return contents

def write_contents_to_file(full_path:str,current_file:str,encrypted_contents:str):
    with open(os.path.join(full_path,current_file),'wb') as file:
        file.write(encrypted_contents)

def encrypt_all_non_coding_files_in_single_folder(full_path:str) -> None:
    try:
        all_files:list[str] = os.listdir(full_path)
        for current_file in all_files:
            if((current_file.split(".")[-1].lower() in ['txt','doc','docx','xlsx','xls','xlsm','pptx','zip']) and (is_file(os.path.join(full_path,current_file)))):
                original_contents:str = read_file(full_path,current_file)
                encrypted_contents:bytes = Fernet(get_master_key()).encrypt(original_contents)
                write_contents_to_file(full_path,current_file,encrypted_contents)            
    except Exception as e:
        print(str(e))

def decrypt_all_non_coding_files_in_single_folder(full_path:str) -> None:
    try:
        all_files:list[str] = os.listdir(full_path)
        for current_file in all_files:
            if((current_file.split(".")[-1].lower() in ['aes','txt','doc','docx','xlsx','xls','xlsm','pptx','zip']) and (is_file(os.path.join(full_path,current_file)))):
                print(current_file)
                encrypted_contents:str = read_file(full_path,current_file)
                original_contents:bytes = Fernet(get_master_key()).decrypt(encrypted_contents)
                write_contents_to_file(full_path,current_file,original_contents)            
    except Exception as e:
        print(str(e))

def load_configuraton() -> tuple[bool,bool]:
    with open("Config.json",'r') as file:
        data:dict[str,bool] = json.load(file)
    return data["Encrypt"],data["Decrypt"]

def main():
    full_path:str = "C:/Code/Python/Encrypt_Decrypt_Files"
    encrypt_files,decrypt_files = load_configuraton()
    if(encrypt_files):
        encrypt_all_non_coding_files_in_single_folder(full_path)
    if(decrypt_files):
        decrypt_all_non_coding_files_in_single_folder(full_path)
    
if __name__ == "__main__":
    main()
    variable_table:DataFrame = get_variable_info()
    variable_table.to_json("Fernet_Encryption_End_Variables.json",index=False,indent=4,orient='table')