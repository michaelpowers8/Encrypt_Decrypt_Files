from cryptography.fernet import Fernet
import os

def create_master_key() -> bytes:
    return Fernet.generate_key()

def get_master_key() -> bytes:
    try:
        with open("Master_Key.key","rb") as key_file:
            master_key:bytes = key_file.read()
    except:
        master_key:bytes = create_master_key()
        with open("Master_Key.key","wb") as key_file:
            key_file.write(master_key)
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
            if((current_file.split(".")[-1].lower() in ['txt','doc','docx','xlsx','xls','xlsm','pptx','zip']) and (is_file(os.path.join(full_path,current_file)))):
                encrypted_contents:str = read_file(full_path,current_file)
                original_contents:bytes = Fernet(get_master_key()).decrypt(encrypted_contents)
                write_contents_to_file(full_path,current_file,original_contents)            
    except Exception as e:
        print(str(e))

def main():
    full_path:str = "C:/Code/Python/Encrypt_Decrypt_Files"
    encrypt_all_non_coding_files_in_single_folder(full_path)
    decrypt_all_non_coding_files_in_single_folder(full_path)
    

if __name__ == "__main__":
    main()