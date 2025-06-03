import sys,hashlib,json,base64,os
from pyAesCrypt import encryptStream,decryptStream
from Crypto.Random import get_random_bytes
from pandas import DataFrame
from stat import S_IREAD

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

def generate_key_iv() -> tuple[bytes,bytes]:
    """
    Generate a random 64-byte AES key and 16-byte IV.
    """
    key:bytes = get_random_bytes(64)  # 32 bytes = 256-bit AES key
    iv:bytes = get_random_bytes(16)   # 16 bytes = block size for AES
    return key, iv

def get_key_iv() -> tuple[bytes,bytes]:
    try:
        os.chmod("Key_IV.json",mode=S_IREAD)
    except:pass
    try:
        with open("Key_IV.json","r") as file:
            data:dict[str,bytes] = json.load(file)
        key:bytes = base64.b64decode(data["Key"])  # Convert back to bytes
        iv:bytes = base64.b64decode(data["IV"])
    except:
        key,iv = generate_key_iv()
        data = {
            "Key": base64.b64encode(key).decode('utf-8'),  # Convert bytes to Base64 string
            "IV": base64.b64encode(iv).decode('utf-8')
        }
        with open("Key_IV.json","w") as file:
            json.dump(data,file,indent=4)
    return key,iv
    
def encrypt_file(file_path:str, password:str):
    buffer_size = 64 * 1024  # 64KB buffer size
    encrypted_file_path = file_path + ".aes"

    with open(file_path, "rb") as f_in:
        with open(encrypted_file_path, "wb") as f_out:
            encryptStream(f_in, f_out, password, buffer_size)

    # Optionally, remove the original file
    os.remove(file_path)
    
def decrypt_file(encrypted_file_path:str, password:str):
    buffer_size = 64 * 1024  # 64KB buffer size
    decrypted_file_path = encrypted_file_path[:-4]  # Remove '.aes' extension

    with open(encrypted_file_path, "rb") as f_in:
        with open(decrypted_file_path, "wb") as f_out:
            try:
                decryptStream(f_in, f_out, password, buffer_size, os.path.getsize(encrypted_file_path))
            except ValueError:
                # Remove partially decrypted file if decryption failed
                os.remove(decrypted_file_path)
                print("Incorrect password!")

def load_configuraton() -> tuple[bool,bool]:
    with open("Config.json",'r') as file:
        data:dict[str,bool] = json.load(file)
    return data["Encrypt"],data["Decrypt"]

def main():
    # File paths
    input_file:str = "File1.txt"  # Original file
    encrypted_file:str = "File1.aes"  # Encrypted file
    decrypted_file:str = input_file  # Decrypted file
    encrypt_files,decrypt_files = load_configuraton()

    # Generate AES key and IV
    key,iv = get_key_iv()

    if(encrypt_files):
        # Encrypt the file
        encrypt_file(input_file, encrypted_file, key, iv)

    if(decrypt_files):
        # Decrypt the file
        decrypt_file(encrypted_file, decrypted_file, key, iv)
    
if __name__ == "__main__":
    main()
    variable_table:DataFrame = get_variable_info()
    variable_table.to_json("AES_Encryption_End_Variables.json",index=False,indent=4,orient='table',mode='w')