from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from pandas import DataFrame
import sys,hashlib,json,base64,os

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
    Generate a random 32-byte AES key and 16-byte IV.
    """
    key:bytes = get_random_bytes(32)  # 32 bytes = 256-bit AES key
    iv:bytes = get_random_bytes(16)   # 16 bytes = block size for AES
    return key, iv

def get_key_iv() -> tuple[bytes,bytes]:
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
    
def encrypt_file(input_file:str, output_file:str, key:bytes, iv:bytes) -> None:
    """
    Encrypt the contents of a file using AES encryption.

    Args:
        input_file (str): Path to the input file.
        output_file (str): Path to save the encrypted file.
        key (bytes): AES key.
        iv (bytes): Initialization vector.
    """
    try:
        # Read the input file
        with open(input_file, 'rb') as f:
            data:bytes = f.read()

        # Pad the data to be a multiple of the AES block size
        padded_data:bytes = pad(data, AES.block_size)

        # Create a Cipher object for AES encryption
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Encrypt the data
        encrypted_data:bytes = cipher.encrypt(padded_data)

        # Write the encrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        print(f"File '{input_file}' encrypted to '{output_file}'.")
        os.remove(input_file)
    except:
        pass

def decrypt_file(input_file:str, output_file:str, key:bytes, iv:bytes):
    """
    Decrypt an AES-encrypted file.

    Args:
        input_file (str): Path to the encrypted file.
        output_file (str): Path to save the decrypted file.
        key (bytes): AES key.
        iv (bytes): Initialization vector.
    """
    try:
        # Read the encrypted file
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        # Create a Cipher object for AES decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the data
        padded_data:bytes = cipher.decrypt(encrypted_data)

        # Remove padding
        data:bytes = unpad(padded_data, AES.block_size)

        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"File '{input_file}' decrypted to '{output_file}'.")
        os.remove(input_file)
    except:
        pass

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