import os
import string
import hashlib
import sys
import json
import traceback
import secrets
import shutil
from tkinter import Tk, Entry, Label, Button, messagebox, simpledialog, Menu, Toplevel
from tkinter.messagebox import askyesno, showinfo, showerror, askokcancel
from pandas import DataFrame
from pyAesCrypt import encryptStream, decryptStream
from logging import basicConfig, getLogger, Logger, RootLogger, INFO

# Constants
CONFIG_DIR = os.path.join(os.getenv('LOCALAPPDATA'), 'SecureFileEncryptor')
MASTER_PASSWORD_FLAG_FILE = os.path.join(CONFIG_DIR, 'master_flag.txt')
PASSWORD_DB_FILE = os.path.join(CONFIG_DIR, 'encrypted_passwords.aes')
TEMP_PASSWORD_FILE = os.path.join(CONFIG_DIR, 'temp_passwords.json')
BUFFER_SIZE = 64 * 1024  # 64KB buffer for encryption

class PasswordManager:
    @staticmethod
    def generate_strong_password(length=32):
        """Generate cryptographically secure random password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def verify_password_strength(password:str):
        """Check if password meets minimum requirements"""
        if len(password) < 12:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in string.punctuation for c in password):
            return False
        return True

class FileEncryptor:
    def __init__(self, logger):
        self.logger = logger
        self.ensure_config_dir()

    def ensure_config_dir(self):
        """Create configuration directory if it doesn't exist"""
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
        except PermissionError:
            self.logger.error("Failed to create config directory")
            raise

    def encrypt_file(self, file_path, password):
        """Encrypt a file with AES-256"""
        encrypted_path = f"{file_path}.aes"
        try:
            with open(file_path, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
                encryptStream(f_in, f_out, password, BUFFER_SIZE)
            os.remove(file_path)
            return True
        except Exception as e:
            self.logger.error(f"Encryption failed for {file_path}: {str(e)}")
            return False

    def decrypt_file(self, encrypted_path, password):
        """Decrypt a file with AES-256"""
        original_path = encrypted_path[:-4]  # Remove .aes extension
        try:
            with open(encrypted_path, 'rb') as f_in, open(original_path, 'wb') as f_out:
                decryptStream(f_in, f_out, password, BUFFER_SIZE)
            os.remove(encrypted_path)
            return True
        except Exception as e:
            self.logger.error(f"Decryption failed for {encrypted_path}: {str(e)}")
            return False

    def encrypt_directory(self, directory, master_password):
        """Encrypt all files in directory"""
        file_passwords = {}
        exclude_dirs = {'Windows', 'Program Files', 'Program Files (x86)'}

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if not file.endswith('.aes'):  # Skip already encrypted files
                    file_path = os.path.join(root, file)
                    file_password = PasswordManager.generate_strong_password()
                    if self.encrypt_file(file_path, file_password):
                        file_passwords[file_path] = file_password

        if file_passwords:
            self._save_password_db(file_passwords, master_password)
            return True
        return False

    def decrypt_directory(self, directory, master_password):
        """Decrypt all files in directory"""
        file_passwords = self._load_password_db(master_password)
        if not file_passwords:
            return False

        success = True
        for file_path, password in file_passwords.items():
            encrypted_path = f"{file_path}.aes"
            if os.path.exists(encrypted_path):
                if not self.decrypt_file(encrypted_path, password):
                    success = False

        if success:
            os.remove(PASSWORD_DB_FILE)
        return success

    def change_master_password(self, old_password, new_password):
        """Change the master password and re-encrypt password database"""
        file_passwords = self._load_password_db(old_password)
        if file_passwords:
            return self._save_password_db(file_passwords, new_password)
        return False

    def _save_password_db(self, passwords, master_password):
        """Save passwords to encrypted database"""
        try:
            # Save to temporary file first
            with open(TEMP_PASSWORD_FILE, 'w') as f:
                json.dump(passwords, f)
            
            # Encrypt the temporary file
            with open(TEMP_PASSWORD_FILE, 'rb') as f_in, open(PASSWORD_DB_FILE, 'wb') as f_out:
                encryptStream(f_in, f_out, master_password, BUFFER_SIZE)
            
            os.remove(TEMP_PASSWORD_FILE)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save password DB: {str(e)}")
            return False

    def _load_password_db(self, master_password):
        """Load passwords from encrypted database"""
        if not os.path.exists(PASSWORD_DB_FILE):
            return None

        try:
            # Decrypt to temporary file
            with open(PASSWORD_DB_FILE, 'rb') as f_in, open(TEMP_PASSWORD_FILE, 'wb') as f_out:
                decryptStream(f_in, f_out, master_password, BUFFER_SIZE)
            
            # Load the decrypted data
            with open(TEMP_PASSWORD_FILE, 'r') as f:
                passwords = json.load(f)
            
            os.remove(TEMP_PASSWORD_FILE)
            return passwords
        except Exception as e:
            self.logger.error(f"Failed to load password DB: {str(e)}")
            return None

class PasswordDialog(Toplevel):
    def __init__(self, parent, title, prompt, verify=False, verify_prompt=None):
        Toplevel.__init__(self, parent)
        self.title(title)
        self.parent = parent
        self.result = None
        
        Label(self, text=prompt).pack(pady=5)
        self.entry = Entry(self, show='*', width=40)
        self.entry.pack(pady=5)
        
        if verify:
            Label(self, text=verify_prompt or "Confirm password:").pack(pady=5)
            self.verify_entry = Entry(self, show='*', width=40)
            self.verify_entry.pack(pady=5)
        else:
            self.verify_entry = None
        
        Button(self, text="OK", command=self.on_ok).pack(pady=10)
        Button(self, text="Cancel", command=self.on_cancel).pack(pady=5)
        
        self.grab_set()
        self.transient(parent)
        self.wait_window(self)
    
    def on_ok(self):
        password = self.entry.get()
        if self.verify_entry:
            verify = self.verify_entry.get()
            if password != verify:
                showerror("Error", "Passwords do not match!")
                return
        
        if not PasswordManager.verify_password_strength(password):
            showerror("Error", "Password must be at least 12 characters with uppercase, lowercase, numbers, and symbols")
            return
        
        self.result = password
        self.destroy()
    
    def on_cancel(self):
        self.result = None
        self.destroy()

class MainApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Encryption Tool")
        
        # Configure logging
        basicConfig(
            filename=os.path.join(CONFIG_DIR, 'encryption.log'),
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=INFO
        )
        self.logger = getLogger()
        
        # Initialize encryptor
        self.encryptor = FileEncryptor(self.logger)
        
        # Create menu
        menubar = Menu(root)
        password_menu = Menu(menubar, tearoff=0)
        password_menu.add_command(label="Change Master Password", command=self.change_password)
        menubar.add_cascade(label="Password", menu=password_menu)
        root.config(menu=menubar)
        
        # Main UI
        Label(root, text="Directory Path:").pack(pady=5)
        self.dir_entry = Entry(root, width=50)
        self.dir_entry.pack(pady=5)
        
        Button(root, text="Encrypt Directory", command=self.encrypt).pack(pady=5)
        Button(root, text="Decrypt Directory", command=self.decrypt).pack(pady=5)
        
        # Initialize master password flag
        self.master_password_set = os.path.exists(MASTER_PASSWORD_FLAG_FILE)
    
    def get_master_password(self, action="access"):
        """Prompt for master password with appropriate dialog"""
        if self.master_password_set:
            # Get existing password
            dialog = PasswordDialog(
                self.root,
                "Enter Master Password",
                f"Enter master password to {action}:"
            )
            return dialog.result
        else:
            # Create new password
            dialog = PasswordDialog(
                self.root,
                "Create Master Password",
                "Create a new master password:",
                verify=True
            )
            if dialog.result:
                with open(MASTER_PASSWORD_FLAG_FILE, 'w') as f:
                    f.write("1")
                self.master_password_set = True
            return dialog.result
    
    def encrypt(self):
        """Handle directory encryption"""
        directory = self.dir_entry.get().strip()
        if not directory or not os.path.isdir(directory):
            showerror("Error", "Invalid directory path")
            return
        
        master_password = self.get_master_password("encrypt files")
        if not master_password:
            return
        
        if askokcancel("Confirm", "Encrypt all files in this directory?"):
            if self.encryptor.encrypt_directory(directory, master_password):
                showinfo("Success", "Files encrypted successfully")
            else:
                showerror("Error", "Failed to encrypt some files")
    
    def decrypt(self):
        """Handle directory decryption"""
        directory = self.dir_entry.get().strip()
        if not directory or not os.path.isdir(directory):
            showerror("Error", "Invalid directory path")
            return
        
        master_password = self.get_master_password("decrypt files")
        if not master_password:
            return
        
        if askokcancel("Confirm", "Decrypt all files in this directory?"):
            if self.encryptor.decrypt_directory(directory, master_password):
                showinfo("Success", "Files decrypted successfully")
            else:
                showerror("Error", "Failed to decrypt some files")
    
    def change_password(self):
        """Handle master password change"""
        if not self.master_password_set:
            showerror("Error", "No master password set yet")
            return
        
        # Get current password
        current_password = self.get_master_password("change password")
        if not current_password:
            return
        
        # Get new password
        dialog = PasswordDialog(
            self.root,
            "Change Master Password",
            "Enter new master password:",
            verify=True
        )
        new_password = dialog.result
        if not new_password:
            return
        
        if self.encryptor.change_master_password(current_password, new_password):
            showinfo("Success", "Master password changed successfully")
        else:
            showerror("Error", "Failed to change master password")

if __name__ == "__main__":
    root = Tk()
    app = MainApplication(root)
    root.mainloop()