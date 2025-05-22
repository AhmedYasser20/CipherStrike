
# Ransomware Simulation

<p align="center"> <img src="https://github.com/user-attachments/assets/a10c5c2f-1147-4cf3-9a3e-da1aa82d0c37" alt="CipherStrike Logo" width="400" height="400"> </p>

## Overview
This project is a **ransomware simulation** developed as part of a **security course** to demonstrate the behavior and impact of ransomware. It is intended for **educational purposes only** and provides insights into how ransomware encrypts files, creates ransom notes, and implements decryption mechanisms.

## Features
- **File Encryption**: Encrypts files in a specified directory using AES encryption.
- **Ransom Note Creation**: Generates a ransom note with instructions for decryption.
- **Decryption Mechanism**: Allows decryption of files using a predefined password.
- **GUI Interface**: Provides a simple graphical interface for encryption and decryption.
- **Auto-Execution**: Automatically encrypts files if no encryption has been performed.

## Purpose
This project is designed to help students and researchers understand:
- The technical implementation of ransomware
- The impact of file encryption on a system
- The importance of cybersecurity measures to prevent ransomware attacks

**This project is for educational purposes only and should not be used for malicious activities.**

## Usage
### Encryption
1. Run the script or executable.
2. The program will automatically encrypt files in the specified directory.
3. A ransom note will be created in the directory with instructions for decryption.

### Decryption
1. Launch the program.
2. Enter the decryption password when prompted.
3. The program will decrypt the files and restore them to their original state.

## Key Components
- **Encryption**:
  - Uses AES encryption with a randomly generated key and IV.
  - Encrypts files in-place and appends a `.encrypted` extension.
- **Ransom Note**:
  - A text file is created with instructions for paying the ransom and decrypting files.
- **Decryption**:
  - Requires the correct password to decrypt files and restore them to their original state.
- **GUI**:
  - A simple interface for interacting with the ransomware simulation.

## Disclaimer
This project is a **simulation** created for a **security course**. It is intended to educate users about ransomware behavior and the importance of cybersecurity. **Do not use this project for malicious purposes.**


# CipherStrike Ransomware Scanner

<p align="center"> <img src="https://github.com/user-attachments/assets/67653590-c612-466c-bfd5-8ca4e8866d90" alt="CipherStrike Logo" width="400" height="400"> </p>

## Overview
This project is developed as part of a **security course** to demonstrate the detection of ransomware and malicious software using YARA rules and entropy analysis. It is intended for **educational purposes only** and showcases techniques for identifying suspicious behaviors in executable files.

## Features
- **YARA Rules**: Over 50 custom rules to detect ransomware behaviors such as:
  - PowerShell abuse
  - Data exfiltration tools
  - Shadow copy deletion
  - Anti-debugging techniques
  - File encryption patterns
- **Entropy Analysis**: Detects files with high entropy, which may indicate encryption or packing.
- **GUI Interface**: A user-friendly interface for scanning folders and displaying results.
 ![image](https://github.com/user-attachments/assets/bf77e141-64af-4c12-85f2-b9712b674344)

- **Risk Scoring**: Assigns a risk score to each file based on matched rules.

## Purpose
This project is **not intended for production use**. It is a demonstration of how YARA rules and basic file analysis can be used to detect ransomware-like behaviors. The focus is on learning and understanding security concepts.

## Usage
1. **Run the Scanner**:
   - Launch the GUI by running `ui.py`.
   - Select a folder to scan.
   - Click "Start Scan" to analyze files in the selected folder.

2. **View Results**:
   - The GUI displays suspicious files, their risk scores, and matched YARA rules.
   - Detailed results include matched patterns and entropy analysis.

3. **Educational Focus**:
   - Explore the YARA rules in rules3.yar to understand how specific ransomware behaviors are detected.
   - Modify or create new rules to expand detection capabilities.

## Disclaimer
This project is for **educational purposes only**. It is not intended for real-world use or deployment in production environments. Always ensure you have proper authorization before scanning systems.
