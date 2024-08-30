import os
import webbrowser
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from tkinter import Tk, filedialog, Button, Label, messagebox, simpledialog, Frame, LEFT, Toplevel, Text, Scrollbar, RIGHT, Y, Entry
import pyperclip
import base64
from pathlib import Path

class EncryptionTool:
    def __init__(self, master):
        self.master = master
        master.title("Cypher-Night: MAX-SEC Encryption Tool")

        # Set fixed window size and disable resizing
        master.geometry("800x200")  # Width x Height
        master.resizable(False, False)  # Disable resizing

        # Create the warning label with bold text for specific parts
        self.warning_label = Label(master, text="WARNING: MILITARY GRADE ENCRYPTION SOFTWARE\n"
                                                "Every attempt to bruteforce or any kind will fail, "
                                                "if key is lost archive can't be opened/forced\n"
                                                "TECHNOLOGY USED AES256 + 4096RSA",
                                   fg="red", bg="yellow", font=("Arial", 12, "bold"))
        self.warning_label.pack(pady=10)

        # Frame to hold the buttons centered
        button_frame = Frame(master)
        button_frame.pack(pady=10)

        # Buttons for encryption and decryption with double size
        self.encrypt_button = Button(button_frame, text="Encrypt", command=self.encrypt_file, width=20, height=4)
        self.encrypt_button.pack(side=LEFT, padx=20)

        self.decrypt_button = Button(button_frame, text="Decrypt", command=self.decrypt_file, width=20, height=4)
        self.decrypt_button.pack(side=LEFT, padx=20)

        # Generate the encryption key and salt securely
        self.encryption_key = os.urandom(32)  # 256-bit key, securely generated
        self.salt = os.urandom(16)  # 128-bit salt, securely generated

        # Track the number of decryptions (1 free decryption allowed)
        self.decryption_count = self.load_decryption_count()

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.encryption_key)

    def encrypt_count(self, count):
        key = self.derive_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_count = encryptor.update(count.to_bytes(4, 'big')) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + encrypted_count).decode('utf-8')

    def decrypt_count(self, encrypted_count):
        encrypted_count = base64.urlsafe_b64decode(encrypted_count.encode('utf-8'))
        iv = encrypted_count[:16]
        encrypted_count = encrypted_count[16:]
        key = self.derive_key()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_count = decryptor.update(encrypted_count) + decryptor.finalize()
        return int.from_bytes(decrypted_count, 'big')

    def hmac_digest(self, data):
        return hmac.new(self.derive_key(), data, hashlib.sha256).hexdigest()

    def load_decryption_count(self):
        try:
            with open("decryption_count.enc", "r") as f:
                encrypted_count = f.read().strip()
                encrypted_count, stored_hmac = encrypted_count.rsplit(":", 1)

                # Verify integrity with HMAC
                if self.hmac_digest(encrypted_count.encode('utf-8')) != stored_hmac:
                    raise ValueError("Integrity check failed.")

                return self.decrypt_count(encrypted_count)
        except (FileNotFoundError, ValueError):
            return 0  # If the file doesn't exist or is tampered with, assume 0 decryptions

    def save_decryption_count(self):
        encrypted_count = self.encrypt_count(self.decryption_count)
        hmac_value = self.hmac_digest(encrypted_count.encode('utf-8'))
        with open("decryption_count.enc", "w") as f:
            f.write(f"{encrypted_count}:{hmac_value}")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select a File to Encrypt")
        if not file_path:
            return

        # Generate RSA Key Pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize the private key to be copied to the clipboard
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_str = private_key_bytes.decode('utf-8')
        
        # Generate AES key
        aes_key = os.urandom(32)  # 256-bit key

        # Encrypt the AES key with the RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Read the file and encrypt it with the AES key
        with open(file_path, 'rb') as f:
            file_data = f.read()

        iv = os.urandom(16)  # Initialization vector for AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Save the encrypted file with .mrk extension
        encrypted_file_path = file_path + '.mrk0'
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + encrypted_aes_key + encrypted_data)

        # Show the RSA private key in a new window
        self.show_private_key_window(private_key_str, encrypted_file_path)

    def show_private_key_window(self, private_key_str, encrypted_file_path):
        # Create a new Toplevel window
        key_window = Toplevel(self.master)
        key_window.title("RSA Private Key")
        key_window.geometry("800x600")  # Width x Height
        key_window.resizable(False, False)  # Disable resizing

        # Create a Text widget to display the RSA private key
        text_area = Text(key_window, wrap='word', bg='white', fg='black', font=("Arial", 8))
        text_area.insert('1.0', private_key_str)
        text_area.config(state='disabled')  # Make the Text widget read-only

        # Create a Scrollbar for the Text widget
        scrollbar = Scrollbar(key_window, command=text_area.yview)
        text_area.config(yscrollcommand=scrollbar.set)

        # Add the Text widget and Scrollbar to the Toplevel window
        text_area.pack(side=LEFT, fill='both', expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Create a Button to copy the key to the clipboard
        copy_button = Button(key_window, text="Copy to Clipboard", command=lambda: pyperclip.copy(private_key_str))
        copy_button.pack(pady=10)

        # Show a message about the encryption result
        messagebox.showinfo("Encryption Complete", f"File encrypted successfully!\n"
                                                   f"File saved as {encrypted_file_path}")

    def decrypt_file(self):
        if self.decryption_count >= 1:
            # Show payment window
            self.show_payment_window()
            return

        file_path = filedialog.askopenfilename(title="Select a File to Decrypt", filetypes=[("Encrypted Files", "*.mrk0")])
        if not file_path:
            return

        # Ask the user to input the RSA private key
        private_key_pem = simpledialog.askstring("Input RSA Private Key", "Please paste your RSA private key:")
        if not private_key_pem:
            return

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Extract the IV, encrypted AES key, and the encrypted data
        iv = file_data[:16]
        encrypted_aes_key = file_data[16:16 + private_key.key_size // 8]
        encrypted_data = file_data[16 + private_key.key_size // 8:]

        # Decrypt the AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the file data with the AES key
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Save the decrypted file (remove .mrk extension)
        decrypted_file_path = file_path.replace('.mrk', '_decrypted')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        # Increment and save the decryption count
        self.decryption_count += 1
        self.save_decryption_count()

        messagebox.showinfo("Decryption Complete", f"File decrypted successfully!\nFile saved as {decrypted_file_path}")

    def show_payment_window(self):
        # Create a new Toplevel window
        payment_window = Toplevel(self.master)
        payment_window.title("Payment Required")
        payment_window.geometry("400x300")
        payment_window.resizable(False, False)  # Disable resizing

        # Add payment message
        payment_label = Label(payment_window, text="You have used your free decryption.\nPlease pay to continue using the tool.",
                              fg="black", font=("Arial", 12, "bold"))
        payment_label.pack(pady=20)

        # Payment button
        pay_button = Button(payment_window, text="Pay Now", command=self.redirect_to_payment_gateway)
        pay_button.pack(pady=10)

        # Unlock code entry
        self.unlock_code_entry = Entry(payment_window, show="*")
        self.unlock_code_entry.pack(pady=10)

        unlock_button = Button(payment_window, text="Unlock with Code", command=self.unlock_with_code)
        unlock_button.pack(pady=10)

    def redirect_to_payment_gateway(self):
        # Open the payment link in the default web browser
        webbrowser.open("https://www.aurawave.eu//_paylink/AZGa7gJd")

    def unlock_with_code(self):
        # Simulate contacting a server to validate the unlock code
        entered_code = self.unlock_code_entry.get()
        if self.validate_unlock_code(entered_code):
            self.decryption_count = 0  # Reset decryption count
            self.save_decryption_count()
            messagebox.showinfo("Unlocked", "Tool unlocked successfully!")
            self.unlock_code_entry.master.destroy()  # Close the payment window
        else:
            messagebox.showerror("Error", "Incorrect unlock code.")

    def validate_unlock_code(self, entered_code):
        # Normally, this would involve server-side validation. Here we simulate it.
        correct_unlock_code = "CYPH3RN1GHT"  # In real application, this should be handled server-side.
        return entered_code == correct_unlock_code

if __name__ == "__main__":
    root = Tk()
    tool = EncryptionTool(root)
    root.mainloop()

