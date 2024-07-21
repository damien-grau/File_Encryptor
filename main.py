import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor")
        self.root.geometry("500x300")
        self.root.resizable(False, False)


        # Mode selection
        self.mode = tk.StringVar(value="encrypt")
        self.create_mode_selection()

        # Encrypt mode widgets
        self.password_label = tk.Label(root, text="Password")
        self.password_entry = tk.Entry(root, show="*")
        self.repeat_label = tk.Label(root, text="Repeat")
        self.repeat_entry = tk.Entry(root, show="*")
        self.key_gen_button = tk.Button(root, text="Generate Key", command=self.generate_key)
        self.browse_key_enc_button = tk.Button(root, text="Browse key file", command=self.browse_key_enc_file)
        self.file_label = tk.Label(root, text="File name")
        self.file_entry = tk.Entry(root, width=50)
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.delete_plain_var = tk.IntVar()
        self.delete_plain_checkbox = tk.Checkbutton(root, text="Delete plain file after encrypt", variable=self.delete_plain_var)
        self.action_button = tk.Button(root, text="ENCRYPT", command=self.encrypt_file)

        # Decrypt mode widgets
        self.password_dec_label = tk.Label(root, text="Password")
        self.password_dec_entry = tk.Entry(root, show="*")
        self.browse_key_button = tk.Button(root, text="Browse key file", command=self.browse_key_file)
        self.browse_enc_file_button = tk.Button(root, text="Browse encrypted file", command=self.browse_enc_file)
        self.delete_enc_var = tk.IntVar()
        self.delete_enc_checkbox = tk.Checkbutton(root, text="Delete encrypted file", variable=self.delete_enc_var)
        self.dec_button = tk.Button(root, text="DECRYPT", command=self.decrypt_file)

        self.key_file = None
        self.enc_file = None
        self.key_enc_file = None

        self.pack_encrypt_widgets()

    def create_mode_selection(self):
        tk.Label(self.root, text="Mode").grid(row=0, column=0)
        tk.Radiobutton(self.root, text="Encrypt", variable=self.mode, value="encrypt", command=self.switch_mode).grid(row=0, column=1)
        tk.Radiobutton(self.root, text="Decrypt", variable=self.mode, value="decrypt", command=self.switch_mode).grid(row=0, column=2)
        tk.Label(self.root, text="File Encryptor", font=("Helvetica", 16)).grid(row=1, columnspan=3)
        tk.Label(self.root, text="").grid(row=2, columnspan=3)

    def switch_mode(self):
        for widget in self.root.winfo_children():
            widget.grid_forget()
        self.create_mode_selection()
        if self.mode.get() == "encrypt":
            self.pack_encrypt_widgets()
        else:
            self.pack_decrypt_widgets()

    def pack_encrypt_widgets(self):
        self.password_label.grid(row=3, column=0)
        self.password_entry.grid(row=3, column=1)
        self.repeat_label.grid(row=4, column=0)
        self.repeat_entry.grid(row=4, column=1)
        self.key_gen_button.grid(row=5, columnspan=3)
        self.browse_key_enc_button.grid(row=6, columnspan=3)
        self.file_label.grid(row=7, column=0)
        self.file_entry.grid(row=7, column=1)
        self.browse_button.grid(row=7, column=2)
        self.delete_plain_checkbox.grid(row=8, columnspan=3)
        self.action_button.grid(row=9, columnspan=3)

    def pack_decrypt_widgets(self):
        self.password_dec_label.grid(row=3, column=0, pady=10, padx=10)
        self.password_dec_entry.grid(row=3, column=1, pady=10, padx=10)
        self.browse_key_button.grid(row=4, columnspan=3, pady=10)
        self.browse_enc_file_button.grid(row=5, columnspan=3, pady=10)
        self.delete_enc_checkbox.grid(row=6, columnspan=3, pady=10)
        self.dec_button.grid(row=7, columnspan=3, pady=20)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def browse_key_file(self):
        self.key_file = filedialog.askopenfilename()

    def browse_key_enc_file(self):
        self.key_enc_file = filedialog.askopenfilename()

    def browse_enc_file(self):
        self.enc_file = filedialog.askopenfilename()

    def generate_key(self):
        key_aes = get_random_bytes(32)  # AES-256 key
        key_hmac = get_random_bytes(64)  # HMAC-512 key
        key_file = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if key_file:
            with open(key_file, 'wb') as kf:
                kf.write(key_aes + key_hmac)
            messagebox.showinfo("Key Generated", "Key file has been generated and saved.")

    def encrypt_file(self):
        password = self.password_entry.get()
        repeat_password = self.repeat_entry.get()

        if self.key_enc_file:
            with open(self.key_enc_file, 'rb') as kf:
                key_aes = kf.read(32)  # Read AES-256 key
        else:
            if password != repeat_password:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            if len(password) == 0:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            key_aes = SHA256.new(password.encode()).digest()

        filename = self.file_entry.get()
        if not filename:
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return

        with open(filename, 'rb') as f:
            plaintext = f.read()

        cipher = AES.new(key_aes, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_filename = filename + ".enc"
        with open(encrypted_filename, 'wb') as ef:
            [ef.write(x) for x in (cipher.nonce, tag, ciphertext)]

        if self.delete_plain_var.get():
            os.remove(filename)

        messagebox.showinfo("Success", "File encrypted successfully.")

    def decrypt_file(self):
        password = self.password_dec_entry.get()
        if len(password) == 0 and not self.key_file:
            messagebox.showerror("Error", "Please provide a password or a key file.")
            return

        if not self.enc_file:
            messagebox.showerror("Error", "Please select an encrypted file after decrypt.")
            return

        if self.key_file:
            with open(self.key_file, 'rb') as kf:
                key_aes = kf.read(32)  # Read AES-256 key
                key_hmac = kf.read(64)  # Read HMAC-512 key
        else:
            key_aes = SHA256.new(password.encode()).digest()
            key_hmac = None  # You may handle HMAC if needed

        with open(self.enc_file, 'rb') as ef:
            nonce, tag, ciphertext = [ef.read(x) for x in (16, 16, -1)]

        cipher = AES.new(key_aes, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            messagebox.showerror("Error", "Incorrect password or corrupted file.")
            return

        decrypted_filename = self.enc_file[:-4]  # Remove .enc
        with open(decrypted_filename, 'wb') as df:
            df.write(plaintext)

        if self.delete_enc_var.get():
            os.remove(self.enc_file)

        messagebox.showinfo("Success", "File decrypted successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
