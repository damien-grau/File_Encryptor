import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tkinter import filedialog
import getpass


def encrypt_file(password, in_filename, out_filename=None, chunksize=64 * 1024):
    if not out_filename:
        out_filename = in_filename + '.enc'

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(salt)
            outfile.write(iv)
            outfile.write(filesize.to_bytes(8, 'big'))

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.update(chunk))

            outfile.write(encryptor.finalize())
    os.remove(in_filename)
    return out_filename


def decrypt_file(password, in_filename, out_filename=None, chunksize=64 * 1024):
    if not out_filename:
        out_filename = ".".join(in_filename.split(".")[0:-1])
    with open(in_filename, 'rb') as infile:
        salt = infile.read(16)
        iv = infile.read(16)
        filesize = int.from_bytes(infile.read(8), 'big')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.update(chunk))

            outfile.write(decryptor.finalize())
    os.remove(in_filename)
    return out_filename


def browse_files():
    filename = filedialog.askopenfilename(initialdir="/", title="Sélectionnez un fichier",
                                          filetypes=[("Tous les fichiers", "*.*"), ("Fichiers textes", "*.txt*"), ("Fichiers encodés", "*.enc*")])

    return filename


print("Chiffrage AES de fichiers texte\n")
filename = browse_files()
file_ext = filename.split('/')[-1].split(".")[-1]
if file_ext != "enc":
    print("ATTENTION! Si vous oubliez votre mot de passe, aucun moyen de retour en arrière ne sera possible.")
    while True:
        pwd = getpass.getpass("Définissez un mot de passe pour sécuriser votre fichier: ")
        pwd1 = getpass.getpass("Répétez le mot de passe : ")
        if pwd == pwd1:
            break
        else:
            print("Les mots de passe ne correspondent pas.\n")
    out_filename = encrypt_file(pwd.encode(), filename)
    print(f"Fichier chiffré avec succès: {out_filename}\n")
else:
    pwd = getpass.getpass("Entrez le mot de passe de votre fichier: ")
    out_filename = decrypt_file(pwd.encode(), filename)
    print(f"Fichier déchiffré avec succès: {out_filename}\n")