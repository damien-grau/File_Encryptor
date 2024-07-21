# AES-256 Encryption Software in Python
Encryption Software that encrypt any type of file on your computer with a password or a keyfile.<br>
Works on any OS.
# Get started
<h4>Encrypt file</h4>
You have to select a file to encrypt. <br>
For the encryption, you have two choices:<br>
<ul>
  <li>Create a password</li>
  <li>Select a key file containing a 256 bits key to be compatible with AES-256. This key can be auto-generated using the button "Generate Key"</li>
</ul>
After, you can choose to delete the plain file before encrypting it.
<h4>Decrypt file</h4>
Same choices as Encrypt Mode.<br>
Enter the password or browse to the keyfile you used to encrypt the file,<br>
select the encrypted file and decrypt it.<br>

# App Preview
## Encrypt mode
![image](https://github.com/user-attachments/assets/489d885c-4176-4bdf-b9cb-b1a9301f47ec)

## Decrypt mode
![image](https://github.com/user-attachments/assets/abd3c92f-9b9c-4b28-9d90-c5696bce81a7)

# Compilation to binary

You can compile this script if you want, using `pyinstaller`.<br>
Download the repository and open a terminal in it.<br><br>

Create a virtual environment with the following command and activate it:<br>
```shell
python3 -m venv .env
```
On windows (Powershell):
```ps1
.\.env\Scripts\Activate.ps1
```
On linux (bash):
```sh
source .env/bin/activate
```

Install depending libraries:<br>
```shell
pip install -r requirements.txt
pip install pyinstaller
```

Compile the python script in one executable file using pyinstaller:
```sh
pyinstaller.exe -F main.py --noconsole --icon=app.ico
```
You can exit of the virtual environment with `deactivate`.<br>
You should see the binary compiled in the `dist` folder.
