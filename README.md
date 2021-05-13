



# Safe Vault

Safe Vault is a password manager for the command line interface written in Python 3. It supports Linux and MacOs operating systems. 

* Data is stored in SQLite3 Database
* Master username & password are hashed in SHA2-512
* All logins & passwords are encrypted with AES-128-CBC

## Screenshot

![screenshot](homepage.png)		

## Installation & Usage

```bash
git clone https://github.com/YNRA/Safe-Vault.git
cd safe_vault
python3 -m pip install -r requirements.txt
python3 safe_vault_cli.py

# Recommended :
chmod -R 700 safe_vault
```



## Troubleshooting

Depends on the operating system, something an error can occur when trying to copy/paste :

```
Pyperclip could not find a copy/paste mechanism for your system. 
Please see https://pyperclip.readthedocs.io/en/latest/introduction.html#not-implemented-error for how to fix this.
```

In that case, you may have to install `xclip` package :

```bash
sudo apt-get install xclip
```


## Credit & License

Safe Vault is licensed under the terms of the MIT license. You can find the complete text in `LICENSE`.

Developed  by Arnaud Boyé ([@YNRA](https://github.com/YNRA)) and Thomas Dejeanne ([@Gomonriou](https://github.com/Gomonriou)).
