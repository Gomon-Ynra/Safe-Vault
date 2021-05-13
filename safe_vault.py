# Authors : Arnaud Boyé (@YNRA), Thomas Dejeanne (@Gomonriou)
# 2020-2021

# *********************************************************************  LIBRAIRIES   **********************************************************************************
# System
import os, sys, datetime, time, random, base64, pyperclip
from string import ascii_letters, digits
# Crypto
import sqlite3
from getpass import getpass
from hashlib import sha512
from Crypto.Cipher import AES 
from Crypto import Random
from backports.pbkdf2 import pbkdf2_hmac as pbkdf2
import webbrowser
# Appearance
from termcolor import colored

# *********************************************************************  GLOBAL VARIABLES ******************************************************************************* 
connection = sqlite3.connect('vault.db')
cursor = connection.cursor()

default = 'white'
warning = 'red'
success = 'green'

ERASE_LINE = '\x1b[2K' 
CURSOR_UP_ONE = '\x1b[1A'
BLOCK_SIZE = 16
PUNCTUATION = "#$%&*+-/=?@_"
ALPHABET = ascii_letters+digits+PUNCTUATION

# *********************************************************************  FUNCTIONS **************************************************************************************

# Basic functions
def banner():
    time.sleep(0.5)
    clear()
    print(colored('''

    ███████╗ █████╗ ███████╗███████╗    ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
    ██╔════╝██╔══██╗██╔════╝██╔════╝    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
    ███████╗███████║█████╗  █████╗      ██║   ██║███████║██║   ██║██║     ██║   
    ╚════██║██╔══██║██╔══╝  ██╔══╝      ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
    ███████║██║  ██║██║     ███████╗     ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
    ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝      ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
                 Powered by YNRA, Gomonriou - 2021\n 
''', warning))

def clear():
    os.system("clear")

def cleanLine():
    sys.stdout.write(CURSOR_UP_ONE)  
    sys.stdout.write(ERASE_LINE)
    sys.stdout.write(ERASE_LINE)

def quit():
    print(colored("\n[!] Exiting ... ", default))
    connection.close()
    sys.exit()


# Initializes database connection. Creates one if none exists, raises error if connection fail
try:
    connection
    banner()
except sqlite3.Error as error:
    print("Error : connection failed", error)

# Initalizes the vault. Set master user and password, stores them into a table. 
def initialize():
    print(colored('''
----------------------------------------------------------------------
                    Welcome to Safe Vault ! 
        Please set a master username and password. Keep it safe !
      DO NOT use a really simple password, master should be STRONG.
 If lost, you will have to delete the database and create a fresh one.
 --------------------------------------------------------------------- 
 ''', warning))
    
    time.sleep(0.5)
    # Get master username and password from user
    # Conditions : check length of username and password, reset function if one is shorter than required
    input_username = input(colored('[+] Master username : ', default)).encode('utf-8')
    while len(input_username) <= 4:
        cleanLine()
        print(colored("For obvious safety reasons, master username must contains at least 5 characters ! Please try again.", warning))
        time.sleep(0.5)
        input_username = input(colored('[+] Master username : ', default)).encode('utf-8')
        cleanLine()

    input_psswd = getpass(colored('[+] Master password : ', default)).encode('utf-8')
    salt = os.urandom(32)
    
    while len(input_psswd) <= 7:
        cleanLine()
        print(colored("For obvious safety reasons, master password must contains at least 8 characters ! Please try again.", warning))
        time.sleep(0.5)
        input_psswd = getpass(colored('[+] Master password : ', default)).encode('utf-8')
        cleanLine()
    
    master_username = sha512(input_username).hexdigest()
    master_psswd = sha512(salt+input_psswd).hexdigest()

    # Creates master, accounts [and GPG/PGP keys] tables
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS master (
            username MEDIUMINT NOT NULL,
            password MEDIUMINT NOT NULL,
            salt BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login BLOB NOT NULL,
            password BLOB NOT NULL,
            application_name VARCHAR(255) NOT NULL,
            application_path TINYTEXT
        );
    ''')
    cursor.execute("INSERT INTO master (username, password, salt) VALUES (?, ?, ?)", (master_username, master_psswd, salt))
    connection.commit()
    print(colored("\n[+] Master credentials saved successfully !", default))
    time.sleep(0.5)
    print(colored("[+] Database initialization ...", default))
    time.sleep(0.5)

# Checks if master username and password are correct
def checkMaster():
    master = cursor.execute("SELECT * FROM master").fetchone()
    salt = master[2]
    username = input(colored("[+] Please enter your name : ", default)).encode('utf-8')
    password = getpass(colored("[+] Please enter your master password : ", default)).encode('utf-8')
    
    if sha512(username).hexdigest() == master[0] and sha512(salt+password).hexdigest() == master[1]:
        time.sleep(0.5) 
        print(colored("[!] Master verified !", success))
        return True
    
    else:
        print(colored("[!] Wrong credentials !", warning))
        time.sleep(0.5)
        quit()

# Checks if the database has been initialized
def firstConnection():
    if cursor.execute("SELECT name FROM sqlite_master WHERE type = ? AND name = ?", ('table', 'master')).fetchone() == None: first = True
    else: first = False
    return first        

# Generates a random password with a chosen length
def generatePassword(from_menu):
    length = input(colored("[+] Enter a length for your password. It must be over 8 : ", default))
   
    if length.isdigit() != True:
        print(colored("[!] Please choose a number.", warning))
        time.sleep(0.5)
        cleanLine()
        cleanLine()
        generatePassword(from_menu)        

    elif int(length) <= 7:
        print(colored("[!] Please choose a value over 8.", warning))
        time.sleep(0.5)
        cleanLine()
        cleanLine()
        generatePassword(from_menu)
    
    elif int(length) > 100:
        print(colored("[!] Don't be greedy my friend ...", warning))
        time.sleep(0.5)
        cleanLine()
        cleanLine()
        generatePassword(from_menu)

    else:
        password = ''.join(random.choice(ALPHABET) for i in range(int(length)))        
        print(colored(f"[+] Generated password (copied to your clipboard): {password}", default))
        pyperclip.copy(password)
        if from_menu == True: time.sleep(4), menu()
        else: pass
        
# Generate a derivated private key base on master password and salt
def privateKey():
    master = cursor.execute("SELECT * FROM master").fetchone()
    master_key = master[0].encode('utf-8')
    salt = master[2]
    key = pbkdf2("sha512", master_key, salt, 200000, 32)
    return key

# Function to encrypt data with AES in CBC mode and password based key derivation function PBKDF2-HMAC
def encryption(raw):
    key = privateKey()
    # Set the padding with a lambda function, and encoded it to bytes
    pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), 'utf-8')
    # Set the IV to a random number of 16 bytes
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypt data w/ the IV, cipher and padding in BASE64 to avoid type conflicts
    raw = base64.b64encode(iv + cipher.encrypt(pad(raw)))
    
    return raw

# Function to decrypt data and return it in clear
def decryption(id):
    key = privateKey()
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    login = cursor.execute(f"SELECT login FROM accounts WHERE id = {id} ").fetchone()
    login = base64.b64decode(login[0].decode("utf-8"))

    password = cursor.execute(f"SELECT password FROM accounts WHERE id = {id}").fetchone()    
    password = base64.b64decode(password[0].decode("utf-8"))

    iv = login[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    login = unpad(cipher.decrypt(login[16:]))

    iv = password[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    password = unpad(cipher.decrypt(password[16:]))
  
    return login, password
   
# Function to print all accounts in the database, with the ID and the name of the app
def showAll(from_menu):
    count = 0
    applications = cursor.execute("SELECT id,application_name FROM accounts").fetchone()
    if applications == None: print(colored("No entries found in the database, please first add an account.", warning)), time.sleep(1), menu()
    else: 
        print(colored("""    ID    |   Application name\n   ----------------------------""", default))
        while applications:
            print(colored(f"    {applications[0]}          {applications[1]}", default))
            count += 1
            applications = cursor.fetchone()
    
    if count == 1 : print(colored(f"\n[+] {count} account found in your database.\n", default))
    else: print(colored(f"\n[+] {count} accounts found in your database.\n", default))

    if from_menu:
        back = input(colored("[+] Press 'ENTER' to go back to the menu ", default)) 
        if not back:
            menu()
        else:
            print(colored("[!] Nice try, still going back to menu ! ", default))
            time.sleep(0.5)
            menu()
            
    else: pass
    
# Remove an account
def removeSpecificAccount():
    showAll(False)
    
    try: 
        print(colored("[!] In order to remove an account, master has to be verified !", warning))
        check = checkMaster()
    
        if check:  
            # Check if an ID exists
            all_id = cursor.execute("SELECT id FROM accounts").fetchall()
            valid_id = [i[0] for i in all_id]
            
            # Choose application to remove with ID
            app_id = input(colored("[+] Enter the ID of the application you wish to remove (Press 'ENTER' to cancel): ", default))
            app_name = cursor.execute("SELECT application_name FROM accounts WHERE id = ?", (app_id,)).fetchone()

            try: 
                if int(app_id) not in valid_id:
                    print(colored("[!] Incorrect value, restarting ...\n", default))
                    time.sleep(0.5)
                    menu()
            
            except ValueError:
                print("[!] Value error !")
                time.sleep(0.5)
                menu()
            
            else:
                confirm = input(colored(f"[?] Are you sure you want to delete '{app_name[0]}' from the database ? Enter Y/N : ", warning)).lower()
                if confirm == 'y':
                    cursor.execute("DELETE FROM accounts WHERE id = ?", (app_id,))
                    connection.commit() 
                    print(colored(f"[-] '{app_name[0]}' credentials has been deleted !", success))
                    time.sleep(1)
                    menu()
                else:
                    time.sleep(0.5)
                    menu()

    except KeyboardInterrupt:
        print(colored("\n[!] Keyboard interrupt detected, exiting ...", default))

    else:
        quit()
        
# Wipe out accounts
def removeAll():
    showAll(False)
    try: 
        print(colored("[!] In order to remove all accounts, master has to be verified !", warning))
        check = checkMaster()
        confirm = input(colored(f"[!] Are you sure you want to delete the database ? Enter Y/N : ", warning)).lower()

        if check:
            if confirm == 'y':
                print(colored("[-] Deleting all accounts ...", default))
                time.sleep(0.5)
                cursor.execute("DELETE FROM accounts;")
                cursor.execute("UPDATE SQLITE_SEQUENCE SET SEQ=0 WHERE NAME='accounts';")
                connection.commit()
                print(colored("[+] All accounts have been deleted !", success))
                time.sleep(1)
                menu()
            else:
                print(colored("[!] Canceled", warning))
                time.sleep(1)
                menu()
    except KeyboardInterrupt:
        print(colored("\n[!] Keyboard interrupt detected, exiting ...", default))

    else:
        quit()
   
# Add encrypt account
def addAccount():
    login = input(colored("[+] Account login : ",default))
    application_name = input(colored("[+] Application name : ",default))
    application_path = input(colored("[+] Application path [optionnal] (ex : github.com) : ",default))
    password = input(colored("[+] Account password (Press '1' to get a generated password or '2' to enter your own ) : ",default))

    if password == '1':
        generatePassword(False)
        password = pyperclip.paste()
    elif password == '2':
         password = getpass(colored("[+] Account password : ",default))
    else:
        print(colored("[!] Incorrect values, restarting ...", warning))
        time.sleep(0.5)
        menu()

    login, password = encryption(login), encryption(password)
    cursor.execute("INSERT INTO accounts (login, password, application_name, application_path) VALUES (?, ?, ?, ?)", (login, password, application_name, application_path))
    connection.commit()
    print(colored(f"[+] Account successfully added ! ", success))
    time.sleep(2)
    menu()

# Show account with ID
def showSpecificAccount():
    showAll(False)
    
    try: 
        print(colored("[!] In order to show an account, master has to be verified !", warning))
        check = checkMaster()
    
        if check:  
            # Check if an ID exists
            all_id = cursor.execute("SELECT id FROM accounts").fetchall()
            valid_id = [i[0] for i in all_id]
            
            # Choose application to show with ID
            app_id = input(colored("[+] Enter the ID of the application you wish to show (Press 'ENTER' to cancel): ", default))
            app_name = cursor.execute("SELECT application_name FROM accounts WHERE id = ?", (app_id,)).fetchone()
        
            try: 
                if int(app_id) not in valid_id:
                    print(colored("[!] Incorrect value, restarting ...\n", default))
                    time.sleep(0.5)
                    menu()
            
            except ValueError:
                time.sleep(0.5)
                menu()
            
            else:
                login, password = decryption(app_id)
                login, password = login.decode('utf-8'), password.decode('utf-8')
                
                print(colored(f"""
    -------------------------------------
    [+] Application : {app_name[0]}
    [+] Login       : {login}   
    [+] Password    : {password}
    -------------------------------------\n""", default))

                copy = input(colored(f"[?] Do you want to copy your password ? Enter Y/N : ", default)).lower()
                if copy == 'y':
                    pyperclip.copy(password)
                    print(colored(f"[+] Your password has been copied to your clipboard ! ", default))
                    openBrowser(app_id)
                    time.sleep(0.5)
                    menu()
                else:
                    openBrowser(app_id)
                    time.sleep(0.5)
                    menu()

    except KeyboardInterrupt:
        print(colored("\n[!] Keyboard interrupt detected, exiting ...", default))

    else:
        print(colored("[!] Exiting ...", warning))

def changePassword():
    showAll(False)

    try: 
        print(colored("[!] In order to modify an account, master has to be verified !", warning))
        check = checkMaster()
    
        if check:  
            # Check if an ID exists
            all_id = cursor.execute("SELECT id FROM accounts").fetchall()
            valid_id = [i[0] for i in all_id]
            # Choose application to show with ID
            app_id = input(colored("[+] Enter the ID of the application you wish to modify (Press 'ENTER' to cancel): ", default))
            
            try: 
                if int(app_id) not in valid_id:
                    print(colored("[!] Incorrect value, restarting ...\n", default))
                    time.sleep(0.5)
                    menu()
            
            except ValueError:
                time.sleep(0.5)
                menu()
            
            else:
                app_id = int(app_id)
                password = input(colored("[+] New password (Press '1' to get a generated password or '2' to enter your own ) : ",default))

            if password == '1':
                generatePassword(False)
                password = pyperclip.paste()
            elif password == '2':
                password = getpass(colored("[+] New password : ",default))
            else:
                print(colored("[!] Incorrect values ...", warning))
                menu()

            password = encryption(password)
            cursor.execute("UPDATE accounts SET password = (?) WHERE id = (?)", (password, app_id))
            connection.commit()
            print(colored(f"[+] Password successfully updated ! ", success))
            time.sleep() 
            menu()

    except KeyboardInterrupt:
        print(colored("\n[!] Keyboard interrupt detected, exiting ...", default))
    else:
        print(colored("[!] Exiting ...", warning))

# Open default browser and go to website
def openBrowser(id):
    url = cursor.execute(f"SELECT application_path FROM accounts WHERE id = {id}").fetchone()
    url = url[0]
    if not url:
       pass
    else: 
        choice = input(colored("[+] Do you want to open website ? Enter Y/N : ", default)).lower()
        if choice == 'y':
            prefix = "https://www."
            url = prefix + url
            webbrowser.open(url)
        else:
            pass

# Main menu
def menu():
    banner()
    print(colored("""    
   __________________ MAIN MENU ____________________
  |                                                 |
  |     Press 1 to : Add a account                  |
  |     Press 2 to : Show an account credentials    |
  |     Press 3 to : Show all accounts              |
  |     Press 4 to : Delete an account              |
  |     Press 5 to : Wipe out all accounts          |
  |     Press 6 to : Generate a password            |
  |     Press 7 to : Change an account password     |
  |     Press 8 to : Exit                           |
  |_________________________________________________|
    """, default))

    choice = input(colored("[?] What would you like to do ? Enter the corresponding number : ", default))
    if choice == '1': banner(), addAccount()
    elif choice == '2': banner(), showSpecificAccount()
    elif choice == '3': banner(), showAll(True)
    elif choice == '4': banner(), removeSpecificAccount()
    elif choice == '5': banner(), removeAll()
    elif choice == '6': banner(), generatePassword(True)
    elif choice == '7': banner(), changePassword()
    elif choice == '8': quit()
    else: print(colored("[!] Incorrect option ! ", warning)), time.sleep(0.5), menu()

# Main function
def main():
    if firstConnection():
        initialize()
    else:
        checkMaster()

    time.sleep(0.5)
    print(colored("[!] Your vault is now open ! ", default))
    time.sleep(0.5)
    menu()

# *********************************************************************  LAUNCH ******************************************************************************************* 
if __name__ == '__main__':    
    try:
        if sys.version_info[0] < 3:
            print(colored('[!] Please use Python 3 ! ', warning))
            quit()
        else:
            main()
    except KeyboardInterrupt:
        print(colored("\n[!] Keyboard interrupt detected, exiting ...", default))