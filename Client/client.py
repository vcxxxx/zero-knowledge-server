import requests
import click
from getpass import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import json
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
SERVER_URL = 'https://localhost:5001'
SESSION = requests.Session()
SESSION.verify = 'ca.pem'


def register_user():
    username = input("Enter email: ") #Also sanitise.
    if(not is_valid_email(username)):
        return
    password = getpass('Enter password: ')
    if(not is_valid_password(password)):
        return
    response1 = trigger2FA(username)
    if(not response1):
        return
    user_input = input("Enter the OTP sent to your email: ")    
    response2 = verify2FA(user_input)
    if(not response2):
        return
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize keys
    pem_private_key = private_key.private_bytes( #gotta hide the private key in the folder by default if possible.
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save private key locally
    with open(f'{username}_private_key.pem', 'wb') as f:
        f.write(pem_private_key)

    data = {
        'username': username,
        'password': password,
        'public_key': pem_public_key.decode()
    }
    response = SESSION.post(f'{SERVER_URL}/register', json=data)
    print(response.json())


def login_user():
    username = input("Enter email: ") #Sanitisation
    if(not is_valid_email(username)):
        return
    response1 = trigger2FA(username)
    if(not response1):
        return
    user_input = input("Enter the OTP sent to your email: ")    
    response2 = verify2FA(user_input)
    if(not response2):
        return
    password = getpass('Enter password: ') #sanitisation
    challenge = request_challenge(username)
    response = send_response(username, password, challenge)
    if response.status_code == 200:
        token = response.json()['token']
        SESSION.headers.update({'x-access-token': token})
        print('Logged in successfully!')
        SESSION.headers.update({'logged_in_username' : username})
    else:
        print(response.json())



def upload_file(): 
    filepath = input("Please enter the path file: ")
    recipients = input("Please enter the usernames of recipients: ") #sanitisation of some kind?
    recipients_list = recipients.split(", ")
    logged_in_user = SESSION.headers.get('logged_in_username') 
    print(f"Logged in user is {logged_in_user}")
    if logged_in_user not in recipients_list:
        recipients_list.append(logged_in_user)
    #Generate symmetric key for the file's encryption
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_file_data = encrypt_file(filepath, cipher)
    valid_recipients_and_keys = {}
    for recipient in recipients_list:
        response = get_public_key(recipient)
        if(response is None):
            continue
        public_key_pem = response['public_key']
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),  # Convert string to bytes
            backend=default_backend()
        )
        encrypted_symmetric_key = encrypt_symmetric_key(key, public_key)
        valid_recipients_and_keys[recipient] = encrypted_symmetric_key.hex() #convert to hex string

       
    files = {
        'file': encrypted_file_data   
    }        
    
    data = {
        'filename':  os.path.basename(filepath),
        'valid_recipients_and_keys': json.dumps(valid_recipients_and_keys)
    }
    
    response = SESSION.post(f'{SERVER_URL}/upload', files=files, data=data)
    print(response.json())
    

def get_public_key(username):
    params = {
        'username': username
    }
    response = SESSION.get(f'{SERVER_URL}/PUBLIC_KEY', params=params)
    if response is None or response.status_code == 404:
        print(f"Public key for {username} does not exist")
        return None
    return response.json()
        
    # Encrypt the file
def encrypt_file(file_path, cipher):
    # Read the file data in binary
    with open(file_path, 'rb') as file:
        file_data = file.read()
    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)


    print("File encrypted successfully.")
    return encrypted_data
    
def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key

def download_file():
    file_id = input("Enter file id to download: ")
    response = SESSION.get(f'{SERVER_URL}/download/{file_id}')
    if response.status_code != 200:
        try:
            print(response.json())  # Try to parse error message if JSON
        except requests.exceptions.JSONDecodeError:
            print("Error: Unable to retrieve file. The server did not respond with JSON.")
        return
    password = getpass('Enter the password to unlock your private key: ')
    with open(f"{SESSION.headers.get('logged_in_username')}_private_key.pem", 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode('utf-8'),
            backend=default_backend()
        )
    file_content = response.content
    #encrypted_key = response.headers.get('x-encrypted-key')
    encrypted_key = bytes.fromhex(response.headers.get('x-encrypted-key'))
    filename = response.headers.get('x-filename')
    
    symmetric_key = decrypt_symmetric_key(encrypted_key, private_key)
    cipher = Fernet(symmetric_key)
    decrypted_file_data = cipher.decrypt(file_content)
    filepath = os.path.join('downloads', f'{filename}.txt')
    os.makedirs('downloads', exist_ok=True)
    save_decrypted_file(decrypted_file_data, filepath)
    
    
    
def decrypt_symmetric_key(encrypted_key, private_key):
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return symmetric_key   

def save_decrypted_file(decrypted_data, output_path):
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    print("Decrypted file saved successfully.")


def view_files():
    response = SESSION.get(f'{SERVER_URL}/view_files')
    print(SESSION.headers.get('logged_in_username'))
    if response.status_code == 200:
        files = response.json().get('files', [])
        if files:
            print("\nFiles accessible to you:")
            for idx, file in enumerate(files, start=1):
                print(f"{idx}. File ID: {file['file_id']}, Filename: {file['filename']}")
        else:
            print("You have no files accessible to you.")
    else:
        print("Error retrieving files:", response.json().get('message', 'Unknown error'))
        
def is_valid_password(password):
    # Define the password complexity rules
    # At least 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character
    if len(password) < 8:
        print("Make sure your password is minimum 8 characters.")
        return False
    if not re.search(r'[A-Z]', password):  # Check for uppercase
        print("Make sure your password has uppercase characters.")
        return False
    if not re.search(r'[a-z]', password):  # Check for lowercase
        print("Make sure your password has lowercase characters.")
        return False
    if not re.search(r'[0-9]', password):  # Check for a digit
        print("Make sure your password has digits.")
        return False
    if not re.search(r'[\W_]', password):  # Check for special character
        print("Make sure your password has special characters.")
        return False
    return True

def request_challenge(username):
    params = {
        'username': username
    }
    response = SESSION.get(f'{SERVER_URL}/get_challenge', params=params)
    return response.json()['challenge']

def send_response(username, password, challenge):
    # Hash the password locally (this should match the server's storage hash function)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Calculate the response using the challenge
    response_hash = hashlib.sha256((password_hash + challenge).encode()).hexdigest()

    # Send the response back to the server
    data = {'username': username, 'response': response_hash, 'challenge': challenge}
    response = SESSION.post(f'{SERVER_URL}/verify_response', json=data)
    return response


def is_valid_email(email):
    """
    Validate the format of an email address.
    Returns True if valid, otherwise False.
    """
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    
    if re.match(email_regex, email):
        return True
    else:
        print("Please enter valid email ID")
        return False
    
    
def trigger2FA(username):
    data = {
        'username': username
    }
    response = SESSION.post(f'{SERVER_URL}/trigger_2fa', json=data)
    if(response.status_code != 200):
        print(response.json())
        return
    else:
        return response

def verify2FA(otp):
    data = {
        'otp': otp
    }
    response = SESSION.post(f'{SERVER_URL}/verify_2fa', json=data)
    if(response.status_code != 200):
        print(response.json())
        return
    else:
        return response

@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """Secure File Client"""
    if ctx.invoked_subcommand is None:
        click.echo("Type 'login', 'upload', 'register', 'download', 'viewfiles' or 'exit' to begin.")
        while True:
            # Prompt for the command in an interactive loop
            command = input("Enter command: ").strip().lower()
            if command == "exit":
                click.echo("Exiting the client.")
                break
            # Attempt to get the command
            cmd = main.get_command(ctx, command)
            if cmd is None:
                # Handle unknown commands
                click.echo("Unknown command. Available commands: login, upload, register, download, viewfiles, exit")
            else:
                # Invoke the found command
                ctx.invoke(cmd)
                



@main.command()
def register():
    """Don't have an account? Register now!"""
    register_user()
    
@main.command()
def login():
    """Existing user? Log in!"""
    login_user()
    
@main.command()
def upload():
    """Upload a file!"""
    upload_file()
    
@main.command()
def download():
    """Download a file!"""
    download_file() 

@main.command()
def viewfiles():
    """View the files available to you!"""
    view_files()

if __name__ == '__main__':
    main()