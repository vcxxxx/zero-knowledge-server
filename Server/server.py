from flask import Flask, request, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps
import uuid
import json
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import smtplib
from email.message import EmailMessage
import hashlib

app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
encryption_key = os.getenv('ENCRYPTION_KEY')
encryption_key = bytes.fromhex(encryption_key.strip()) 
otp_email = os.getenv('otp_email')
otp_password = os.getenv('otp_password')
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.Text, nullable=False)

class File(db.Model):
    id = db.Column(db.String(200), primary_key=True)  
    owner_name = db.Column(db.String(200), nullable=False)  
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(200), nullable=False)
    

class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(200), nullable=False)  
    user_id = db.Column(db.Integer, nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)

# Authentication Decorator - used to authenticate sessions and access to app actions
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/register', methods=['POST'])
def register():  
    data = request.get_json()
    hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
    encrypted_username = deterministic_encrypt(data['username'])
    new_user = User(
        username=encrypted_username,
        password=hashed_password, 
        public_key=data['public_key']
    )
    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        return jsonify({'message': 'Username already exists!'}), 409
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/upload', methods=['POST'])
@token_required
def upload(current_user):
    if 'file' not in request.files or 'valid_recipients_and_keys' not in request.form or 'filename' not in request.form:
        return jsonify({'message': 'Invalid request!'}), 400
    file = request.files['file']
    encrypted_keys = json.loads(request.form.get('valid_recipients_and_keys'))
    filename = request.form.get('filename')

    # Save file
    file_id = str(uuid.uuid4())
    filepath = os.path.join('uploads', f'{file_id}_{filename}.enc')
    os.makedirs('uploads', exist_ok=True)
    file.save(filepath)

    new_file = File(
        id = file_id,
        owner_name=current_user.username,
        filename=filename,
        filepath=filepath
    )
    db.session.add(new_file)
    db.session.commit()

    # Save encrypted keys
    for username, encrypted_key in encrypted_keys.items():
        print(file_id)
        user = User.query.filter_by(username=deterministic_encrypt(username)).first()
        access = FileAccess(
            file_id=file_id,
            user_id = user.id,
            encrypted_key=encrypted_key
        )
        db.session.add(access)
    try:
        db.session.commit()
    except Exception as e:
        print(f"Error committing to the database: {e}")
        
    all_access_entries = FileAccess.query.all()
    for entry in all_access_entries:
        print(f"File ID: {entry.file_id}, User ID: {entry.user_id}")
    

    return jsonify({'message': 'PLEASE NOTE - You will need the file ID to download the file!', 'file_id': file_id}), 201


@app.route('/PUBLIC_KEY', methods=['GET'])
def get_public_key():
    username = request.args.get('username')  
    if not username:
        return jsonify({'error': 'Username not provided'}), 400
    user = User.query.filter_by(username=deterministic_encrypt(username)).first()
    if user:
        return jsonify({'public_key': user.public_key}), 200
    else:
        return jsonify({'error': 'User not found'}), 404
   
@app.route('/download/<file_id>', methods=['GET'])
@token_required
def download(current_user, file_id):
    access = FileAccess.query.filter_by(file_id=file_id, user_id=current_user.id).first()
    if not access:
        return jsonify({'message': 'Access denied!'}), 403

    file_record = File.query.filter_by(id=file_id).first()
    print(f"here's the uuid {file_record.id}")
    if not file_record:
        return jsonify({'message': 'File not found!'}), 404

    try:
        response = send_file(
            file_record.filepath,
            as_attachment=True,
            download_name=file_record.filename,
            mimetype='application/octet-stream'
        )
        
        # Set additional headers directly on the response
        response.headers['x-filename'] = file_record.filename
        response.headers['x-encrypted-key'] = access.encrypted_key
        
        # Return the response with a 200 OK status
        return response, 200
    except Exception as e:
        return jsonify({'message': 'Error retrieving file', 'error': str(e)}), 500
    
@app.route('/view_files', methods=['GET'])
@token_required
def view_files(current_user):
    # Retrieve all FileAccess entries for the current user
    access_entries = FileAccess.query.filter_by(user_id=current_user.id).all()
    
    # Gather file details for each accessible file
    file_list = []
    for access in access_entries:
        file_record = File.query.filter_by(id=access.file_id).first()
        if file_record:
            file_list.append({
                'file_id': file_record.id,
                'filename': file_record.filename
            })
    
    # Return the list of files as a JSON response
    return jsonify({'files': file_list}), 200

@app.route('/get_challenge', methods=['GET'])
def get_challenge():
    username = request.args.get('username')
    user = User.query.filter_by(username=deterministic_encrypt(username)).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Generate a random challenge (nonce)
    challenge = os.urandom(16).hex()
    return jsonify({'challenge': challenge}), 200


@app.route('/verify_response', methods=['POST'])
def verify_response():
    data = request.get_json()
    username = data['username']
    client_response = data['response']
    challenge = data['challenge']
    user = User.query.filter_by(username=deterministic_encrypt(username)).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Retrieve the stored hash of the password
    stored_password_hash = user.password  # This is the hashed password from registration

    # Retrieve the challenge from session storage
    if not challenge:
        return jsonify({'message': 'Challenge expired or not found'}), 400

    # Server calculates expected response
    expected_response = hashlib.sha256((stored_password_hash + challenge).encode()).hexdigest()

    if expected_response == client_response:
        # Authentication successful
        token = jwt.encode({
        'id': user.id,
        # 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=2)
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token}), 200
    else:
        return jsonify({'message': 'Authentication failed!'}), 401
    
    
def deterministic_encrypt(username: str) -> str:
    """Encrypt the username deterministically."""
    # Generate a fixed hash for the username (ensures the same input produces the same output)
    username_hash = hashlib.sha256(username.encode()).digest()
    
    # Encrypt the hash (to obscure its value and secure it)
    aesgcm = AESGCM(encryption_key)
    nonce = b'\x00' * 12  # Using a fixed nonce for deterministic encryption
    ciphertext = aesgcm.encrypt(nonce, username_hash, None)
    
    return ciphertext.hex()

def generate_otp(length=6):
    # Generate a numeric OTP of the given length
    return ''.join(secrets.choice("0123456789") for _ in range(length))

def verify_otp(user_input_otp, generated_otp):
    return user_input_otp == generated_otp


def send_email(to_email, otp):
    # Set up the email server (e.g., Gmail SMTP server)
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = otp_email
    sender_password = otp_password 
    # Construct the email
    message = EmailMessage()
    message['Subject'] = 'Your OTP Code'
    message['From'] = sender_email
    message['To'] = to_email
    message.set_content(f'Your OTP is: {otp}')

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.send_message(message)
            print("OTP sent successfully.")
            return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

    
@app.route('/trigger_2fa', methods=['POST'])
def trigger_2fa():
    data = request.get_json()
    email = data.get('username')
    print(email)
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Generate and store OTP
    otp = generate_otp()
    # Send OTP via email
    session['otp'] = otp
    response = send_email(email, otp)
    if(response):
        return jsonify({"message": "2FA initiated. OTP sent to your email."}), 200
    else:
        return jsonify({"error": "Failed to send OTP. Please try again later."}), 500
    
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
     data = request.get_json()
     otp = data.get('otp')
     if(session['otp'] == otp):
         return jsonify({"message": "2FA authenticated."}), 200
     else:
         return jsonify({"error": "Wrong OTP entered."}), 500
         
    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5001, debug=False, ssl_context=('server.crt', 'server.key'))
    
    