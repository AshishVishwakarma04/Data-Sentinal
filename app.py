import os
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import base64
import datetime
import cv2

app = Flask(__name__)
app.secret_key = base64.urlsafe_b64encode(os.urandom(32))
UPLOAD_FOLDER = 'uploads'
CAPTURES_FOLDER = 'static/captures'
INVALID_ATTEMPTS_FILE = 'invalid_attempts.txt'

def record_invalid_attempt(ip_address):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(INVALID_ATTEMPTS_FILE, 'a') as file:
        file.write(f'Timestamp: {timestamp} - IP Address: {ip_address}\n')

def capture_image():
    camera = cv2.VideoCapture(0)
    _, frame = camera.read()
    camera.release()
    if frame is not None:
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f'capture_{timestamp}.jpg'
        file_path = os.path.join(UPLOAD_FOLDER, filename)  # Save the image to the 'uploads' folder
        cv2.imwrite(file_path, frame)


def get_invalid_login_attempts():
    invalid_attempts = []
    if os.path.exists(INVALID_ATTEMPTS_FILE):
        with open(INVALID_ATTEMPTS_FILE, 'r') as file:
            for line in file:
                if line.strip():
                    timestamp, ip_address = line.strip().split('-')
                    invalid_attempts.append({'timestamp': timestamp.strip(), 'ip_address': ip_address.strip()})
    return invalid_attempts

def clear_invalid_login_attempts():
    if os.path.exists(INVALID_ATTEMPTS_FILE):
        os.remove(INVALID_ATTEMPTS_FILE)

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    file_list = os.listdir(UPLOAD_FOLDER)
    invalid_attempts = get_invalid_login_attempts()
    return render_template('index.html', files=file_list, invalid_attempts=invalid_attempts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Perform authentication logic, e.g., check username and password against a database
        if username == 'admin' and password == 'password':
            session['username'] = username
            clear_invalid_login_attempts()
            return redirect(url_for('index'))
        else:
            ip_address = request.remote_addr
            record_invalid_attempt(ip_address)
            capture_image()
            return render_template('login.html', error=True)
    return render_template('login.html', error=False)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return redirect(url_for('index'))
    filename = secure_filename(uploaded_file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(file_path)
    return redirect(url_for('index'))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'username' not in session:
        return redirect(url_for('login'))
    file_name = request.form['file_name']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)

    fernet = Fernet(app.secret_key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

    return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'username' not in session:
        return redirect(url_for('login'))
    encrypted_file = request.files['encrypted_file']
    if encrypted_file.filename == '':
        return redirect(url_for('index'))
    filename = secure_filename(encrypted_file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    encrypted_file.save(file_path)

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    fernet = Fernet(app.secret_key)
    decrypted_data = fernet.decrypt(encrypted_data)

    decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'decrypted_{filename}')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    return send_file(decrypted_file_path, as_attachment=True)

class LogEntry:
    def __init__(self, timestamp, event_type, client_ip, url, metadata):
        self.timestamp = timestamp
        self.event_type = event_type
        self.client_ip = client_ip
        self.url = url
        self.metadata = metadata

contract_code = """
contract WebServerLogs {
    struct LogEntry {
        uint256 timestamp;
        string eventType;
        string clientIP;
        string url;
        string metadata;
    }

    LogEntry[] public logEntries;

    function addLogEntry(uint256 timestamp, string memory eventType, string memory clientIP, string memory url, string memory metadata) public {
        LogEntry memory entry;
        entry.timestamp = timestamp;
        entry.eventType = eventType;
        entry.clientIP = clientIP;
        entry.url = url;
        entry.metadata = metadata;
        logEntries.push(entry);
    }

    function getLogEntries() public view returns (LogEntry[] memory) {
        return logEntries;
    }
}
"""

if __name__ == '__main__':
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['CAPTURES_FOLDER'] = CAPTURES_FOLDER
    app.run(debug=True)