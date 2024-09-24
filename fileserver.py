# file_server.py

from flask import Flask, request, jsonify, send_file
import os
import secrets

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    # Use a secure random string for the filename
    filename = secrets.token_urlsafe(32)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    file_url = f"/files/{filename}"
    return jsonify({'file_url': file_url})


@app.route('/files/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        return 'File not found', 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)
