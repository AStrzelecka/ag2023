# -*- coding: utf-8 -*-

import os
from flask import Flask, render_template, request, redirect, send_file
from werkzeug.utils import secure_filename
import io
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Funkcja szyfruj¹ca
def encrypt_file(plaintext, password):
    # Generowanie klucza na podstawie has³a
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'somesalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Szyfrowanie pliku
    cipher = Cipher(algorithms.AES(key), modes.CFB(bytes.fromhex('00112233445566778899aabbccddeeff')), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext

# Funkcja deszyfruj¹ca
def decrypt_file(ciphertext, password):
    # Generowanie klucza na podstawie has³a
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'somesalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))

    # Odszyfrowywanie pliku
    cipher = Cipher(algorithms.AES(key), modes.CFB(bytes.fromhex('00112233445566778899aabbccddeeff')), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

# Strona g³ówna
@app.route('/')
def index():
    return render_template('index.html')

# Endpoint szyfrowania
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']

    if file:
        try:
            # Odczytanie has³a i nazwy pliku z formularza
            password = request.form['password']
            new_filename = secure_filename(request.form['new_filename'])
            
            # Pobranie oryginalnego rozszerzenia pliku
            original_extension = os.path.splitext(file.filename)[1]
            
            # Nowa nazwa pliku z oryginalnym rozszerzeniem
            output_filename = secure_filename(new_filename) + original_extension

            # Odczytanie zawartoœci pliku
            plaintext = file.read()

            # Szyfrowanie treœci pliku
            ciphertext = encrypt_file(plaintext, password)

            # Zapisanie zaszyfrowanej treœci do BytesIO
            encrypted_content = io.BytesIO()
            encrypted_content.write(ciphertext)
            encrypted_content.seek(0)

            # Wys³anie zaszyfrowanej treœci jako za³¹cznik
            return send_file(encrypted_content, as_attachment=True, download_name=output_filename) 
        
        except Exception as e:
            return str(e)

    else:
        print ('Error')

# Endpoint deszyfrowania
@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']

    if file:
        try:
            # Odczytanie has³a i nazwy pliku z formularza
            password = request.form['password']
            new_filename = secure_filename(request.form['new_filename'])
            
            # Pobranie oryginalnego rozszerzenia pliku
            original_extension = os.path.splitext(file.filename)[1]

            # Nowa nazwa pliku z oryginalnym rozszerzeniem
            output_filename = secure_filename(new_filename) + original_extension

            # Odczytanie zawartoœci pliku
            ciphertext = file.read()

            # Odszyfrowywanie treœci pliku
            plaintext = decrypt_file(ciphertext, password)

            # Zapisanie odszyfrowanej treœci do BytesIO
            decrypted_content = io.BytesIO()
            decrypted_content.write(plaintext)
            decrypted_content.seek(0)

            # Wys³anie odszyfrowanej treœci jako za³¹cznik
            return send_file(decrypted_content, as_attachment=True, download_name=output_filename)

        except Exception as e:
            return str(e)

    else:
        print ('Error')

# Uruchomienie programu
if __name__ == '__main__':
    app.run(debug=True)