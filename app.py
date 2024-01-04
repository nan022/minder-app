import numpy as np
import os
from os.path import join, dirname
from dotenv import load_dotenv
from pymongo import MongoClient
import jwt
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
import pymongo
from werkzeug.utils import secure_filename
from collections import defaultdict
import datetime as dt
from datetime import datetime, timedelta

app = Flask(__name__)

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)

db = client[DB_NAME]

app = Flask(__name__)

TOKEN_KEY = 'nande'
SECRET_KEY = "NANDAIME"

@app.route('/', methods=['GET','POST'])
def home():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode (
            token_receive, 
            SECRET_KEY, 
            algorithms=['HS256']
        )
        username = payload.get('username')
        user_info = db.users.find_one({'username': username})
        users = list(db.users.find())
        threads = db.threads.find()
        return render_template("index.html", user_info=user_info, threads=threads, users=users)
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was problem logging you in'
        return redirect(url_for('landing', msg=msg))

@app.route('/sign_in', methods=["POST"])
def sign_in_cek():
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    result = db.users.find_one({
        "username": username_receive,
        "password": password_receive,
    })
    if result:
        payload = {
            "username": username_receive,
            "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 2),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({
            "result": "success",
            "token": token,
        })
    else:
        return jsonify({
            "result": "fail",
            "msg": "We could not find a user with that id/password combination",
        })

@app.route('/login')
def login():
    token_receive = request.cookies.get(TOKEN_KEY)
    return render_template("login.html",token=token_receive)

@app.route("/signup")
def regis():
    return render_template("registrasi.html")

@app.route("/minder")
def landing():
    return render_template("landing.html")

@app.route("/sign_up", methods=["POST"])
def sign_up():
    fullname_receive = request.form['fullname_give']
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    doc = {
        'nama': fullname_receive,
        'username': username_receive,
        'password': password_receive
    }
    db.users.insert_one(doc)
    return jsonify({'msg': 'Data berhasil disimpan!'})

@app.route('/chatting/<username>', methods=['GET'])
def user(username):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        status = username == payload.get('id')
        user_info = db.users.find_one(
            {'username': username},
            {'_id': False}
        )
        chats = db.chat.find({'username': username})  # Use find instead of find_one
        users = db.users.find()
        return render_template(
            'chatting.html',
            user_info=user_info,
            chats=chats,
            users=users,
            status=status
        )
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))
    
@app.route('/friends/<username>', methods=['GET'])
def friends(username):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        status = username == payload.get('id')
        user_info = db.users.find_one(
            {'username': username},
            {'_id': False}
        )
        chats = db.chat.find({'username': username})  # Use find instead of find_one
        users = db.users.find()
        return render_template(
            'friends.html',
            user_info=user_info,
            chats=chats,
            users=users,
            status=status
        )
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))
    
@app.route('/chat_with/<username>/<receiver>', methods=['GET'])
def receiver(username, receiver):
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        status = username == payload.get('id')
        user_info = db.users.find_one(
            {'username': username},
            {'_id': False}
        )
        chats = db.chat.find({
            '$or': [
                {'sender': username, 'receiver': receiver},
                {'sender': receiver, 'receiver': username}
            ]
        }).sort('date', 1)
        users = db.users.find()
        user_chat = db.users.find_one({'username': receiver})
        key_matrix = np.array([[2, 1], [3, 4]])  # Matriks kunci 2x2
        return render_template(
            'chat_with.html',
            user_info=user_info,
            chats=chats,
            users=users,
            user_chat=user_chat,
            status=status,
            hill_cipher_decrypt=hill_cipher_decrypt,
            key_matrix=key_matrix
        )
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))

def hill_cipher_encrypt(plain_text, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plain_text = plain_text.upper()  # Mengubah teks menjadi huruf kapital
    encrypted_text = ""  # Inisialisasi teks terenkripsi sebagai string kosong
    
    n = len(key_matrix)  # Ukuran matriks kunci
    
    # Pad teks jika panjangnya tidak kelipatan dari n
    if len(plain_text) % n != 0:
        plain_text += "X" * (n - (len(plain_text) % n))
    
    # Loop melalui teks plain dan enkripsi per blok n
    for i in range(0, len(plain_text), n):
        chunk = plain_text[i:i + n]  # Ambil potongan teks sepanjang n
        chunk_vector = []
        
        # Buat vektor karakter, mengabaikan spasi
        for char in chunk:
            if char in alphabet:
                chunk_vector.append(alphabet.index(char))
            else:
                chunk_vector.append(ord(char) - ord('A'))
        
        encrypted_chunk = np.dot(key_matrix, chunk_vector) % 26  # Enkripsi menggunakan matriks kunci
        encrypted_text += "".join([alphabet[int(idx)] if isinstance(idx, (int, np.integer)) else chr(idx + ord('A')) for idx in encrypted_chunk])  # Gabungkan hasil enkripsi
    
    return encrypted_text  # Mengembalikan teks terenkripsi

# Fungsi untuk menghitung invers matriks modulo
def matrix_mod_inverse(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))  # Menghitung determinan matriks
    det_inverse = pow(det, -1, modulus)  # Menghitung invers determinan
    adjugate = (det * np.linalg.inv(matrix)).round()  # Menghitung matriks adjugate
    inverse = (adjugate * det_inverse) % modulus  # Menghitung invers matriks
    return inverse

# Fungsi untuk mendekripsi teks yang telah dienkripsi menggunakan Hill Cipher
def hill_cipher_decrypt(encrypted_text, key_matrix):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted_text = encrypted_text.upper()  # Mengubah teks terenkripsi menjadi huruf kapital
    decrypted_text = ""  # Inisialisasi teks terdekripsi sebagai string kosong
    
    n = len(key_matrix)  # Ukuran matriks kunci
    
    # Menghitung invers matriks kunci
    key_inverse = matrix_mod_inverse(key_matrix, 26)
    
    # Loop melalui teks terenkripsi dan mendekripsi per blok n
    for i in range(0, len(encrypted_text), n):
        chunk = encrypted_text[i:i + n]  # Ambil potongan teks terenkripsi sepanjang n
        chunk_vector = np.array([alphabet.index(char) for char in chunk])  # Buat vektor karakter
        decrypted_chunk = np.dot(key_inverse, chunk_vector) % 26  # Mendekripsi menggunakan invers matriks kunci
        decrypted_text += "".join([alphabet[int(idx)] for idx in decrypted_chunk])  # Gabungkan hasil dekripsi
    
    return decrypted_text  # Mengembalikan teks terdekripsi

@app.route("/send_chat", methods=["POST"])
def send_chat():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        sender_receive = request.form['sender_give']
        receiver_receive = request.form['receiver_give']
        plaintext_receive = request.form['plaintext_give']
        current_date = datetime.now()
        formatted_date = current_date.strftime("%Y-%m-%d %H:%M")
        key_matrix = np.array([[2, 1], [3, 4]])  # Matriks kunci 2x2
        ciphertext = hill_cipher_encrypt(plaintext_receive, key_matrix)  # Enkripsi teks
        user_info = db.users.find_one({'username': payload.get('username')})
        doc = {
            'id_user' : user_info['_id'],
            'plaintext' : plaintext_receive,
            'ciphertext' : ciphertext,
            'date' : formatted_date,
            'sender' : sender_receive,
            'receiver' : receiver_receive
        }
        db.chat.insert_one(doc)
        newly_inserted_data = db.chat.find_one(sort=[('_id', pymongo.DESCENDING)])  # Mengambil data terakhir berdasarkan _id
        decrypted_text = hill_cipher_decrypt(newly_inserted_data.get('ciphertext'), key_matrix)
        print(decrypted_text)
        return jsonify({'msg': 'Data berhasil disimpan!'})
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was a problem logging you in'
        return redirect(url_for('login', msg=msg))
    
@app.route("/add_threads", methods=["POST"])
def add_threads():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        threads_receive = request.form['threads_give']
        current_date = datetime.now()
        formatted_date = current_date.strftime("%Y-%m-%d %H:%M")
        user_info = db.users.find_one({'username': payload.get('username')})
        doc = {
            'id_user' : user_info['_id'],
            'username' : user_info['username'],
            'tweat' : threads_receive,
            'date' : formatted_date
        }
        db.threads.insert_one(doc)
        return jsonify({'msg': 'Data berhasil disimpan!'})
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was a problem logging you in'
        return redirect(url_for('login', msg=msg))

@app.route('/update_profile', methods=['POST'])
def save_img():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = jwt.decode(
            token_receive,
            SECRET_KEY,
            algorithms=['HS256']
        )
        nama_receive = request.form['nama_give']
        user_info = db.users.find_one({'username': payload.get('username')})
        username = user_info['username']
        new_doc = {"nama": nama_receive}
        if "file_give" in request.files:
            file = request.files["file_give"]
            filename = secure_filename(file.filename)
            extension = filename.split(".")[-1]
            file_path = f"profile_pics/{username}.{extension}"
            file.save("./static/" + file_path)
            new_doc["profile_pic"] = filename
            new_doc["profile_pic_real"] = file_path
        db.users.update_one({"username": payload["username"]}, {"$set": new_doc})
        return jsonify({'msg': 'Data berhasil disimpan!'})
    except jwt.ExpiredSignatureError:
        msg = 'Your token has expired'
        return redirect(url_for('login', msg=msg))
    except jwt.exceptions.DecodeError:
        msg = 'There was a problem logging you in'
        return redirect(url_for('login', msg=msg))

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)