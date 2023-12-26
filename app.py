import numpy as np
import os
from os.path import join, dirname
from dotenv import load_dotenv
from pymongo import MongoClient
import jwt
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
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
        return render_template(
            'chat_with.html',
            user_info=user_info,
            chats=chats,
            users=users,
            user_chat=user_chat,
            status=status
        )
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for('home'))

# Function TO Encryption
def hill_cipher_encrypt(PT, key):
    # Menghapus spasi dan mengubah huruf kecil
    PT = PT.lower()

    # Mendefinisikan abjad dengan nomor, termasuk karakter khusus
    EAM = {chr(i): i - 97 for i in range(32, 127)}

    # Mendapatkan nomor dari plaintext
    PT_numbers = [EAM.get(char, None) for char in PT]

    # Validasi kunci dan plaintext
    if any(num is None for num in PT_numbers):
        print("Error: Karakter tidak valid dalam plaintext.")
        return None

    key_numbers = [EAM.get(char, None) for char in key]

    # Validasi kunci
    if any(num is None for num in key_numbers):
        print("Error: Karakter tidak valid dalam kunci.")
        return None

    BL = len(key) // 2  # Panjang Blok

    # Memeriksa apakah matriks kunci dapat diinvers
    try:
        key_matrix = np.array(key_numbers).reshape(BL, BL)
        np.linalg.inv(key_matrix)
    except np.linalg.LinAlgError:
        print("Error: Matriks kunci tidak dapat diinvers.")
        return None

    # Mengubah nomor PT menjadi matriks
    PT_array = np.array(PT_numbers)

    # Mengisi spasi pada plaintext jika panjangnya tidak habis dibagi oleh BL
    if len(PT_array) % BL != 0:
        padding = BL - (len(PT_array) % BL)
        PT_array = np.concatenate([PT_array, np.zeros(padding, dtype=int)])

    PT_blocks = np.split(PT_array, len(PT_array) // BL)

    CT_blocks = [np.matmul(PT_blocks[i], key_matrix) % 94 for i in range(len(PT_blocks))]

    CT_array = np.concatenate(CT_blocks)

    # Mengonversi kembali ke karakter, memperhatikan rentang ASCII
    CT = ''.join([chr(i + 32) for i in CT_array])

    return CT

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
        key = "test"
        ciphertext = hill_cipher_encrypt(plaintext_receive, key)
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