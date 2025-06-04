from datetime import timedelta, datetime, date
from flask import Flask, logging, render_template, redirect, url_for, flash, request, session, jsonify, Response
from flask_login import current_user, LoginManager, login_user, LoginManager
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, jwt_required
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from functools import wraps
from flask_caching import Cache
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.oauth2 import OAuth2ConsumerBlueprint
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from forms import RegistrationForm, LoginForm, SetNicknameForm
from models import IMAGES_PATH, VIDEOS_PATH, ARQuizQuestion, ARQuizResult, Difficulty, HariPenting, LeaderboardHistory, Quiz, SongArtist, UserQuizScore, db, User, Tokoh, Role, Timeline, get_leaderboard, SentimentAnalyzer, Review, TimelineMedia, BadWord, Song
from email_validator import validate_email, EmailNotValidError
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import random
import os
import uuid
from tensorflow.keras.models import load_model
import tensorflow as tf
from PIL import Image
import numpy as np
import glob
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, pipeline
from huggingface_hub import login
import requests
import torch
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
from bs4 import BeautifulSoup
import re
import cv2
import mediapipe as mp
from dotenv import load_dotenv

load_dotenv()

# Inisialisasi Flask app
app = Flask(__name__)

# Konfigurasi aplikasi
app.config[
    "SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root@localhost:3306/capstone"
app.config['SECRET_KEY'] = 'JETOKIN_CAPSTONE'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# JWT config
app.config['JWT_SECRET_KEY'] = 'JETOKIN_JWT_SECRET'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
jwt = JWTManager(app)

# Inisialisasi DB dan Bcrypt
pymysql.install_as_MySQLdb()
bcrypt = Bcrypt(app)
db.init_app(app)
bcrypt = Bcrypt(app)
cache = Cache(app)

# API KEY
API_KEY = "JETOKIN_API_KEY_SECRET"

# Konfigurasi SMTP Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Gunakan port 465 jika menggunakan SSL
app.config['MAIL_USE_TLS'] = True  # Gunakan TLS untuk port 587
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'zidanreksa789@gmail.com'
app.config['MAIL_PASSWORD'] = 'mykv sqms qxox dskg'  # Masukkan App Password
app.config['MAIL_DEFAULT_SENDER'] = ('Jetokin', 'zidanreksa789@gmail.com')

mail = Mail(app)

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Ambil user dari database


# Fungsi untuk mengirim OTP
def send_otp(email):
    otp = str(random.randint(100000, 999999))  # Generate OTP
    msg = Message("Your OTP Code", recipients=[email])
    msg.body = f"Your OTP code is {otp}. It is valid for 10 minutes."
    mail.send(msg)
    session['otp'] = otp  # Simpan OTP di session
    return otp


# Konfigurasi OAuth untuk Google Login
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_to="google_login",
    scope=[
        "openid", "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ])

app.register_blueprint(google_bp, url_prefix="/google_login")


# Fungsi untuk kompresi ukuran file hingga <2MB
def compress_image_to_size(input_path, output_path, max_size_kb=2048):
    """Kompres gambar agar ukurannya kurang dari max_size_kb (dalam KB)."""
    with Image.open(input_path) as img:
        img = img.convert("RGB")  # Pastikan formatnya RGB
        quality = 85  # Mulai dari kualitas tinggi
        img.save(output_path, "JPEG", quality=quality)

        # Jika ukuran file masih lebih besar dari batas, turunkan kualitas
        while os.path.getsize(
                output_path) > max_size_kb * 1024 and quality > 10:
            quality -= 5
            img.save(output_path, "JPEG", quality=quality)


# Fungsi untuk menghasilkan nama file unik menggunakan UUID
def generate_unique_filename(original_filename):
    """Menghasilkan nama file unik menggunakan UUID."""
    file_extension = os.path.splitext(original_filename)[
        1]  # Contoh: '.jpg' atau '.png'
    unique_filename = f"{uuid.uuid4().hex}{file_extension}"
    return unique_filename


# Jika token expired
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print(
        f"🔴 Token expired. JWT Header: {jwt_header}, JWT Payload: {jwt_payload}"
    )
    flash("Sesi kamu telah habis. Silakan login ulang.", "warning")
    return redirect(url_for('login_apk'))


# Jika token tidak dikirim
@jwt.unauthorized_loader
def missing_token_callback(reason):
    print(f"🔴 Token missing. Reason: {reason}")
    flash("Kamu harus login terlebih dahulu.", "warning")
    return redirect(url_for('login_apk'))


# Jika token salah format atau tidak valid
@jwt.invalid_token_loader
def invalid_token_callback(reason):
    print(f"🔴 Invalid token. Reason: {reason}")
    if request.path.startswith('/api/'):
        return jsonify({"message": "Token tidak valid"}), 401
    else:
        flash("Token tidak valid. Silakan login ulang.", "danger")
        return redirect(url_for('login_apk'))


# Jika token dicabut (opsional kalau kamu pakai token blacklist)
@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    print(
        f"🔴 Token revoked. JWT Header: {jwt_header}, JWT Payload: {jwt_payload}"
    )
    flash("Token telah dicabut. Silakan login ulang.", "danger")
    return redirect(url_for('login_apk'))


@app.route('/login', methods=['GET', 'POST'])
def login_apk():
    form = LoginForm()

    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(
                identity={
                    'user_id': user.user_id,
                    'email': user.email,
                    'nickname': user.nickname,
                    'role': user.role
                },
                expires_delta=timedelta(hours=24))

            session['access_token'] = access_token

            if user.role == 'admin':
                session['admin_token'] = access_token
                return redirect(url_for('admin_menu'))

            if not user.nickname:
                return redirect(url_for('set_nickname'))
            return redirect(url_for('homepage'))

        flash('Email atau password salah.', 'error')

    return render_template('login.html', form=form)


@app.route('/homepage')
def homepage():
    try:
        # Ambil token dari session
        access_token = session.get('access_token')
        if not access_token:
            flash('Kamu belum login, silakan login dulu.', 'error')
            return redirect(url_for('login_apk'))

        # Kalau mau decode token buat ambil data user:
        from flask_jwt_extended import decode_token
        identity = decode_token(access_token)['sub']
        print(f"User JWT: {identity}")

        # Ambil data tokoh
        tokoh_list = Tokoh.query.all()
        zaman_perjuangan_list = db.session.query(
            Tokoh.zaman_perjuangan).distinct().all()
        bidang_perjuangan_list = db.session.query(
            Tokoh.bidang_perjuangan).distinct().all()
        provinsi_list = db.session.query(Tokoh.birth_place).distinct().all()

        lagu_list = Song.query.all()

        # Kelompokin wilayah
        wilayah = {
            "Jawa": [],
            "Sumatera": [],
            "Kalimantan": [],
            "Sulawesi": [],
            "Papua": [],
            "Bali": [],
            "Maluku": [],
            "Lainnya": []
        }
        for provinsi in provinsi_list:
            prov = provinsi[0].lower()
            if 'jawa' in prov:
                wilayah["Jawa"].append(provinsi[0])
            elif 'sumatera' in prov:
                wilayah["Sumatera"].append(provinsi[0])
            elif 'kalimantan' in prov:
                wilayah["Kalimantan"].append(provinsi[0])
            elif 'sulawesi' in prov:
                wilayah["Sulawesi"].append(provinsi[0])
            elif 'papua' in prov:
                wilayah["Papua"].append(provinsi[0])
            elif 'bali' in prov:
                wilayah["Bali"].append(provinsi[0])
            elif 'maluku' in prov:
                wilayah["Maluku"].append(provinsi[0])
            else:
                wilayah["Lainnya"].append(provinsi[0])

        today = datetime.today().strftime('%d-%m')
        hari_penting = HariPenting.query.filter(
            HariPenting.tanggal == today).first()

        return render_template('homepage.html',
                               tokoh_list=tokoh_list,
                               zaman_perjuangan_list=zaman_perjuangan_list,
                               bidang_perjuangan_list=bidang_perjuangan_list,
                               provinsi_list=provinsi_list,
                               wilayah=wilayah,
                               hari_penting=hari_penting,
                               lagu_list=lagu_list)

    except Exception as e:
        flash('Terjadi kesalahan saat mengambil data.', 'error')
        print(str(e))
        return redirect(url_for('login_apk'))


@app.route('/lagu/<int:id>')
def detail_lagu(id):
    lagu = Song.query.get_or_404(id)  # Mengambil lagu berdasarkan id
    return render_template('detail_lagu.html', lagu=lagu)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Cek apakah email sudah ada di database
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email sudah digunakan. Silakan gunakan email lain.',
                  'danger')
            return redirect(url_for('register'))

        # Jika email belum ada, lakukan pendaftaran
        hashed_password = generate_password_hash(
            form.password.data)  # Hash password
        user = User(
            fullname=form.fullname.data,
            email=form.email.data,
            password=hashed_password,  # Simpan password yang sudah di-hash
            gender=form.gender.data,  # Pastikan ini sesuai
            role=Role.user,
            profile_picture='default.jpeg')
        db.session.add(user)
        db.session.commit()
        flash('Akun berhasil dibuat!', 'success')
        return redirect(url_for('login_apk'))  # Redirect ke halaman login
    return render_template('register.html', form=form)


@app.route("/set_nickname", methods=['GET', 'POST'])
def set_nickname():
    form = SetNicknameForm()

    # Ambil token dari session
    access_token = session.get('access_token')
    if not access_token:
        flash('Kamu belum login, silakan login dulu.', 'error')
        return redirect(url_for('login_apk'))

    try:
        # Decode token untuk mendapatkan identitas pengguna
        identity = decode_token(access_token)['sub']
        email = identity.get('email')
    except Exception as e:
        flash('Token tidak valid atau sudah kedaluwarsa.', 'error')
        return redirect(url_for('login_apk'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('login_apk'))

    if request.method == 'POST' and form.validate_on_submit():
        # Cek apakah nickname sudah digunakan
        existing_nickname = User.query.filter_by(
            nickname=form.nickname.data).first()
        if existing_nickname:
            flash('Nickname sudah digunakan, silakan pilih yang lain.',
                  'danger')
            return redirect(url_for('set_nickname'))

        # Simpan nickname baru
        user.nickname = form.nickname.data
        db.session.commit()

        flash('Nickname berhasil disimpan!', 'success')
        return redirect(url_for('homepage'))

    return render_template('set_nickname.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        new_password = request.form.get('new_password')

        # Mengupdate password di database dengan hashing
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = generate_password_hash(
                new_password)  # Hash password baru
            user.password = hashed_password
            db.session.commit()
            flash('Kata sandi Anda telah berhasil diatur ulang!', 'success')
            return redirect(url_for('login_apk'))
        else:
            flash('Email tidak ditemukan!', 'danger')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html', email=email)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(
            email=email).first()  # Menggunakan model User untuk mencari email
        if user:
            otp = send_otp(email)  # Mengirim OTP
            flash(
                'OTP telah dikirim ke email Anda. Silakan periksa email Anda.',
                'success')
            return redirect(url_for('verify_otp', email=email, otp=otp))
        else:
            flash('Email tidak ditemukan dalam data kami.', 'danger')
    return render_template('forgot_password.html')


@app.route('/verify_otp/<email>/<otp>', methods=['GET', 'POST'])
def verify_otp(email, otp):
    if request.method == 'POST':
        # Menggabungkan nilai dari semua input OTP
        entered_otp = ''.join([
            request.form.get(f'otp{i}') for i in range(1, 7)
        ])  # Mengambil dari otp1 hingga otp6
        print(f"Entered OTP: {entered_otp}"
              )  # Debugging untuk melihat OTP yang dimasukkan

        # Bandingkan OTP yang dimasukkan dengan OTP yang diharapkan
        if entered_otp == otp:
            flash('OTP berhasil diverifikasi!', 'success')
            return redirect(url_for('reset_password', email=email))
            # Tambahkan logika untuk melanjutkan proses setelah verifikasi berhasil
        else:
            flash('OTP yang dimasukkan tidak valid.', 'error')

    return render_template('verify_otp.html', email=email, otp=otp)


def get_tanggalan_data():
    import datetime
    current_year = datetime.datetime.now().year

    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    driver = webdriver.Chrome(options=options)
    driver.get("https://tanggalan.com/")
    time.sleep(3)
    page_text = driver.find_element("tag name", "body").text
    driver.quit()

    bulan_list = [
        'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli',
        'Agustus', 'September', 'Oktober', 'November', 'Desember'
    ]

    data = []
    current_bulan = ""

    for line in page_text.split('\n'):
        line = line.strip()
        if any(bulan.lower() in line.lower()
               for bulan in bulan_list) and str(current_year) in line:
            for b in bulan_list:
                if b.lower() in line.lower():
                    current_bulan = b
                    break
        else:
            match = re.match(r'^(\d{1,2})\s*(.+)', line)
            if match and current_bulan:
                tanggal = match.group(1)
                peringatan = match.group(2).strip()
                if not peringatan.isdigit():
                    bulan_numerik = str(bulan_list.index(current_bulan) +
                                        1).zfill(2)
                    tanggal_format = f"{tanggal.zfill(2)}-{bulan_numerik}"
                    data.append({
                        "Tanggal": tanggal_format,
                        "Peringatan": peringatan
                    })

    return data


# Fungsi scraping dari Wikipedia
def get_wikipedia_data():
    url = "https://id.wikipedia.org/wiki/Daftar_hari_penting_di_Indonesia"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")

    bulan_valid = [
        "Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli",
        "Agustus", "September", "Oktober", "November", "Desember"
    ]

    hari_penting = []
    pattern = re.compile(r"(\d{1,2})\s+(\w+)\s*(.*)")
    lists = soup.find_all(["ul", "ol"])

    for lst in lists:
        for li in lst.find_all("li"):
            text = li.get_text().strip()
            match = pattern.match(text)
            if match:
                tanggal = match.group(1)
                bulan = match.group(2)
                peringatan = match.group(3).strip()
                if bulan in bulan_valid and not re.search(
                        r"\d{4}", peringatan):
                    bulan_numerik = str(bulan_valid.index(bulan) + 1).zfill(2)
                    tanggal_format = f"{tanggal.zfill(2)}-{bulan_numerik}"
                    hari_penting.append({
                        "Tanggal": tanggal_format,
                        "Peringatan": peringatan
                    })

    return hari_penting


def save_to_database(data):
    for item in data:
        # Hapus data lama berdasarkan tanggal dan nama peringatan
        db.session.query(HariPenting).filter_by(
            tanggal=item['Tanggal'], nama=item['Peringatan']).delete()

        # Tambahkan data baru
        new_item = HariPenting(tanggal=item['Tanggal'],
                               nama=item['Peringatan'])
        db.session.add(new_item)

    db.session.commit()


@app.route("/")
def home():
    tanggalan_data = get_tanggalan_data()
    wikipedia_data = get_wikipedia_data()

    combined = []
    for tgl, info in tanggalan_data:
        combined.append({"Tanggal": tgl, "Peringatan": info})
    for item in wikipedia_data:
        combined.append({
            "Tanggal": item['Tanggal'],
            "Peringatan": item['Peringatan']
        })

    # Simpan data terbaru ke dalam database
    save_to_database(combined)

    return render_template('home.html')


@app.route('/setting')
def setting():
    # Ambil token dari session
    token = session.get('access_token')
    if not token:
        flash('Akses tidak sah. Silakan login ulang.', 'danger')
        return redirect(url_for('login_apk'))

    try:
        # Decode token untuk ambil user_id
        identity = decode_token(token)['sub']
        user_id = identity['user_id']

        user = User.query.get(user_id)
        if not user:
            flash('Pengguna tidak ditemukan.', 'danger')
            return redirect(url_for('homepage'))

        return render_template('setting.html', user=user)

    except Exception as e:
        print("Error saat decode token:", str(e))
        flash('Token tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('login_apk'))


@app.route('/delete_account1', methods=['POST'])
def delete_account1():
    token = session.get('access_token')
    if not token:
        flash('Anda harus login untuk menghapus akun.', 'error')
        return redirect(url_for('login_apk'))

    try:
        # Decode token untuk mendapatkan user_id
        identity = decode_token(token)['sub']
        user_id = identity['user_id']

        # Cari user berdasarkan ID
        user = User.query.get(user_id)
        if not user:
            flash('Akun tidak ditemukan.', 'error')
            return redirect(url_for('edit_profile'))

        # Hapus skor terkait user
        UserQuizScore.query.filter_by(user_id=user_id).delete()

        # Hapus user dari tabel
        db.session.delete(user)
        db.session.commit()

        # Hapus token dari session
        session.pop('access_token', None)

        flash('Akun Anda beserta data terkait telah berhasil dihapus.',
              'success')
        return redirect(url_for('login_apk'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saat menghapus akun: {e}")
        flash('Terjadi kesalahan saat menghapus akun. Silakan coba lagi.',
              'error')
        return redirect(url_for('edit_profile'))


# Tentukan folder tempat menyimpan gambar profil
app.config['UPLOAD_FOLDER'] = 'static/uploads'


# Fungsi untuk memeriksa ekstensi file yang diizinkan
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit(
        '.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    token = session.get('access_token')
    if not token:
        flash('Anda harus login terlebih dahulu.', 'danger')
        return redirect(url_for('login_apk'))

    try:
        identity = decode_token(token)['sub']
        user_id = identity['user_id']
    except Exception as e:
        flash('Token tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('login_apk'))

    user = User.query.get(user_id)
    if not user:
        flash('Pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('homepage'))

    if request.method == 'POST':
        fullname = request.form['fullname']
        nickname = request.form['nickname']
        email = request.form['email']
        gender = request.form['gender']

        # Validasi email
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Email tidak valid.', 'danger')
            return redirect(url_for('edit_profile'))

        # Cek nickname sudah dipakai orang lain belum
        existing_nickname_user = User.query.filter(
            User.nickname == nickname, User.user_id != user.user_id).first()

        if existing_nickname_user:
            flash('Nickname sudah digunakan, silakan coba yang lain.',
                  'danger')
            return redirect(url_for('edit_profile'))

        # Upload gambar profil
        profile_image = request.files.get('profile_image')
        if profile_image and allowed_file(profile_image.filename):
            # Hapus gambar lama kalau ada
            if user.profile_picture:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                             user.profile_picture)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            # Simpan file baru
            filename = f"{uuid.uuid4().hex}{os.path.splitext(secure_filename(profile_image.filename))[1]}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            try:
                profile_image.save(filepath)
                user.profile_picture = filename
            except Exception as e:
                flash('Gagal menyimpan file gambar.', 'danger')
                return redirect(url_for('edit_profile'))

        # Update user info
        user.fullname = fullname
        user.nickname = nickname
        user.email = email
        user.gender = gender

        try:
            db.session.commit()
            flash('Profil berhasil diperbarui.', 'success')
            return redirect(url_for('setting'))
        except Exception as e:
            flash('Gagal memperbarui profil. Silakan coba lagi.', 'danger')
            return redirect(url_for('edit_profile'))

    return render_template('setting.html', user=user)


@app.route('/change-password', methods=['POST'])
def change_password():
    token = session.get('access_token')  # Ambil token dari sesi
    if not token:
        flash('Anda harus login terlebih dahulu', 'danger')
        return redirect(url_for('login_apk'))

    try:
        identity = decode_token(token)['sub']
        user_id = identity['user_id']
    except Exception as e:
        flash('Token tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('login_apk'))

    user = User.query.get(user_id)  # Ambil user berdasarkan user_id dari token

    old_password = request.form['old-password']
    new_password = request.form['new-password']
    confirm_password = request.form['confirm-password']

    # Cek apakah password lama cocok dengan hashing
    if not check_passentimentsword_hash(user.password, old_password):
        flash('Password lama tidak cocok', 'danger')
        return redirect(url_for('edit_profile'))

    # Cek apakah password baru dan konfirmasi cocok
    if new_password != confirm_password:
        flash('Password baru dan konfirmasi tidak cocok', 'danger')
        return redirect(url_for('edit_profile'))

    # Ubah password dengan hashing
    hashed_password = generate_password_hash(new_password)
    user.password = hashed_password
    db.session.commit()

    flash('Password berhasil diubah', 'success')
    return redirect(url_for('edit_profile'))


from flask import jsonify


@app.route("/google_login")
def google_login():
    try:
        # Jika belum terotorisasi, arahkan ke Google login
        if not google.authorized:
            print("Belum authorized, redirect ke google.login")
            return redirect(url_for('google.login'))

        token = google.token
        print("Token yang diterima:", token)

        # Jika token kadaluarsa atau tidak valid
        if not token or token.get("expires_in", 0) < 0:
            print(
                "Token kadaluarsa atau tidak valid. Redirect ke login ulang.")
            return redirect(url_for('google.login'))

        # Ambil data pengguna dari Google
        resp = google.get("/oauth2/v2/userinfo")
        if not resp.ok:
            print("Error respons Google:", resp.content)
            flash("Gagal mengambil info pengguna dari Google.", "danger")
            return redirect(url_for('login_apk'))

        # Ambil data user
        user_info = resp.json()
        print(f"Data dari Google: {user_info}")

        email = user_info.get("email")
        fullname = user_info.get("name", email)
        profile_picture_url = user_info.get("picture")

        # Cek apakah user sudah ada di DB
        user = User.query.filter_by(email=email).first()
        print(f"Mencari pengguna dengan email: {email}")

        if user is None:
            print("Pengguna tidak ditemukan, membuat akun baru...")
            hashed_password = generate_password_hash("default_password")

            profile_picture_name = None
            if profile_picture_url:
                try:
                    response = requests.get(profile_picture_url, stream=True)
                    if response.status_code == 200:
                        folder = os.path.join('static', 'uploads')
                        os.makedirs(folder, exist_ok=True)

                        profile_picture_name = f"{email.replace('@', '_').replace('.', '_')}.jpg"
                        file_path = os.path.join(folder, profile_picture_name)

                        with open(file_path, 'wb') as f:
                            for chunk in response.iter_content(1024):
                                f.write(chunk)
                        print(f"Foto profil disimpan di: {file_path}")
                    else:
                        print("Gagal mengunduh foto profil.")
                except Exception as e:
                    print("Error menyimpan foto profil:", e)

            user = User(fullname=fullname,
                        email=email,
                        password=hashed_password,
                        gender="Laki-laki",
                        role="user",
                        profile_picture=profile_picture_name,
                        nickname=None)

            try:
                db.session.add(user)
                db.session.commit()
                print("Pengguna baru berhasil dibuat.")
            except Exception as e:
                print("Gagal menyimpan pengguna:", e)
                flash("Gagal mendaftar pengguna baru.", "danger")
                return redirect(url_for('login_apk'))

        # Login pengguna
        login_user(user)
        print(f"Pengguna yang login: {user}")

        # Buat JWT token
        access_token = create_access_token(identity={
            'user_id': user.user_id,
            'email': user.email,
            'nickname': user.nickname,
            'role': user.role
        },
                                           expires_delta=timedelta(hours=24))

        session['access_token'] = access_token
        print(f"Token JWT disimpan di session: {access_token}")

        # Redirect berdasarkan role
        if user.role == 'admin':
            print("Pengguna admin, redirect ke admin_menu.")
            return redirect(url_for('admin_menu'))

        if user.nickname is None:
            print("Pengguna belum punya nickname, redirect ke set_nickname.")
            return redirect(url_for('set_nickname'))

        print("Redirect ke homepage.")
        return redirect(url_for('homepage'))

    except Exception as e:
        print("Kesalahan terjadi:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/logout')
def logout():
    # Hapus token dari sesi
    session.pop('access_token', None)  # Menghapus token akses

    flash('Anda telah berhasil logout.', 'success')
    return redirect(url_for('login_apk'))


@app.route('/detail_tokoh/<int:id>', methods=['GET'])
def detail_tokoh(id):
    # Ambil data tokoh berdasarkan ID
    tokoh = Tokoh.query.get_or_404(id)

    # Ambil timeline yang terkait dengan tokoh tersebut
    timeline = Timeline.query.filter_by(tokoh_id=id).all()

    # Ambil media terkait dari setiap timeline
    timeline_with_media = []
    for t in timeline:
        media = TimelineMedia.query.filter_by(
            timeline_id=t.timeline_id).order_by(
                TimelineMedia.nomor_urut).all()
        media_data = [m.to_dict(base_url=request.host_url)
                      for m in media]  # Konversi ke dictionary
        timeline_with_media.append({
            "timeline": t,  # Timeline tetap sebagai objek
            "media": media_data  # Media sudah berupa dictionary
        })

    # Kirim data tokoh, timeline, dan media ke template
    return render_template('detail_tokoh.html',
                           tokoh=tokoh,
                           timeline_with_media=timeline_with_media,
                           timeline=timeline)


@app.route('/feedback')
def feedback():
    # Mengambil semua review dari database
    reviews = Review.query.all()
    return render_template('feedback.html')


@app.route('/sentimen')
def sentimen():
    try:
        # Mengambil semua review dari database
        reviews = Review.query.all()

        # Inisialisasi list untuk hasil analisis sentimen
        sentiment_results = []

        for review in reviews:
            # Prediksi sentimen menggunakan analyzer_indobert
            predicted_class, probabilities = analyzer_indobert.predict_sentiment(
                review.text)
            sentiment = "Positif" if predicted_class == 1 else "Negatif"

            # Tambahkan hasil ke dalam list
            sentiment_results.append({
                "text": review.text,
                "sentiment": sentiment
            })

        # Debugging untuk memastikan data yang dikirim
        print(sentiment_results)  # Cek output di terminal/server log

        # Pastikan data yang dikirimkan ke template
        return render_template('admin_dashboard.html',
                               sentiment_results=sentiment_results)

    except Exception as e:
        app.logger.error(f"Error saat memproses sentimen: {str(e)}")
        return render_template(
            'admin_dashboard.html',
            error="Terjadi kesalahan saat memuat data sentimen.")


@app.route('/add_review', methods=['POST'])
def add_review():
    try:
        # Ambil data JSON yang dikirim
        data = request.get_json()
        review_text = data.get('text')

        # Pastikan ulasan ada
        if not review_text:
            app.logger.debug("Tidak ada teks ulasan.")
            return jsonify({"message": "Tidak ada teks ulasan."}), 400

        # Simpan ulasan ke dalam database
        new_review = Review(text=review_text)
        db.session.add(new_review)
        db.session.commit()  # Pastikan commit berhasil
        app.logger.debug(f"Ulasan berhasil disimpan: {review_text}")

        return jsonify({"message": "Ulasan berhasil dikirim!"}), 201

    except Exception as e:
        db.session.rollback()  # Rollback jika terjadi error
        app.logger.error(f"Terjadi kesalahan: {str(e)}")
        return jsonify({"message": f"Terjadi kesalahan: {str(e)}"}), 500


# Token Hugging Face
HF_TOKEN = os.getenv("HF_TOKEN")  # Ganti dengan token Anda
login(token=HF_TOKEN)

# Model dan Tokenizer
MODEL_NAME = "danzrp28/fine-tuned-jetokin-model-v10"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)


# Optimized get_chatbot_response
def get_chatbot_response(messages):
    try:
        # Terapkan format chat ke tokenizer
        prompt = tokenizer.apply_chat_template(messages,
                                               tokenize=False,
                                               add_generation_prompt=True)

        # Batasi panjang prompt (contoh: 512 token maksimum)
        max_prompt_length = 512
        if len(prompt) > max_prompt_length:
            prompt = prompt[-max_prompt_length:]  # Ambil bagian akhir prompt

        # Tokenisasi input
        inputs = tokenizer(prompt,
                           return_tensors='pt',
                           padding=True,
                           truncation=True,
                           max_length=max_prompt_length)

        # Pastikan input ada di perangkat model
        inputs = {key: value.to(model.device) for key, value in inputs.items()}

        # Lakukan inferensi dengan pengurangan max_new_tokens
        outputs = model.generate(
            **inputs,
            max_new_tokens=500,  # Batasi jumlah token baru
            num_return_sequences=1)

        # Decode hasilnya
        response_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Bersihkan respons
        if "model" in response_text:
            generated_answer = response_text.split("model", 1)[-1].strip()
        else:
            generated_answer = response_text.strip()

        return generated_answer
    except Exception as e:
        print(f"Error in get_chatbot_response: {e}")
        return "Maaf, terjadi kesalahan saat memproses permintaan Anda."


@app.route('/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.get_json()
        user_message = data.get('message', '')

        if not user_message:
            return jsonify(response="Pesan tidak boleh kosong."), 400

        # Format pesan pengguna
        messages = [{"role": "user", "content": user_message}]

        # Ambil respons dari model
        bot_response = get_chatbot_response(messages)

        return jsonify(response=bot_response), 200
    except Exception as e:
        return jsonify(response="Maaf, terjadi kesalahan."), 500


UPLOAD_FOLDER_PAHLAWAN = os.path.join('static', 'images', 'Pahlawan')
app.config['UPLOAD_FOLDER_PAHLAWAN'] = UPLOAD_FOLDER_PAHLAWAN


@app.route('/add_tokoh', methods=['POST'])
def add_tokoh():
    if request.method == 'POST':
        try:
            # Ambil data dari form
            name = request.form['name']
            ascencion_document_number = request.form.get(
                'ascencion_document_number')
            ascencion_document_date = request.form.get(
                'ascencion_document_date')
            ascencion_year = request.form.get('ascencion_year')
            zaman_perjuangan = request.form['zaman_perjuangan']
            bidang_perjuangan = request.form['bidang_perjuangan']
            birth_date = request.form.get('birth_date')
            birth_place = request.form.get('birth_place')
            death_date = request.form.get('death_date')
            death_place = request.form.get('death_place')
            burial_place = request.form.get('burial_place')
            description = request.form['description']
            peran_utama = request.form.get('peran_utama')

            # Ambil foto yang di-upload
            photo = request.files['photo']

            # Log data untuk debugging
            app.logger.info(f"Received data: {name}, {photo.filename}")

            # Simpan data tokoh ke database
            new_tokoh = Tokoh(
                name=name,
                ascencion_document_number=ascencion_document_number,
                ascencion_document_date=ascencion_document_date,
                ascencion_year=ascencion_year,
                zaman_perjuangan=zaman_perjuangan,
                bidang_perjuangan=bidang_perjuangan,
                birth_date=birth_date,
                birth_place=birth_place,
                death_date=death_date,
                death_place=death_place,
                burial_place=burial_place,
                description=description,
                peran_utama=peran_utama)

            # Jika foto di-upload, simpan foto di folder yang sudah ditentukan
            if photo and allowed_file(photo.filename):
                filename = secure_filename(photo.filename)
                # Simpan file foto ke folder yang telah ditentukan
                photo_path = os.path.join(app.config['UPLOAD_FOLDER_PAHLAWAN'],
                                          filename)
                photo.save(photo_path)

                # Menyimpan URL foto ke dalam database
                photo_url = {filename}
                new_tokoh.photo_url = photo_url

            # Simpan objek Tokoh ke database
            db.session.add(new_tokoh)
            db.session.commit()

            app.logger.info(f"Data {name} berhasil disimpan ke database.")

            # Redirect ke halaman admin_dashboard setelah berhasil
            return redirect(url_for('admin_menu', show_tokoh_content=True))

        except Exception as e:
            app.logger.error(f"Error saat memproses data: {str(e)}")
            return render_template(
                'admin.html', error="Terjadi kesalahan saat menyimpan data.")


# Hapus Data Tokoh
@app.route('/delete_tokoh/<int:id>', methods=['GET', 'POST'])
def delete_tokoh(id):
    try:
        # Cari tokoh berdasarkan ID
        tokoh = Tokoh.query.filter_by(id=id).first()

        # Jika tokoh tidak ditemukan
        if tokoh is None:
            app.logger.error(f"Tokoh dengan ID {id} tidak ditemukan.")
            return redirect(
                url_for('data_tokoh', error="Tokoh tidak ditemukan"))

        # Hapus tokoh dari database
        db.session.delete(tokoh)
        db.session.commit()

        app.logger.info(f"Tokoh {tokoh.name} berhasil dihapus.")

        # Redirect ke halaman daftar tokoh setelah penghapusan
        return redirect(url_for('admin_menu', show_tokoh_content=True))

    except Exception as e:
        app.logger.error(
            f"Error saat menghapus tokoh dengan ID {id}: {str(e)}")
        return redirect(
            url_for('data_tokoh',
                    error="Terjadi kesalahan saat menghapus tokoh"))


@app.route('/add_timeline', methods=['GET', 'POST'])
def add_timeline():
    if request.method == 'POST':
        nama_timeline = request.form['nama_timeline']
        nomor_urut = request.form['nomor_urut']
        deskripsi = request.form['deskripsi']
        tokoh_id = request.form['tokoh_id']

        new_timeline = Timeline(nama_timeline=nama_timeline,
                                nomor_urut=nomor_urut,
                                deskripsi=deskripsi,
                                tokoh_id=tokoh_id)
        db.session.add(new_timeline)
        db.session.commit()
        return redirect(url_for('admin_menu'))

    tokoh_list = Tokoh.query.all()
    if not tokoh_list:
        print("Data Tokoh kosong.")
    else:
        print("Data Tokoh:", tokoh_list)

    return render_template('admin.html', tokoh_list=tokoh_list)


@app.route('/delete_timeline/<int:timeline_id>', methods=['POST'])
def delete_timeline(timeline_id):
    timeline = Timeline.query.get_or_404(timeline_id)
    db.session.delete(timeline)
    db.session.commit()
    return redirect(url_for('admin_menu'))


@app.route('/add_quiz', methods=['GET', 'POST'])
def add_quiz():
    if request.method == 'POST':
        tokoh_id = request.form['tokoh_id']
        question = request.form['question']
        correct_answer = request.form['correct_answer']
        option_1 = request.form['option_1']
        option_2 = request.form['option_2']
        option_3 = request.form['option_3']
        difficulty = request.form['difficulty']
        points = int(request.form['points'])

        new_quiz = Quiz(tokoh_id=tokoh_id,
                        question=question,
                        correct_answer=correct_answer,
                        option_1=option_1,
                        option_2=option_2,
                        option_3=option_3,
                        difficulty=difficulty,
                        points=points)

        db.session.add(new_quiz)
        db.session.commit()

        return redirect(url_for(
            'admin_menu'))  # Redirect ke menu admin setelah menambahkan quiz

    # Ambil daftar tokoh untuk dropdown
    tokoh_list = Tokoh.query.all()
    return render_template('admin.html', tokoh_list=tokoh_list)


@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)  # Mengambil quiz berdasarkan quiz_id
    db.session.delete(quiz)  # Menghapus quiz dari database
    db.session.commit()  # Menyimpan perubahan ke database
    return redirect(url_for('admin_menu'))  # Mengarahkan kembali ke menu admin


@app.route('/add_song', methods=['POST'])
def add_song():
    try:
        title = request.form.get('title')
        song_type = request.form.get('type')  # 'nasional' atau 'daerah'
        artist = request.form.get('artist')  # opsional
        release_year = request.form.get('release_year')
        language = request.form.get('language')
        duration_str = request.form.get('duration')  # format mm:ss
        lyrics = request.form.get('lyrics')

        audio_file = request.files.get('audio_url')
        cover_file = request.files.get('cover_url')

        # Validasi minimal
        if not title or not song_type or not audio_file:
            flash("Judul, tipe lagu, dan file audio harus diisi.", "error")
            return redirect(url_for('admin_menu'))

        if song_type not in ['nasional', 'daerah']:
            flash("Tipe lagu harus 'nasional' atau 'daerah'.", "error")
            return redirect(url_for('admin_menu'))

        # Parsing duration mm:ss ke detik (int)
        duration_seconds = None
        if duration_str:
            try:
                m, s = duration_str.split(':')
                duration_seconds = int(m) * 60 + int(s)
            except:
                flash("Format durasi harus mm:ss.", "error")
                return redirect(url_for('admin_menu'))

        # Buat folder audio & cover berdasarkan tipe lagu
        folder_audio = os.path.join(app.static_folder, 'LAGU',
                                    song_type.capitalize(), 'audio')
        folder_cover = os.path.join(app.static_folder, 'LAGU',
                                    song_type.capitalize(), 'cover')
        os.makedirs(folder_audio, exist_ok=True)
        os.makedirs(folder_cover, exist_ok=True)

        # Simpan file audio
        audio_filename = secure_filename(audio_file.filename)
        audio_path = os.path.join(folder_audio, audio_filename)
        audio_file.save(audio_path)

        # Simpan file cover jika ada
        cover_filename = None
        if cover_file and cover_file.filename != '':
            cover_filename = secure_filename(cover_file.filename)
            cover_path = os.path.join(folder_cover, cover_filename)
            cover_file.save(cover_path)

        # Simpan ke database (contoh model Song)
        new_song = Song(
            title=title,
            type=song_type,
            release_year=int(release_year) if release_year else None,
            language=language,
            duration=duration_seconds,
            lyrics=lyrics,
            audio_url=audio_filename,
            cover_url=cover_filename)
        db.session.add(new_song)
        db.session.commit()

        flash("Lagu berhasil ditambahkan!", "success")
        return redirect(url_for('admin_menu'))

    except Exception as e:
        app.logger.error(f"Error saat menambahkan lagu: {str(e)}")
        flash("Terjadi kesalahan saat menambahkan lagu.", "error")
        return redirect(url_for('admin_menu'))


@app.route('/delete_song/<int:song_id>', methods=['POST'])
def delete_song(song_id):
    try:
        song = Song.query.get(song_id)
        if not song:
            flash("Lagu tidak ditemukan.", "error")
            return redirect(url_for('admin_menu'))

        db.session.delete(song)
        db.session.commit()

        flash("Lagu berhasil dihapus!", "success")
        return redirect(url_for('admin_menu'))

    except Exception as e:
        app.logger.error(f"Error saat menghapus lagu: {str(e)}")
        flash("Terjadi kesalahan saat menghapus lagu.", "error")
        return redirect(url_for('admin_menu'))


@app.route('/add_media', methods=['POST'])
def add_media():
    timeline_id = request.form.get('timeline_id')
    nomor_urut = request.form.get('nomor_urut')
    media_type = request.form.get('media_type')
    description = request.form.get('description', '')
    media_file = request.files.get('media_file')

    if not media_file:
        flash('File media harus diunggah.', 'error')
        return redirect(url_for('admin_menu'))

    # Simpan file media ke folder statis
    filename = secure_filename(media_file.filename)
    file_path = os.path.join(
        'static/Media/images'
        if media_type == 'image' else 'static/Media/video', filename)
    media_file.save(file_path)

    # Simpan data ke database
    new_media = TimelineMedia(timeline_id=timeline_id,
                              nomor_urut=nomor_urut,
                              media_type=media_type,
                              media_url=filename,
                              description=description)
    db.session.add(new_media)
    db.session.commit()

    flash('Media berhasil ditambahkan.', 'success')
    return redirect(url_for('admin_menu'))


@app.route('/delete_media/<int:id>', methods=['GET'])
def delete_media(id):
    try:
        # Cari media berdasarkan ID
        media = TimelineMedia.query.get(id)

        if not media:
            flash('Media tidak ditemukan.', 'error')
            return redirect(url_for('admin_menu'))

        # Tentukan path file media
        media_folder = 'static/Media/images' if media.media_type == 'image' else 'static/Media/video'
        file_path = os.path.join(media_folder, media.media_url)

        # Hapus file jika ada
        if os.path.exists(file_path):
            os.remove(file_path)

        # Hapus data media dari database
        db.session.delete(media)
        db.session.commit()

        flash('Media berhasil dihapus.', 'success')
    except Exception as e:
        app.logger.error(f"Error saat menghapus media: {str(e)}")
        flash('Terjadi kesalahan saat menghapus media.', 'error')

    return redirect(url_for('admin_menu'))


@app.route('/add_hari_penting', methods=['POST'])
def add_hari_penting():
    nama = request.form['nama']
    tanggal = request.form['tanggal']
    new_hari_penting = HariPenting(nama=nama, tanggal=tanggal)
    db.session.add(new_hari_penting)
    db.session.commit()
    return redirect(url_for('admin_menu'))


@app.route('/delete_hari_penting/<int:id>', methods=['GET'])
def delete_hari_penting(id):
    hari_penting = HariPenting.query.get(id)
    if hari_penting:
        db.session.delete(hari_penting)
        db.session.commit()
    return redirect(url_for('admin_menu'))


@app.route('/add_badword', methods=['POST'])
def add_badword():
    word = request.form['word']
    if word:
        new_badword = BadWord(word=word)
        db.session.add(new_badword)
        db.session.commit()
        flash('BadWord berhasil ditambahkan!', 'success')
    return redirect(url_for('admin_menu'))


@app.route('/delete_badword/<int:id>', methods=['GET'])
def delete_badword(id):
    badword = BadWord.query.get_or_404(id)
    db.session.delete(badword)
    db.session.commit()
    flash('BadWord berhasil dihapus!', 'success')
    return redirect(url_for('admin_menu'))


model_huggingface = "danzrp28/sentimentanalisis"


@app.route('/admin_dashboard', methods=['GET'])
def admin_menu():
    try:
        # Inisialisasi analyzer_indobert dengan path model yang benar
        analyzer_indobert = SentimentAnalyzer(model_path=model_huggingface)

        # Mengambil total user dan total tokoh
        total_users = User.query.count()
        total_tokoh = Tokoh.query.count()

        # Mendapatkan nilai pencarian nama tokoh dari URL parameter
        search_tokoh = request.args.get('search_tokoh', '')

        # Mengambil semua data tokoh
        if search_tokoh:
            tokoh = Tokoh.query.filter(
                Tokoh.name.ilike(f'%{search_tokoh}%')).all()
        else:
            tokoh = Tokoh.query.all()

        # Mengambil data timeline yang diurutkan berdasarkan nama tokoh dan nomor urut
        if search_tokoh:
            timelines = db.session.query(Timeline).join(Tokoh).filter(
                Tokoh.name.ilike(f'%{search_tokoh}%')).order_by(
                    Tokoh.name, Timeline.nomor_urut).all()
        else:
            timelines = db.session.query(Timeline).join(Tokoh).order_by(
                Tokoh.name, Timeline.nomor_urut).all()

        # Mengambil semua review untuk analisis sentimen
        reviews = Review.query.all()

        # Proses analisis sentimen
        sentiment_results = []
        for review in reviews:
            try:
                predicted_class, probabilities = analyzer_indobert.predict_sentiment(
                    review.text)
                sentiment = "Positif" if predicted_class == 1 else "Negatif"
                sentiment_results.append({
                    "text": review.text,
                    "sentiment": sentiment
                })
            except Exception as e:
                app.logger.error(
                    f"Error saat menganalisis sentimen untuk review: {review.text}. Error: {str(e)}"
                )
                sentiment_results.append({
                    "text":
                    review.text,
                    "sentiment":
                    f"Tidak dapat dianalisis: {str(e)}"
                })

        # Memastikan quiz_list tidak kosong atau None
        quiz_list = Quiz.query.all(
        )  # Mengambil semua quiz yang ada dalam database
        # Mengambil tokoh berdasarkan ID jika tersedia (pastikan ID diambil dari URL)
        tokoh_id = Tokoh.query.get(request.args.get('id'))

        search_media = request.args.get('search_media', '')

        # Memastikan pencarian hanya mencari berdasarkan deskripsi media
        if search_media:
            media = TimelineMedia.query.filter(
                TimelineMedia.description.contains(search_media)).all()
        else:
            media = TimelineMedia.query.all()

        # Pencarian untuk badword
        search_badword = request.args.get('search_badword', '')

        # Mengambil data badword berdasarkan pencarian
        if search_badword:
            badwords = BadWord.query.filter(
                BadWord.word.ilike(f'%{search_badword}%')).all()
        else:
            badwords = BadWord.query.all()

        # Lagu daerah
        search_lagu_daerah = request.args.get('search_song', '')
        if search_lagu_daerah:
            lagu_daerah = Song.query.filter(
                Song.type == 'daerah',
                Song.title.ilike(f'%{search_lagu_daerah}%')).all()
        else:
            lagu_daerah = Song.query.filter_by(type='daerah').all()

        # Ambil parameter pencarian lagu nasional dari form
        search_lagu_nasional = request.args.get(
            'search_song', '')  # samakan dengan form input name="search_song"

        # Query lagu nasional sesuai pencarian
        if search_lagu_nasional:
            lagu_nasional = Song.query.filter(
                Song.type == 'nasional',
                Song.title.ilike(f'%{search_lagu_nasional}%')).all()
        else:
            lagu_nasional = Song.query.filter_by(type='nasional').all()

        # Kirim ke template dengan key 'songs' supaya sesuai di template
        return render_template('admin.html',
                               total_users=total_users,
                               total_tokoh=total_tokoh,
                               tokoh=tokoh,
                               timelines=timelines,
                               sentiment_results=sentiment_results,
                               quiz_list=quiz_list,
                               t=tokoh_id,
                               media=media,
                               badwords=badwords,
                               lagu_daerah=lagu_daerah,
                               songs=lagu_nasional)

    except Exception as e:
        app.logger.error(f"Error saat memproses dashboard: {str(e)}")
        return render_template(
            'admin.html', error="Terjadi kesalahan saat memuat dashboard.")


@app.route('/quiz')
def quiz():
    # Ambil nickname dari sesi JWT jika ada
    token = session.get('access_token')
    if token:
        try:
            # Decode token untuk mendapatkan identity
            identity = decode_token(token)['sub']
            nickname = identity['nickname']
        except Exception as e:
            print(f"Error decoding token: {e}")
            nickname = 'Guest'
    else:
        nickname = 'Guest'

    return render_template('quiz.html', nickname=nickname)


@app.route('/start', methods=['GET', 'POST'])
def start_quiz():
    # Ambil token dari sesi untuk mendapatkan user_id
    token = session.get('access_token')
    if not token:
        return redirect(
            url_for('login_apk'))  # Pastikan user sudah login dengan token

    try:
        # Decode token untuk mendapatkan identity dan user_id
        identity = decode_token(token)['sub']
        user_id = identity['user_id']
    except Exception as e:
        print(f"Error decoding token: {e}")
        return redirect(
            url_for('login_apk'))  # Jika token tidak valid atau error decoding

    # Fetch questions by difficulty
    easy_questions = Quiz.query.filter_by(difficulty='easy').all()
    medium_questions = Quiz.query.filter_by(difficulty='medium').all()
    hard_questions = Quiz.query.filter_by(difficulty='hard').all()

    # Select and shuffle questions
    selected_questions = random.sample(easy_questions, min(len(easy_questions), 5)) + \
                         random.sample(medium_questions, min(len(medium_questions), 3)) + \
                         random.sample(hard_questions, min(len(hard_questions), 2))
    random.shuffle(selected_questions)

    for question in selected_questions:
        options = [
            question.correct_answer, question.option_1, question.option_2,
            question.option_3
        ]
        options = [opt for opt in options if opt]  # Remove empty options
        random.shuffle(options)
        question.randomized_options = options

    if request.method == 'POST':
        # Cek jika data dikirim dalam format JSON
        if request.is_json:
            data = request.get_json()
            correct_answers = data.get('correctAnswers', 0)
            total_points = data.get('totalPoints', 0)

            try:
                # Simpan skor ke database
                user_quiz_score = UserQuizScore(
                    user_id=user_id,
                    quiz_id=selected_questions[0].quiz_id,
                    score=total_points)
                db.session.add(user_quiz_score)
                db.session.commit()

                # Update leaderboard
                update_leaderboard(user_id)
                return jsonify({
                    "message": "Score saved successfully",
                    "totalPoints": total_points
                }), 200

            except Exception as e:
                db.session.rollback()
                print(f"Error saving score: {e}")
                return jsonify({"message": "Error saving score"}), 500

        # Jika bukan request JSON, proses secara normal
        return redirect(url_for('leaderboard'))

    return render_template('start_quiz.html',
                           questions=selected_questions,
                           user_id=user_id)


@app.route('/leaderboard')
def leaderboard_quiz():
    # Memastikan pengguna sudah login dengan token JWT
    token = session.get('access_token')
    if not token:
        return redirect(url_for('login_apk'))  # Pastikan pengguna sudah login

    try:
        # Decode token untuk mendapatkan identity
        identity = decode_token(token)['sub']
        user_id = identity['user_id']
    except Exception as e:
        print(f"Error decoding token: {e}")
        return redirect(
            url_for('login_apk'))  # Jika token tidak valid atau error decoding

    # Mendapatkan tanggal mulai dan akhir minggu ini
    today = datetime.today()
    week_start = today - timedelta(
        days=today.weekday())  # Start of the week (Monday)
    week_end = week_start + timedelta(days=7)  # End of the week (Sunday)

    # Ambil semua pengguna dengan role "user"
    users = User.query.filter_by(role="user").all()

    # Query untuk mendapatkan skor total pengguna berdasarkan minggu ini
    leaderboard_data = db.session.query(
        User.user_id, User.nickname, User.profile_picture,
        func.coalesce(func.sum(
            UserQuizScore.score), 0).label('total_score')).join(
                UserQuizScore,
                User.user_id == UserQuizScore.user_id,
                isouter=True  # Pastikan outer join
            ).filter(
                UserQuizScore.date_taken.between(
                    week_start,
                    week_end),  # Filter berdasarkan rentang minggu ini
                User.role ==
                "user"  # Filter hanya untuk pengguna dengan role "user"
            ).group_by(User.user_id).all()

    # Menyusun data leaderboard dengan menggabungkan data pengguna dan skor minggu ini
    leaderboard_dict = {
        user.user_id: {
            "nickname":
            user.nickname,
            "profile_picture_url":
            f"/static/uploads/{user.profile_picture}"
            if user.profile_picture else "/static/uploads/default.jpeg",
            "total_score":
            0
        }
        for user in users
    }

    # Update skor leaderboard dengan data yang ada
    for user_id, nickname, profile_picture, total_score in leaderboard_data:
        leaderboard_dict[user_id] = {
            "nickname":
            nickname,
            "profile_picture_url":
            f"/static/uploads/{profile_picture}"
            if profile_picture else "/static/uploads/default.jpeg",
            "total_score":
            total_score
        }

    # Urutkan leaderboard berdasarkan total_score
    sorted_leaderboard = sorted(leaderboard_dict.values(),
                                key=lambda x: x['total_score'],
                                reverse=True)

    # Menambahkan ranking ke setiap pengguna
    for rank, user in enumerate(sorted_leaderboard, start=1):
        user['ranking'] = rank

    # Pastikan leaderboard sudah diproses dengan benar
    print("Processed Leaderboard:", sorted_leaderboard)

    return render_template('leaderboard.html', leaderboard=sorted_leaderboard)


# Setup Face Mesh
mp_face_mesh = mp.solutions.face_mesh
face_mesh = mp_face_mesh.FaceMesh(static_image_mode=False,
                                  max_num_faces=1,
                                  refine_landmarks=True)

# Variabel untuk melacak quiz
cap = None
question_index = 0
answered = False
quiz_started = False
countdown_time = 5  # 5 detik countdown
countdown_start = None
feedback_message = ""
border_color = (0, 255, 0)


def draw_text_in_box(img,
                     text,
                     box_top_left,
                     box_bottom_right,
                     font_scale=0.5,
                     color=(0, 0, 0),
                     thickness=2):
    x1, y1 = box_top_left
    x2, y2 = box_bottom_right
    max_width = x2 - x1 - 20  # padding kiri kanan

    words = text.split(' ')
    lines = []
    current_line = ''

    for word in words:
        test_line = current_line + ' ' + word if current_line else word
        size = cv2.getTextSize(test_line, cv2.FONT_HERSHEY_SIMPLEX, font_scale,
                               thickness)[0]

        if size[0] <= max_width:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    line_height = cv2.getTextSize('Test', cv2.FONT_HERSHEY_SIMPLEX, font_scale,
                                  thickness)[0][1] + 10

    y = y1 + 25
    for line in lines:
        cv2.putText(img, line, (x1 + 10, y), cv2.FONT_HERSHEY_SIMPLEX,
                    font_scale, color, thickness)
        y += line_height


def draw_wrapped_text(frame,
                      text,
                      start_point,
                      box_color,
                      text_color,
                      max_width,
                      font_scale=0.5,
                      thickness=2,
                      padding=10):
    font = cv2.FONT_HERSHEY_SIMPLEX

    # Pisah teks jadi kata-kata
    words = text.split()
    lines = []
    current_line = ""

    for word in words:
        test_line = current_line + " " + word if current_line else word
        (test_width, _), _ = cv2.getTextSize(test_line, font, font_scale,
                                             thickness)
        if test_width <= max_width - 2 * padding:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)

    # Hitung ukuran box
    line_height = cv2.getTextSize("Test", font, font_scale,
                                  thickness)[0][1] + 5
    box_height = line_height * len(lines) + 2 * padding
    box_width = max_width

    # Gambar kotak
    x, y = start_point
    cv2.rectangle(frame, start_point, (x + box_width, y + box_height),
                  box_color, -1)
    cv2.rectangle(frame, start_point, (x + box_width, y + box_height),
                  (0, 0, 0), 2)

    # Tulis teks per baris
    y_offset = y + padding + line_height - 5
    for line in lines:
        cv2.putText(frame, line, (x + padding, y_offset), font, font_scale,
                    text_color, thickness)
        y_offset += line_height

    # Return box_end position kalau mau dipakai lagi
    return (x + box_width, y + box_height)


def get_questions_from_db():
    # Ambil 1 soal dengan difficulty 'hard'
    hard_questions = db.session.query(Quiz).filter_by(
        difficulty='hard').limit(1).all()

    # Ambil 2 soal dengan difficulty 'medium'
    medium_questions = db.session.query(Quiz).filter_by(
        difficulty='medium').limit(2).all()

    # Ambil 2 soal dengan difficulty 'easy'
    easy_questions = db.session.query(Quiz).filter_by(
        difficulty='easy').limit(2).all()

    # Gabungkan semua soal
    all_questions = hard_questions + medium_questions + easy_questions

    # Acak soal agar urutannya bervariasi
    random.shuffle(all_questions)

    return all_questions


# Tambahan: Flag untuk cek apakah skor sudah dikirim
score_sent = False


# Fungsi untuk menampilkan frame video
def generate_frames(server_url, user_fullname, user_id, token):
    global question_index, answered, quiz_started, countdown_start, total_score, feedback_message, border_color

    total_score = 0
    feedback_message = ""
    border_color = (0, 255, 0)

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Camera not accessible")
        return

    score_sent = False  # Reset flag

    while True:
        success, frame = cap.read()
        if not success:
            print("Failed to read frame from camera")
            break

        frame = cv2.flip(frame, 1)
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        results = face_mesh.process(rgb)

        h, w, _ = frame.shape

        # --- Menampilkan nama user ---
        cv2.putText(frame, f"User: {user_fullname}", (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)

        # --- Countdown sebelum mulai quiz ---
        if not quiz_started:
            if countdown_start is None:
                countdown_start = time.time()

            elapsed = time.time() - countdown_start
            remaining = int(countdown_time - elapsed)

            if remaining > 0:
                cv2.putText(frame, str(remaining), (w // 2 - 30, h // 2 + 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1.5, (0, 255, 0), 3)
            else:
                quiz_started = True

            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            continue

        # Head movement detection logic
        if results.multi_face_landmarks:
            for face_landmarks in results.multi_face_landmarks:
                left_ear = face_landmarks.landmark[234]
                right_ear = face_landmarks.landmark[454]

                y_left = left_ear.y
                y_right = right_ear.y
                diff_y = y_left - y_right

                posisi = "lurus"
                if diff_y > 0.1:
                    posisi = "kiri"
                elif diff_y < -0.1:
                    posisi = "kanan"

                if not answered and question_index < len(selected_questions):
                    chosen = ""
                    correct_answer = selected_questions[
                        question_index].correct_answer

                    if posisi == "kiri":
                        chosen = selected_questions[
                            question_index].randomized_options[0]
                    elif posisi == "kanan":
                        chosen = selected_questions[
                            question_index].randomized_options[1]

                    if chosen:
                        if chosen == correct_answer:
                            total_score += selected_questions[
                                question_index].points
                            feedback_message = "Benar!"
                            border_color = (0, 255, 0)
                        else:
                            feedback_message = "Salah!"
                            border_color = (0, 0, 255)

                        answered = True
                        print(f"Jawaban dipilih: {chosen}")
                        question_index += 1
                        time.sleep(0.5)
                        answered = False

        # Display question
        if question_index < len(selected_questions):
            q = selected_questions[question_index]
            if results.multi_face_landmarks:
                for face_landmarks in results.multi_face_landmarks:
                    forehead = face_landmarks.landmark[10]
                    forehead_x = int(forehead.x * w)
                    forehead_y = int(forehead.y * h)

                    top_left = (forehead_x - 175, forehead_y - 90)
                    bottom_right = (forehead_x + 175, forehead_y - 30)

                    cv2.rectangle(frame, top_left, bottom_right,
                                  (255, 255, 255), -1)
                    cv2.rectangle(frame, top_left, bottom_right, (0, 0, 0), 2)

                    draw_text_in_box(frame, q.question, top_left, bottom_right)

                    # Display options
                    draw_wrapped_text(frame, f" {q.randomized_options[0]}",
                                      (50, h - 150), (100, 100, 255),
                                      (255, 255, 255), 250)
                    draw_wrapped_text(frame, f" {q.randomized_options[1]}",
                                      (w - 300, h - 150), (0, 200, 0),
                                      (255, 255, 255), 250)

        else:
            # Quiz finished
            if results.multi_face_landmarks:
                for face_landmarks in results.multi_face_landmarks:
                    forehead = face_landmarks.landmark[10]
                    forehead_x = int(forehead.x * w)
                    forehead_y = int(forehead.y * h)

                    top_left = (forehead_x - 175, forehead_y - 90)
                    bottom_right = (forehead_x + 175, forehead_y - 30)

                    cv2.rectangle(frame, top_left, bottom_right,
                                  (255, 255, 255), -1)
                    cv2.rectangle(frame, top_left, bottom_right, (0, 255, 0),
                                  2)

                    text = f"Skor: {total_score}"
                    text_width, text_height = cv2.getTextSize(
                        text, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 2)[0]
                    text_x = top_left[0] + (350 - text_width) // 2
                    text_y = top_left[1] + (60 + text_height) // 2
                    cv2.putText(frame, text, (text_x, text_y),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 2)

                if not score_sent:
                    try:
                        # Kirim skor ke server sekali saja
                        payload = {
                            'total_score':
                            total_score,
                            'quiz_id':
                            selected_questions[0].quiz_id if hasattr(
                                selected_questions[0], 'quiz_id') else
                            1  # Atur ID quiz
                        }
                        # Tambahkan ini dulu:
                        if isinstance(token, bytes):
                            token = token.decode('utf-8')

                        headers = {
                            'Authorization': f'Bearer {token}',
                            'Content-Type': 'application/json'
                        }
                        response = requests.post(server_url,
                                                 json=payload,
                                                 headers=headers)

                        if response.status_code == 200:
                            print("Score saved successfully.")
                        elif response.status_code == 409:
                            # User sudah ngerjain hari ini
                            feedback_message = "Anda sudah mengerjakan hari ini!"
                            border_color = (0, 165, 255
                                            )  # Orange color untuk warning
                            print(f"Warning: {response.json().get('message')}")
                        else:
                            print(
                                f"Failed to save score. Status code: {response.status_code}, Response: {response.text}"
                            )

                        score_sent = True  # Jangan kirim 2x
                    except Exception as e:
                        print(f"Error sending score: {e}")

        if feedback_message:
            border_thickness = 10
            cv2.rectangle(frame, (0, 0), (w, h), border_color,
                          border_thickness)

        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


# Route untuk quiz
@app.route('/quickquiz')
def quickquiz():
    token = session.get('access_token')
    if not token:
        return redirect(
            url_for('login_apk'))  # Pastikan user sudah login dengan token

    try:
        # Decode token untuk mendapatkan identity dan user_id
        identity = decode_token(token)['sub']
        user_id = identity['user_id']
    except Exception as e:
        print(f"Error decoding token: {e}")
        return redirect(url_for('login_apk'))

    global cap, selected_questions  # Cek apakah user sudah mengerjakan quiz hari ini
    today = datetime.utcnow().date()  # Ambil hanya tanggal tanpa waktu

    # Cari entri dengan user_id dan tanggal yang sama
    existing_score = UserQuizScore.query.filter_by(user_id=user_id).filter(
        db.func.date(UserQuizScore.completed_at) == today).first()

    if existing_score:
        # Jika user sudah mengerjakan quiz hari ini, beri notifikasi dan redirect ke dashboard
        flash("Anda sudah mengerjakan quiz hari ini!", "warning")
        return redirect(
            url_for('quiz')
        )  # Redirect ke halaman dashboard quiz (atau halaman lain sesuai kebutuhan)

    # Ambil soal dari database
    all_questions = Quiz.query.all()

    # Pilih beberapa soal secara acak (misal 5 soal)
    selected_questions = random.sample(all_questions, 5)

    # Randomize opsi jawaban untuk tiap soal
    for question in selected_questions:
        options = [question.correct_answer, question.option_1]
        random.shuffle(options)
        question.randomized_options = options

    cap = cv2.VideoCapture(
        0
    )  # Menggunakan kamera pertama, ganti 0 menjadi 1 jika kamera default tidak terdeteksi

    # Render template dengan mengirimkan nickname dan soal yang sudah dipilih
    return render_template('quickquiz.html', questions=selected_questions)


@app.route('/save_score', methods=['POST'])
def save_score():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Authorization header missing'}), 400

    try:
        print(f"Authorization header received: {auth_header}")
        if not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Invalid authorization format'}), 400

        token = auth_header.split(" ")[1]
        decoded_token = decode_token(token)
        identity = decoded_token['sub']
        user_id = identity['user_id']

        data = request.get_json()
        print(f"Received data: {data}")

        total_score = data.get('total_score')
        quiz_id = data.get('quiz_id')

        if total_score is None or quiz_id is None:
            return jsonify({"message": "Missing total_score or quiz_id"}), 400

        # Cek apakah user sudah mengerjakan quiz hari ini
        today = datetime.utcnow().date()  # Ambil hanya tanggal tanpa waktu

        # Cari entri dengan user_id, quiz_id, dan tanggal yang sama
        existing_score = UserQuizScore.query.filter_by(
            user_id=user_id, quiz_id=quiz_id).filter(
                db.func.date(UserQuizScore.completed_at) == today).first()

        if existing_score:
            return jsonify(
                {"message": "Anda sudah mengerjakan quiz hari ini!"}), 409

        # Simpan skor hanya jika belum ada entri hari ini
        user_quiz_score = UserQuizScore(
            user_id=user_id,
            quiz_id=quiz_id,
            score=total_score,
            completed_at=datetime.utcnow()  # Simpan waktu lengkap saat ini
        )
        db.session.add(user_quiz_score)
        db.session.commit()

        update_leaderboard(user_id)

        return jsonify({"message": "Score saved successfully"}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"message": "Error saving score", "error": str(e)}), 500


@app.route('/video_feed')
def video_feed():
    if 'access_token' not in session:
        return redirect(url_for('login_apk'))

    # Ambil token dari sesi
    token = session.get('access_token')
    try:
        # Dekode token untuk mendapatkan identity pengguna
        decoded_token = decode_token(token)
        identity = decoded_token['sub']  # 'sub' berisi identity pengguna
        user_id = identity['user_id']  # Ambil user_id dari identity

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except Exception as e:
        return jsonify({
            "message": "Error decoding token",
            "error": str(e)
        }), 500

    # Kirim server_url dan data user ke generate_frames
    server_url = request.url_root.strip('/') + '/save_score'
    return Response(generate_frames(server_url, identity['nickname'], user_id,
                                    token),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


# --------API ENDPOINT FLUTTER---------
@app.route('/api/register', methods=['POST'])
def api_register():
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    data = request.json

    # Validasi input
    fullname = data.get('fullname', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    gender = data.get('gender', '').strip()

    if not fullname or not email or not password or not gender:
        return jsonify({"message": "All fields are required"}), 400

    # Cek apakah email sudah terdaftar
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Email already registered"}), 400

    # Hash password sebelum disimpan
    hashed_password = generate_password_hash(password)

    # Tambahkan pengguna baru ke database
    new_user = User(
        fullname=fullname,
        email=email,
        password=hashed_password,  # Simpan hash password
        gender=gender,
        role='user',  # Set role sebagai 'user' secara default
        profile_picture='default.png')

    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": "Failed to register user",
            "error": str(e)
        }), 500

    # Ambil user_id dari pengguna yang baru dibuat
    user_id = new_user.user_id  # Gunakan user_id sesuai model

    # Buat JWT token
    access_token = create_access_token(identity=str(user_id),
                                       expires_delta=timedelta(hours=24))

    # Kirim respons dengan user_id dan token
    return jsonify({
        "message": "User registered successfully",
        "user_id": user_id,
        "access_token": access_token  # Kirimkan access_token
    }), 201


@app.route('/api/check-token', methods=['GET'])
@jwt_required()
def check_token():
    return jsonify({"message": "Token valid"}), 200


# Endpoint untuk mengecek ketersediaan nickname
@app.route('/api/check_nickname', methods=['POST'])
@jwt_required()
def check_nickname():
    # Verifikasi API Key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        # Ambil user_id dari JWT token
        user_id = get_jwt_identity()
        print(f"👤 User ID dari JWT: {user_id}")

        data = request.json
        nickname = data.get('nickname', '').strip()

        if not nickname:
            return jsonify({"message": "Nama panggilan wajib diisi."}), 400

        normalized_nickname = nickname.lower()

        # Cek cache bad words
        bad_words = cache.get('bad_words')
        if not bad_words:
            bad_words = [
                bad_word.word.lower() for bad_word in BadWord.query.all()
            ]
            cache.set('bad_words', bad_words)

        for bad_word in bad_words:
            if bad_word in normalized_nickname:
                return jsonify({
                    "message":
                    "Nama panggilan Anda mengandung kata yang tidak pantas. Silakan gunakan nama lain."
                }), 400

        existing_user = User.query.filter_by(nickname=nickname).first()
        if existing_user:
            return jsonify({
                "status":
                "taken",
                "message":
                "Nama panggilan sudah digunakan. Silakan pilih nama lain."
            }), 200
        else:
            return jsonify({
                "status": "available",
                "message": "Nama panggilan tersedia."
            }), 200
    except Exception as e:
        print(f"Error in /api/check_nickname: {e}")
        return jsonify({
            "message":
            "Terjadi kesalahan pada server. Silakan coba lagi nanti."
        }), 500


# Endpoint untuk menyimpan nickname pengguna
@app.route('/api/save_nickname', methods=['POST'])
@jwt_required()
def save_nickname():
    # Verifikasi API key dari header
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        data = request.json
        nickname = data.get('nickname', '').strip()

        if not nickname:
            return jsonify({"message": "Nama panggilan wajib diisi."}), 400

        # Ambil user_id dari JWT token
        user_id = get_jwt_identity()
        normalized_nickname = nickname.lower()

        # Cari user berdasarkan user_id dari token
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({"message": "Pengguna tidak ditemukan."}), 404

        # Ambil daftar bad words dari cache atau DB
        bad_words = cache.get('bad_words')
        if not bad_words:
            bad_words = [bw.word.lower() for bw in BadWord.query.all()]
            cache.set('bad_words', bad_words)

        for bad_word in bad_words:
            if bad_word in normalized_nickname:
                return jsonify({
                    "message":
                    "Nama panggilan Anda mengandung kata yang tidak pantas. Silakan gunakan nama lain."
                }), 400

        existing_user = User.query.filter(User.nickname == nickname,
                                          User.user_id != user_id).first()
        if existing_user:
            return jsonify({
                "message":
                "Nama panggilan sudah digunakan. Silakan pilih nama lain."
            }), 400

        # Simpan nickname
        user.nickname = nickname
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Nama panggilan berhasil disimpan."
        }), 200

    except Exception as e:
        print(f"Error in save_nickname: {e}")
        return jsonify({
            "message":
            "Terjadi kesalahan pada server. Silakan coba lagi nanti."
        }), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    data = request.json

    # Validasi input
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    # Cari pengguna berdasarkan email
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Buat JWT token
        access_token = create_access_token(identity=str(user.user_id),
                                           expires_delta=timedelta(hours=1))

        # Optional: bisa juga kirim user info jika client butuh
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "user": {
                "user_id": user.user_id,
                "fullname": user.fullname,
                "email": user.email,
                "role": user.role,
                "nickname": user.nickname,
                "profile_picture": user.profile_picture
            }
        }), 200
    else:
        return jsonify({"message": "Invalid email or password"}), 401


@app.route('/api/google-login', methods=['POST'])
def api_google_login():
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    print("API Google Login Called")
    data = request.json
    print(f"Received Data: {data}")

    email = data.get('email')
    fullname = data.get('fullname')
    profile_picture_url = data.get('profile_picture')

    if not email or not isinstance(email, str) or "@" not in email:
        return jsonify({"message": "Invalid or missing email"}), 400

    try:

        def download_and_save_image(image_url, email):
            try:
                response = requests.get(image_url, stream=True)
                print(f"Response Status Code: {response.status_code}")

                if response.status_code == 200:
                    filename = f"{email.replace('@', '_').replace('.', '_')}.jpg"
                    folder = app.config['UPLOAD_FOLDER']
                    os.makedirs(folder, exist_ok=True)
                    file_path = os.path.join(folder, filename)
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(1024):
                            f.write(chunk)
                    print(f"Image successfully saved to: {file_path}")
                    return filename
                else:
                    print(f"Failed to download image: {response.status_code}")
                    return None
            except Exception as e:
                print(f"Error downloading image: {e}")
                return None

        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        user = User.query.filter_by(email=email).first()
        if user:
            updated = False
            if fullname and fullname != user.fullname:
                user.fullname = fullname
                updated = True
            if profile_picture_url:
                saved_path = download_and_save_image(profile_picture_url,
                                                     email)
                if saved_path:
                    user.profile_picture = saved_path
                    updated = True
            if updated:
                db.session.commit()
        else:
            saved_path = download_and_save_image(
                profile_picture_url, email) if profile_picture_url else None
            user = User(
                fullname=fullname or "Pengguna Google",
                email=email,
                password=generate_password_hash("google_auth"),
                gender="Laki-laki",
                role="user",
                profile_picture=saved_path,
            )
            db.session.add(user)
            db.session.commit()

        # ✅ Buat access token (JWT)
        access_token = create_access_token(identity=str(user.user_id),
                                           expires_delta=timedelta(hours=1))

        user_data = {
            "user_id": user.user_id,
            "fullname": user.fullname,
            "email": user.email,
            "nickname": user.nickname,
            "profile_picture": user.profile_picture,  # hanya filename
        }

        print(f"Respons yang dikirim ke Flutter: {user_data}")
        return jsonify({
            "message": "Login berhasil",
            "access_token": access_token,
            "user": user_data
        }), 200

    except Exception as e:
        print(f"Error in Google Login API: {e}")
        return jsonify({"message": "Internal server error"}), 500


@app.route('/api/upload_profile_picture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    try:
        # Validasi API key dari header
        api_key = request.headers.get('x-api-key')
        if not api_key or api_key != API_KEY:
            return jsonify({'message': 'Invalid or missing API key'}), 403

        # Ambil user_id dari JWT
        user_id = get_jwt_identity()

        # Validasi file
        if 'file' not in request.files:
            return jsonify({"message": "No file part"}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({"message": "No selected file"}), 400

        if file and allowed_file(file.filename):
            # Buat nama file unik
            original_filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{original_filename}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                     unique_filename)

            file.save(save_path)
            compressed_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                           f"compressed_{unique_filename}")

            try:
                compress_image_to_size(save_path,
                                       compressed_path,
                                       max_size_kb=2048)
            except Exception as e:
                os.remove(save_path)
                return jsonify({
                    "message": "Error compressing image",
                    "error": str(e)
                }), 500

            os.remove(save_path)

            # Simpan nama file ke DB
            user = User.query.filter_by(user_id=user_id).first()
            if user:
                user.profile_picture = f"compressed_{unique_filename}"
                db.session.commit()

                return jsonify({
                    "message": "Profile picture uploaded successfully",
                    "path": f"compressed_{unique_filename}"
                }), 200
            else:
                os.remove(compressed_path)
                return jsonify({"message": "User not found"}), 404

        return jsonify({"message": "Invalid file format"}), 400

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            "message": "Error uploading profile picture",
            "error": str(e)
        }), 500


@app.route('/api/logout', methods=['POST'])
def api_logout():
    # Hapus data sesi pengguna
    session.pop('user_id', None)
    session.pop('email', None)
    session.pop('fullname', None)
    session.pop('role', None)

    return jsonify({"message": "Logout successful"}), 200


@app.route('/api/get_user_by_id/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(user_id):
    print(f"🧪 Authorization Header: {request.headers.get('Authorization')}")
    # Ambil API key
    api_key = request.headers.get('x-api-key')
    print(f"🔐 API Key Diterima: {api_key}")

    if not api_key or api_key != API_KEY:
        print("🚫 API Key tidak valid")
        return jsonify({'message': 'Invalid or missing API key'}), 403

    # Ambil identity dari JWT
    requester_id = get_jwt_identity()
    print(f"👤 JWT Identity: {requester_id} (type: {type(requester_id)})")
    print(f"📨 URL user_id: {user_id} (type: {type(user_id)})")

    # Bandingkan apakah identity cocok dengan user_id
    if str(requester_id) != str(user_id):
        print("🚫 Akses ditolak: requester_id != user_id")
        return jsonify({'message': 'Unauthorized access'}), 403

    # Ambil data user dari database
    try:
        user = User.query.filter_by(user_id=user_id).first()
    except Exception as e:
        print(f"❌ Error while querying database: {e}")
        return jsonify({"message": "Internal Server Error"}), 500

    if user:
        profile_picture_url = user.get_profile_picture(
            request.host_url.strip('/'))
        return jsonify({
            "user_id": user.user_id,
            "fullname": user.fullname,
            "nickname": user.nickname,
            "email": user.email,
            "gender": user.gender,
            "profile_picture": profile_picture_url
        }), 200
    else:
        print("❌ User tidak ditemukan")
        return jsonify({"message": "User not found"}), 404


@app.route('/api/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    # Validasi API key dari header
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    data = request.json

    user_id = data.get('user_id')
    fullname = data.get('fullname')
    nickname = data.get('nickname')
    email = data.get('email')
    gender = data.get('gender')
    password = data.get('password')
    profile_picture = data.get('profile_picture')

    # Validasi data yang diperlukan
    if not user_id or not fullname or not email:
        return jsonify(
            {"message": "User ID, fullname, and email are required"}), 400

    # Validasi agar user hanya bisa update datanya sendiri
    requester_id = get_jwt_identity()
    if str(requester_id) != str(user_id):
        return jsonify({"message": "Unauthorized access"}), 403

    # Cari pengguna berdasarkan user_id
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Update data pengguna
    user.fullname = fullname
    user.nickname = nickname
    user.email = email
    user.gender = gender

    # Update password jika disediakan
    if password:
        user.password = generate_password_hash(password)

    # Update gambar profil jika disediakan
    if profile_picture:
        user.profile_picture = profile_picture

    # Simpan perubahan ke database
    db.session.commit()

    return jsonify({"message": "User updated successfully"}), 200


#Route API Lupa Sandi Di flutter
@app.route('/api/send_reset_code', methods=['POST'])
def send_reset_code():
    # Validasi API key dari header
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    # Cari pengguna berdasarkan email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Email not found"}), 404

    # Periksa apakah OTP yang ada masih valid
    otp = User.get_otp(email)
    if otp:
        return jsonify({
            "message":
            "An OTP has already been sent. Please wait for it to expire."
        }), 400

    # Generate OTP baru
    otp = random.randint(100000, 999999)  # 6 digit OTP
    User.set_otp(
        email, otp)  # Simpan OTP ke database dengan masa kedaluwarsa 10 menit

    # Kirim kode melalui email
    try:
        msg = Message('Reset Password Code', recipients=[email])
        msg.body = f"Kode reset password Anda adalah: {otp}. Berlaku selama 10 menit."
        mail.send(msg)
        print(f"OTP sent successfully to {email}: {otp}")  # Log sukses
    except Exception as e:
        print(f"Failed to send OTP to {email}: {e}")  # Log error
        return jsonify({"message": f"Failed to send email: {e}"}), 500

    return jsonify({"message": "Reset code sent successfully"}), 200


@app.route('/api/verify_reset_code', methods=['POST'])
def verify_reset_code():
    # Validasi API key dari header
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    data = request.json
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"message": "Email and code are required"}), 400

    # Cari pengguna berdasarkan email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Validasi jumlah percobaan
    if user.otp_attempts >= 5:
        print(f"Too many failed attempts for {email}")
        return jsonify({
            "message":
            "Too many failed attempts. Please request a new code."
        }), 400

    # Validasi OTP
    otp = User.get_otp(email)
    if otp is None:
        return jsonify({"message": "Code has expired or invalid"}), 400

    if otp != int(code):
        user.otp_attempts += 1  # Increment jumlah percobaan
        db.session.commit()
        print(f"Invalid OTP for {email}. Attempts: {user.otp_attempts}")
        return jsonify({"message": "Invalid code"}), 400

    # Tandai bahwa OTP telah diverifikasi, tetapi jangan hapus
    print(f"OTP verified successfully for {email}")

    return jsonify({"message": "Code verified successfully"}), 200


@app.route('/api/reset_password', methods=['POST'])
def api_reset_password():
    # Validasi API key dari header
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    data = request.json
    email = data.get('email')
    code = data.get('code')
    new_password = data.get('new_password')

    if not email or not code or not new_password:
        return jsonify(
            {"message": "Email, code, and new password are required"}), 400

    # Debug log
    print(
        f"Reset Password Request: email={email}, code={code}, new_password=******"
    )

    # Validasi password baru
    if len(new_password) < 8:
        return jsonify(
            {"message": "Password must be at least 8 characters long"}), 400
    if not any(char.isdigit() for char in new_password):
        return jsonify(
            {"message": "Password must include at least one number"}), 400
    if not any(char.isalpha() for char in new_password):
        return jsonify(
            {"message": "Password must include at least one letter"}), 400
    if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for char in new_password):
        return jsonify({
            "message":
            "Password must include at least one special character"
        }), 400

    # Cari pengguna berdasarkan email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Validasi kode OTP
    otp = User.get_otp(email)
    print(f"OTP from database: {otp}")  # Debug log untuk memverifikasi OTP

    if otp is None:
        return jsonify({"message": "Code has expired or invalid"}), 400

    if otp != int(code):
        user.otp_attempts += 1  # Increment jumlah percobaan
        db.session.commit()
        print(f"OTP mismatch: received={code}, expected={otp}")
        return jsonify({"message": "Invalid code"}), 400

    # Perbarui kata sandi
    user.password = generate_password_hash(new_password)
    User.delete_otp(email)  # Hapus OTP setelah digunakan
    db.session.commit()

    print(f"Password reset successful for {email}")
    return jsonify({"message": "Password reset successfully"}), 200


#Api User untuk hapus akun
@app.route('/api/delete_account/<int:user_id>', methods=['DELETE'])
@jwt_required()
def hapus_account(user_id):
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        print("Headers:", request.headers)
        print("Incoming user_id from URL:", user_id)
        # Ambil user_id dari JWT token
        current_user_id = get_jwt_identity()
        print("JWT user_id:", current_user_id)

        # Cegah user menghapus akun orang lain
        if str(user_id) != current_user_id:
            return jsonify({
                'message':
                'Anda tidak memiliki izin untuk menghapus akun ini.'
            }), 403

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User tidak ditemukan"}), 404

        # Hapus semua skor kuis terkait user
        UserQuizScore.query.filter_by(user_id=user_id).delete()

        # Hapus semua hasil kuis AR terkait user
        ARQuizResult.query.filter_by(user_id=user_id).delete()

        # Hapus user
        db.session.delete(user)
        db.session.commit()

        return jsonify({"message":
                        "Akun dan data terkait berhasil dihapus"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] delete_account: {e}")
        return jsonify({"error": "Terjadi kesalahan pada server"}), 500


#-------API get Data Pahlawan Mobile------------
#Route untuk mendapatkan semua tokoh dengan pagination dan pencarian
@app.route('/api/tokoh', methods=['GET'])
@jwt_required()
def get_all_tokoh():
    """
    API untuk mendapatkan daftar semua tokoh dengan pencarian, filter, dan pagination opsional.
    Query parameters:
    - q: String pencarian berdasarkan nama tokoh.
    - letter: Filter berdasarkan huruf awal nama tokoh.
    - page: Halaman yang diinginkan untuk pagination (default 1).
    - per_page: Jumlah tokoh per halaman (default 20).
    - group_by: Kategori grouping (provinsi, bidang_perjuangan, atau zaman_perjuangan).
    """
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        # Ambil parameter query
        search_query = request.args.get('q', '').strip().lower()
        letter = request.args.get('letter', '').strip().upper()
        zaman_perjuangan = request.args.get('zaman_perjuangan', '').strip()
        provinsi = request.args.get('provinsi', '').strip()
        bidang_perjuangan = request.args.get('bidang_perjuangan', '').strip()
        group_by = request.args.get('group_by', '').strip()

        # Pagination setup
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))

        # Base query
        query = Tokoh.query

        # Filter berdasarkan pencarian nama
        if search_query:
            query = query.filter(Tokoh.name.ilike(f'%{search_query}%'))

        # Filter berdasarkan huruf awal nama
        if letter:
            query = query.filter(Tokoh.name.ilike(f'{letter}%'))

        # Filter berdasarkan kategori: Zaman Perjuangan
        if zaman_perjuangan:
            query = query.filter(Tokoh.zaman_perjuangan == zaman_perjuangan)

        # Filter berdasarkan kategori: Provinsi
        if provinsi:
            query = query.filter(Tokoh.birth_place.ilike(f'%{provinsi}%'))

        # Filter berdasarkan kategori: Bidang Perjuangan
        if bidang_perjuangan:
            query = query.filter(
                Tokoh.bidang_perjuangan.ilike(f'%{bidang_perjuangan}%'))

        # Jika menggunakan grouping (subkategori)
        if group_by:
            if group_by == 'provinsi':
                # Query untuk grouping berdasarkan provinsi
                result = db.session.execute(
                    text("""
                    SELECT 
                        CASE 
                            WHEN birth_place LIKE '%Jawa Barat%' THEN 'Jawa Barat'
                            WHEN birth_place LIKE '%Jawa Tengah%' THEN 'Jawa Tengah'
                            WHEN birth_place LIKE '%Jawa Timur%' THEN 'Jawa Timur'
                            WHEN birth_place LIKE '%Sumatera Barat%' THEN 'Sumatera Barat'
                            WHEN birth_place LIKE '%Sumatera Utara%' THEN 'Sumatera Utara'
                            WHEN birth_place LIKE '%Sulawesi Selatan%' THEN 'Sulawesi Selatan'
                            WHEN birth_place LIKE '%Sulawesi Utara%' THEN 'Sulawesi Utara'
                            WHEN birth_place LIKE '%Aceh%' THEN 'Aceh'
                            WHEN birth_place LIKE '%Bali%' THEN 'Bali'
                            WHEN birth_place LIKE '%Maluku%' THEN 'Maluku'
                            WHEN birth_place LIKE '%Riau%' THEN 'Riau'
                            WHEN birth_place LIKE '%Papua%' THEN 'Papua'
                            WHEN birth_place LIKE '%Kalimantan%' THEN 'Kalimantan'
                            WHEN birth_place LIKE '%Lampung%' THEN 'Lampung'
                            WHEN birth_place LIKE '%Banten%' THEN 'Banten'
                            ELSE 'Lainnya'
                        END AS provinsi,
                        COUNT(*) AS jumlah
                    FROM tokoh
                    GROUP BY provinsi
                    ORDER BY jumlah DESC;
                """))
                grouped_data = [{
                    "provinsi": row[0],
                    "jumlah": row[1]
                } for row in result]
                return jsonify({
                    "data": grouped_data,
                    "status": "success"
                }), 200

            elif group_by == 'zaman_perjuangan':
                # Query untuk grouping berdasarkan zaman perjuangan
                result = db.session.query(
                    Tokoh.zaman_perjuangan,
                    db.func.count(Tokoh.id).label('jumlah')).group_by(
                        Tokoh.zaman_perjuangan).all()

                grouped_data = [{
                    "zaman_perjuangan": row[0],
                    "jumlah": row[1]
                } for row in result]
                return jsonify({
                    "data": grouped_data,
                    "status": "success"
                }), 200

            elif group_by == 'bidang_perjuangan':
                # Query untuk grouping berdasarkan bidang perjuangan
                result = db.session.execute(
                    text("""
                    SELECT 
                        CASE 
                            WHEN bidang_perjuangan LIKE '%Militer%' THEN 'Militer'
                            WHEN bidang_perjuangan LIKE '%Sosial%' THEN 'Sosial'
                            WHEN bidang_perjuangan LIKE '%Politik%' THEN 'Politik'
                            WHEN bidang_perjuangan LIKE '%Pendidikan%' THEN 'Pendidikan'
                            WHEN bidang_perjuangan LIKE '%Agama%' THEN 'Agama'
                            WHEN bidang_perjuangan LIKE '%Diplomasi%' THEN 'Diplomasi'
                            WHEN bidang_perjuangan LIKE '%Hukum%' THEN 'Hukum'
                            WHEN bidang_perjuangan LIKE '%Budaya%' THEN 'Budaya'
                            WHEN bidang_perjuangan LIKE '%Kesehatan%' THEN 'Kesehatan'
                            ELSE 'Lainnya'
                        END AS bidang_kategori,
                        COUNT(*) AS jumlah
                    FROM tokoh
                    GROUP BY bidang_kategori
                    ORDER BY jumlah DESC;
                """))
                grouped_data = [{
                    "bidang_kategori": row[0],
                    "jumlah": row[1]
                } for row in result]
                return jsonify({
                    "data": grouped_data,
                    "status": "success"
                }), 200

            else:
                return jsonify({"message":
                                "Parameter group_by tidak valid"}), 400

        # Jika tidak ada grouping, jalankan pagination seperti biasa
        pagination = query.paginate(page=page,
                                    per_page=per_page,
                                    error_out=False)
        tokoh_list = pagination.items
        total_items = pagination.total

        # Jika tidak ada tokoh yang ditemukan
        if not tokoh_list:
            error_message = "Tidak ada tokoh yang ditemukan"

            # Jika pencarian berdasarkan alfabet, tambahkan pesan lebih spesifik
            if letter:
                error_message = f"Tidak ada tokoh dengan huruf '{letter}'"

            # Jika pencarian berdasarkan kata kunci
            elif search_query:
                error_message = f"Tidak ada tokoh yang cocok dengan pencarian '{search_query}'"

            return jsonify({
                "message": error_message,
                "tokoh_list": [],
                "total_items": total_items,
                "page": page,
                "per_page": per_page
            }), 404

        # Format hasil query
        result = [tokoh.to_dict() for tokoh in tokoh_list]

        return jsonify({
            "message": "Daftar tokoh berhasil diambil",
            "tokoh_list": result,
            "total_items": total_items,
            "total_pages": pagination.pages,
            "current_page": pagination.page,
            "per_page": pagination.per_page
        }), 200

    except Exception as e:
        app.logger.error(f"Error fetching all tokoh: {str(e)}")
        return jsonify({"message": "Terjadi kesalahan", "error": str(e)}), 500


# Route untuk mendapatkan detail tokoh berdasarkan ID
@app.route('/api/tokoh/<int:id>', methods=['GET'])
@jwt_required()
def get_tokoh_detail(id):
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        tokoh = Tokoh.query.get(id)

        if not tokoh:
            return jsonify({"message": "Tokoh tidak ditemukan"}), 404

        return jsonify({
            "message": "Detail tokoh berhasil diambil",
            "tokoh": tokoh.to_dict()  # Hanya kirim URL gambar
        }), 200

    except SQLAlchemyError as e:
        return jsonify({
            "message": "Terjadi kesalahan pada database",
            "error": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "message": "Terjadi kesalahan yang tidak terduga",
            "error": str(e)
        }), 500


# Fungsi untuk chatbot tanpa role
def get_chatbot_response_no_role(user_message):
    try:
        # Tokenisasi pesan pengguna
        inputs = tokenizer(user_message,
                           return_tensors='pt',
                           padding=True,
                           truncation=True,
                           max_length=512)

        # Pastikan input ada di perangkat model
        inputs = {key: value.to(device) for key, value in inputs.items()}

        # Lakukan inferensi
        outputs = model.generate(
            **inputs,
            max_new_tokens=30,  # Batasi jumlah token baru
            num_return_sequences=1)

        # Decode hasilnya
        response_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response_text.strip()
    except Exception as e:
        print(f"Error in get_chatbot_response_no_role: {e}")
        return "Maaf, terjadi kesalahan saat memproses permintaan Anda."


# Endpoint chatbot untuk mobile (tanpa role)
@app.route('/api/chat/<int:id>', methods=['POST'])
@jwt_required()
def chat_without_role(id):
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        # Cari tokoh berdasarkan ID di database
        tokoh = Tokoh.query.get(id)
        if not tokoh:
            return jsonify(
                {"error": "Fitur Chatbot untuk tokoh ini belum tersedia"}), 404

        # Ambil pesan pengguna dari request
        data = request.json or {}
        user_message = data.get("message", "")

        if not user_message:
            return jsonify({"error": "Pesan tidak boleh kosong."}), 400

        # Hasilkan respons chatbot tanpa role
        chatbot_response = get_chatbot_response_no_role(user_message)

        # Kembalikan hanya respons chatbot
        return jsonify({"response": chatbot_response}), 200

    except Exception as e:
        return jsonify({
            "error": "Terjadi kesalahan yang tidak terduga",
            "details": str(e)
        }), 500


# Route untuk mendapatkan Timeline tokoh beserta media
@app.route('/api/get_timeline/<int:tokoh_id>', methods=['GET'])
@jwt_required()
def get_timeline(tokoh_id):
    # Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    try:
        # Ambil semua timeline yang terkait dengan tokoh_id
        timelines = Timeline.query.filter_by(tokoh_id=tokoh_id).all()

        if not timelines:
            return jsonify({"message":
                            "No timelines found for this hero"}), 404

        # Base URL untuk media (diambil dari request host)
        base_url = request.host_url.rstrip("/")  # Ambil base URL dari request

        # Menyusun data yang akan dikirim dalam response
        timeline_data = []
        for timeline in timelines:
            # Ambil semua media yang terkait dengan timeline ini
            media_items = TimelineMedia.query.filter_by(
                timeline_id=timeline.timeline_id).all()

            # Siapkan data media
            media_data = [{
                "media_id":
                media.media_id,
                "nomor_urut":
                media.nomor_urut,
                "media_type":
                media.media_type,
                "media_url":
                f"{base_url}{IMAGES_PATH}/{media.media_url}"
                if media.media_type == "image" else
                f"{base_url}{VIDEOS_PATH}/{media.media_url}",
                "description":
                media.description if media.description else "No description",
            } for media in media_items]
            # Jika media kosong, tambahkan default message
            if not media_data:
                media_data = [{"message": "No media available"}]

            # Masukkan data timeline + media ke dalam response
            timeline_data.append({
                "timeline_id": timeline.timeline_id,
                "nomor_urut": timeline.nomor_urut,
                "nama_timeline": timeline.nama_timeline,
                "deskripsi": timeline.deskripsi,
                "media": media_data  # Tambahkan media ke timeline
            })

        return jsonify({"timelines": timeline_data}), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            "message": "Error retrieving timeline",
            "error": str(e)
        }), 500


#API Untuk Quiz di Mobile
@app.route('/api/get_quizzes', methods=['GET'])
@jwt_required()
def get_quizzes():
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({
                "status": "error",
                "message": "User ID is required"
            }), 400

        # Log User ID
        app.logger.info(f"User ID: {user_id}")

        today_start = datetime.combine(date.today(), datetime.min.time())
        today_end = datetime.combine(date.today(), datetime.max.time())

        # Periksa apakah pengguna sudah bermain
        already_played = UserQuizScore.query.filter(
            UserQuizScore.user_id == user_id,
            UserQuizScore.date_taken.between(today_start, today_end)).first()

        app.logger.info(f"Already Played: {bool(already_played)}")

        if already_played:
            return jsonify({
                "status":
                "error",
                "message":
                "Anda sudah main quiz hari ini, coba lagi besok!"
            }), 403

        # Ambil soal
        easy_questions = Quiz.query.filter_by(difficulty='easy').order_by(
            func.random()).limit(5).all()
        medium_questions = Quiz.query.filter_by(difficulty='medium').order_by(
            func.random()).limit(3).all()
        hard_questions = Quiz.query.filter_by(difficulty='hard').order_by(
            func.random()).limit(2).all()

        app.logger.info(f"Easy Questions: {len(easy_questions)}")
        app.logger.info(f"Medium Questions: {len(medium_questions)}")
        app.logger.info(f"Hard Questions: {len(hard_questions)}")

        selected_questions = easy_questions + medium_questions + hard_questions
        random.shuffle(selected_questions)

        # Pastikan soal benar
        if not selected_questions:
            return jsonify({
                "status": "error",
                "message": "No quizzes available"
            }), 404

        quizzes = []
        for quiz in selected_questions:
            options = [
                quiz.option_1, quiz.option_2, quiz.option_3,
                quiz.correct_answer
            ]
            options = [opt for opt in options if opt is not None]
            random.shuffle(options)

            quizzes.append({
                "quiz_id": quiz.quiz_id,
                "question": quiz.question,
                "correct_answer": quiz.correct_answer,
                "options": options,
                "difficulty": quiz.difficulty,
                "points": quiz.points,
            })

        return jsonify({"status": "success", "quizzes": quizzes}), 200
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/save_quiz_results', methods=['POST'])
@jwt_required()
def save_quiz_results():
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    try:
        # Ambil data JSON dari request
        data = request.get_json()

        # Validasi input
        user_id = data.get('user_id')
        results = data.get('results')

        if not user_id or not isinstance(results, list):
            return jsonify({
                "status": "error",
                "message": "Invalid data format"
            }), 400

        # Periksa apakah user_id valid
        user = User.query.get(user_id)
        if not user:
            return jsonify({
                "status": "error",
                "message": "Invalid user_id"
            }), 400

        total_score = 0  # Variable untuk menghitung skor total pengguna

        # Validasi dan simpan hasil kuis
        for result in results:
            quiz_id = result.get('quiz_id')
            score = result.get('score')

            if not quiz_id or not isinstance(score, int) or score < 0:
                return jsonify({
                    "status": "error",
                    "message": "Invalid result format"
                }), 400

            # Periksa apakah quiz_id valid
            quiz = Quiz.query.get(quiz_id)
            if not quiz:
                return jsonify({
                    "status": "error",
                    "message": f"Invalid quiz_id: {quiz_id}"
                }), 400

            # Tambahkan skor pengguna
            total_score += score

            # Simpan hasil baru ke database
            new_score = UserQuizScore(user_id=user_id,
                                      quiz_id=quiz_id,
                                      score=score)
            db.session.add(new_score)

        # Commit ke database
        db.session.commit()

        # Return dengan total_score
        return jsonify({
            "status": "success",
            "message": "Quiz results saved successfully!",
            "total_score": total_score  # Kirim skor total ke klien
        }), 200

    except Exception as e:
        # Rollback jika terjadi error
        db.session.rollback()
        app.logger.error(f"Error in save_quiz_results: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal Server Error"
        }), 500


@app.route('/api/player-performance/<string:week_type>/<int:user_id>',
           methods=['GET'])
@jwt_required()
def get_player_performance(week_type, user_id):
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    try:
        today = datetime.today()
        if week_type == "this-week":
            week_start = today - timedelta(days=today.weekday())
            week_end = week_start + timedelta(days=6)
        elif week_type == "last-week":
            week_start = today - timedelta(days=today.weekday() + 7)
            week_end = week_start + timedelta(days=6)
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid week type"
            }), 400

        player_score = db.session.query(func.sum(UserQuizScore.score)).filter(
            UserQuizScore.user_id == user_id,
            func.date(UserQuizScore.date_taken).between(
                week_start.date(), week_end.date())).scalar() or 0

        leaderboard = db.session.query(
            UserQuizScore.user_id,
            func.sum(UserQuizScore.score).label('total_score')).filter(
                func.date(UserQuizScore.date_taken).between(
                    week_start.date(),
                    week_end.date())).group_by(UserQuizScore.user_id).order_by(
                        func.sum(UserQuizScore.score).desc()).all()

        total_players = len(leaderboard)
        better_than_count = sum(1 for user_id_, score in leaderboard
                                if score < player_score)

        # Periksa jika leaderboard kosong
        if total_players == 0:
            player_ranking = 1
            better_than_percentage = 0.0
        else:
            player_ranking = next(
                (rank + 1 for rank, (user_id_, score) in enumerate(leaderboard)
                 if user_id_ == user_id), total_players + 1)
            better_than_percentage = round(
                (better_than_count / total_players * 100), 2)

        return jsonify({
            "status": "success",
            "user_id": user_id,
            "total_score": int(player_score),  # Pastikan integer
            "ranking": int(player_ranking),  # Pastikan integer
            "better_than_percentage":
            float(better_than_percentage),  # Pastikan float
            "week_start": week_start.strftime('%Y-%m-%d'),
            "week_end": week_end.strftime('%Y-%m-%d'),
        }), 200

    except Exception as e:
        print(f"Error fetching player performance: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal Server Error"
        }), 500


#Api Enpoint untuk Hari Penting
@app.route('/api/hari-penting', methods=['GET'])
@jwt_required()
def check_day():
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    # ✅ Ambil tanggal hari ini dalam format dd-mm
    today = datetime.now().strftime('%d-%m')

    # ✅ Ambil semua entri hari penting pada tanggal tersebut
    hari_list = HariPenting.query.filter_by(tanggal=today).all()

    if hari_list:
        return jsonify({
            "status": "success",
            "message": f"Ditemukan {len(hari_list)} hari penting hari ini.",
            "data": [hari.to_dict() for hari in hari_list]
        }), 200
    else:
        return jsonify({
            "status": "success",
            "message": "Hari ini bukan hari penting.",
            "data": []
        }), 200


#API Untuk leaderboard di Mobile
@app.route('/api/leaderboard', methods=['GET'])
@jwt_required()
def get_leaderboard():
    try:
        # ✅ Verifikasi API key
        api_key = request.headers.get('x-api-key')
        if not api_key or api_key != API_KEY:
            return jsonify({'error': 'Invalid or missing API key'}), 403

        # Ambil parameter 'week' dari query string
        week_type = request.args.get('week',
                                     'this-week')  # Default ke 'this-week'

        # Tentukan rentang tanggal untuk 'this-week' atau 'last-week'
        today = datetime.today()
        if week_type == "this-week":
            week_start = today - timedelta(
                days=today.weekday())  # Senin minggu ini
            week_end = week_start + timedelta(days=6)  # Minggu minggu ini
        elif week_type == "last-week":
            last_week_start = today - timedelta(days=today.weekday() + 7)
            week_start = last_week_start
            week_end = week_start + timedelta(days=6)
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid week parameter"
            }), 400

        # Query total skor user hanya dalam rentang tanggal tertentu
        leaderboard = db.session.query(
            UserQuizScore.user_id,
            func.sum(UserQuizScore.score).label('total_score')).filter(
                func.date(UserQuizScore.date_taken).between(
                    week_start.date(),
                    week_end.date())).group_by(UserQuizScore.user_id).order_by(
                        func.sum(UserQuizScore.score).desc()).all()

        # Ambil data pengguna
        leaderboard_data = []
        for index, (user_id, total_score) in enumerate(leaderboard):
            user = User.query.get(user_id)
            leaderboard_data.append({
                "user_id":
                user_id,
                "total_score":
                total_score,
                "ranking":
                index + 1,
                "nickname":
                user.nickname if user else "Unknown",
                "profile_picture":
                user.profile_picture
                if user and user.profile_picture else "default.png"
            })

        return jsonify({"leaderboard": leaderboard_data}), 200

    except Exception as e:
        app.logger.error(f"Error fetching leaderboard: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal Server Error"
        }), 500


# ------ Api untuk Sentimen -----
@app.route('/api/analyze_sentiment', methods=['POST'])
@jwt_required()
def analyze_sentiment():
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    try:
        # Mendapatkan teks dari body request
        data = request.get_json()
        text = data.get("text", "")

        if not text:
            return jsonify({"message": "Text is required"}), 400

        # Prediksi sentimen menggunakan analyzer_indobert yang telah diinisialisasi
        predicted_class, probabilities = analyzer_indobert.predict_sentiment(
            text)

        # Simpan review ke database
        new_review = Review(text=text)
        db.session.add(new_review)  # Menambahkan review baru ke session
        db.session.commit()  # Menyimpan ke database

        # Respons sederhana ke user
        return jsonify({
            "message":
            "Terima kasih sudah memberikan komentar Anda untuk aplikasi kami"
        }), 200

    except Exception as e:
        return jsonify({"message": "Terjadi kesalahan pada server"}), 500


# =====LAGU=====
# Base URL static (untuk frontend Flutter bisa akses)
STATIC_BASE_URL = '/static/LAGU'


@app.route('/api/songs', methods=['GET'])
def get_all_songs():
    songs = Song.query.options(
        joinedload(Song.region),
        joinedload(Song.artists).joinedload(SongArtist.artist)).all()

    result = []

    for song in songs:
        audio_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/audio/{song.audio_url}" if song.audio_url else None
        cover_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/cover/{song.cover_url}" if song.cover_url else None

        result.append({
            'id':
            song.id,
            'title':
            song.title,
            'type':
            song.type,
            'region':
            song.region.name if song.region else None,
            'release_year':
            song.release_year,
            'lyrics':
            song.lyrics,
            'audio_url':
            audio_path,
            'cover_url':
            cover_path,
            'duration':
            str(song.duration) if song.duration else None,
            'language':
            song.language,
            'created_at':
            song.created_at.isoformat(),
            'artists': [{
                'id': sa.artist.id,
                'name': sa.artist.name,
                'role': sa.role
            } for sa in song.artists]
        })

    return jsonify(result)


@app.route('/api/songs/<string:type>', methods=['GET'])
@jwt_required()
def get_songs_by_type(type):
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    # ✅ Validasi tipe lagu
    if type not in ['nasional', 'daerah']:
        return jsonify({'error': 'Tipe lagu tidak valid'}), 400

    # ✅ Ambil dan validasi query param
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
    except ValueError:
        return jsonify(
            {'error': 'Parameter page dan limit harus berupa angka'}), 400

    if page < 1 or limit < 1:
        return jsonify({'error': 'Page dan limit harus lebih dari 0'}), 400

    query = request.args.get('q', '').strip()
    offset = (page - 1) * limit

    # ✅ Query data lagu
    songs_query = Song.query.options(
        joinedload(Song.region),
        joinedload(Song.artists).joinedload(
            SongArtist.artist)).filter_by(type=type)

    if query:
        songs_query = songs_query.filter(Song.title.ilike(f"%{query}%"))

    total = songs_query.count()
    songs = songs_query.order_by(Song.id).offset(offset).limit(limit).all()

    # ✅ Format hasil
    result = []
    for song in songs:
        audio_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/audio/{song.audio_url}" if song.audio_url else None
        cover_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/cover/{song.cover_url}" if song.cover_url else None

        result.append({
            'id':
            song.id,
            'title':
            song.title,
            'region':
            song.region.name if song.region else None,
            'release_year':
            song.release_year,
            'lyrics':
            song.lyrics,
            'audio_url':
            audio_path,
            'cover_url':
            cover_path,
            'duration':
            str(song.duration) if song.duration else None,
            'language':
            song.language,
            'created_at':
            song.created_at.isoformat(),
            'artists': [{
                'id': sa.artist.id,
                'name': sa.artist.name,
                'role': sa.role
            } for sa in song.artists]
        })

    return jsonify({
        'total': total,
        'page': page,
        'limit': limit,
        'songs': result
    }), 200


@app.route('/api/songs/<int:id>', methods=['GET'])
@jwt_required()
def get_song_by_id(id):
    # ✅ Verifikasi API key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 403

    song = Song.query.options(
        joinedload(Song.region),
        joinedload(Song.artists).joinedload(SongArtist.artist)).get(id)

    if not song:
        return jsonify({'error': 'Lagu tidak ditemukan'}), 404

    audio_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/audio/{song.audio_url}" if song.audio_url else None
    cover_path = f"{STATIC_BASE_URL}/{song.type.capitalize()}/cover/{song.cover_url}" if song.cover_url else None

    song_data = {
        'id':
        song.id,
        'title':
        song.title,
        'type':
        song.type,
        'region':
        song.region.name if song.region else None,
        'release_year':
        song.release_year,
        'lyrics':
        song.lyrics,
        'audio_url':
        audio_path,
        'cover_url':
        cover_path,
        'duration':
        str(song.duration) if song.duration else None,
        'language':
        song.language,
        'created_at':
        song.created_at.isoformat(),
        'artists': [{
            'id': sa.artist.id,
            'name': sa.artist.name,
            'role': sa.role
        } for sa in song.artists]
    }

    return jsonify(song_data)


#ARQuest
def build_arquiz_image_url(filename):
    return url_for('static',
                   filename=f'arquest/images/{filename}',
                   _external=True)


def serialize_question(question):
    return {
        'id': question.question_id,
        'level': question.level,
        'question_text': question.question_text,
        'question_image_url': build_arquiz_image_url(question.question_image),
        'option_a': question.option_a_text,
        'option_b': question.option_b_text,
        'correct_answer': question.correct_answer  # ✅ Tambahkan ini
    }


@app.route('/api/arquiz/start', methods=['GET'])
@jwt_required()
def start_ar_quiz():
    # ✅ Cek API Key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    # ✅ Ambil soal berdasarkan level & acak
    easy = ARQuizQuestion.query.filter_by(level='easy').order_by(
        func.rand()).limit(5).all()
    medium = ARQuizQuestion.query.filter_by(level='medium').order_by(
        func.rand()).limit(3).all()
    hard = ARQuizQuestion.query.filter_by(level='hard').order_by(
        func.rand()).limit(2).all()

    all_questions = easy + medium + hard
    random.shuffle(all_questions)

    return jsonify([serialize_question(q) for q in all_questions])


@app.route('/api/arquiz/result', methods=['POST'])
@jwt_required()
def save_ar_quiz_result():
    # ✅ Cek API Key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    user_id = get_jwt_identity()
    data = request.get_json()

    level = data.get('level')
    score = data.get('score')
    correct_answers = data.get('correct_answers')
    total_questions = data.get('total_questions')

    if not all([level, score is not None, correct_answers, total_questions]):
        return jsonify({'error': 'Missing fields'}), 400

    result = ARQuizResult(
        user_id=user_id,
        level=level,
        score=score,
        correct_answers=correct_answers,
        total_questions=total_questions,
    )

    db.session.add(result)
    db.session.commit()

    return jsonify({'message': 'Result saved successfully'}), 200


@app.route('/api/arquiz/leaderboard', methods=['GET'])
@jwt_required()
def ar_quiz_leaderboard():
    # ✅ Cek API Key
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return jsonify({'message': 'Invalid or missing API key'}), 403

    # 🎯 Season parameter: week_current or week_last
    season = request.args.get('season', 'week_current')  # default minggu ini

    now = datetime.utcnow()
    start_of_week = now - timedelta(days=now.weekday())  # Senin minggu ini
    end_of_week = start_of_week + timedelta(days=7)

    if season == 'week_last':
        start_date = start_of_week - timedelta(days=7)
        end_date = start_of_week
    else:  # week_current
        start_date = start_of_week
        end_date = end_of_week

    # Subquery: total skor user untuk periode yang dipilih
    total_score_subquery = (db.session.query(
        ARQuizResult.user_id,
        func.sum(ARQuizResult.score).label('total_score')).filter(
            ARQuizResult.timestamp >= start_date, ARQuizResult.timestamp
            < end_date).group_by(ARQuizResult.user_id).subquery())

    # Subquery: ambil entry terbaru per user (dari semua waktu untuk info level terakhir)
    latest_result_subquery = (db.session.query(
        ARQuizResult.user_id, ARQuizResult.level, ARQuizResult.timestamp).join(
            db.session.query(
                ARQuizResult.user_id.label('uid'),
                func.max(ARQuizResult.timestamp).label(
                    'latest_timestamp')).group_by(
                        ARQuizResult.user_id).subquery(),
            db.and_(
                ARQuizResult.user_id == db.literal_column('uid'),
                ARQuizResult.timestamp == db.literal_column(
                    'latest_timestamp'))).subquery())

    leaderboard = (db.session.query(
        User.user_id, User.nickname, User.profile_picture,
        total_score_subquery.c.total_score, latest_result_subquery.c.level,
        latest_result_subquery.c.timestamp).join(
            total_score_subquery,
            total_score_subquery.c.user_id == User.user_id).join(
                latest_result_subquery,
                latest_result_subquery.c.user_id == User.user_id).order_by(
                    desc(total_score_subquery.c.total_score)).limit(10).all())

    result = []
    for row in leaderboard:
        result.append({
            'user_id':
            row.user_id,
            'nickname':
            row.nickname,
            'profile_picture':
            row.profile_picture,
            'score':
            row.total_score,
            'level':
            row.level,
            'timestamp':
            row.timestamp.isoformat() if row.timestamp else None
        })

    return jsonify({
        'season': season,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'leaderboard': result
    })


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5012)
